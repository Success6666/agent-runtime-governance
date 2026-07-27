from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum

import pytest

from agent_runtime_governance.context import RiskTier
from agent_runtime_governance.contracts import (
    bind_arguments,
    canonical_json_bytes,
    materialize_call,
    normalize_json,
    validate_instance,
)
from agent_runtime_governance.errors import ContractValidationError, RegistryError
from agent_runtime_governance.reconciliation import SQLiteReconciliationLedger
from agent_runtime_governance.registry import (
    IdempotencyConflictError,
    IdempotencyInProgressError,
    IdempotencyOutcomeUnknownError,
    InMemoryIdempotencyStore,
    SQLiteIdempotencyStore,
    ToolSpec,
)


class IntegerCode(IntEnum):
    OK = 1


class TextCode(str, Enum):
    OK = "ok"


def test_primitive_backed_enums_normalize_to_scalar_values() -> None:
    normalized = normalize_json(
        {"integer": IntegerCode.OK, "text": TextCode.OK}
    )
    assert normalized == {"integer": 1, "text": "ok"}
    assert type(normalized["integer"]) is int
    assert type(normalized["text"]) is str


def test_json_schema_is_checked_at_registration() -> None:
    with pytest.raises(RegistryError, match="invalid parameters JSON Schema"):
        ToolSpec(
            name="broken",
            function=lambda: None,
            risk=RiskTier.LOW,
            requires_approval=False,
            description="",
            parameters_schema={"type": "definitely-not-a-json-schema-type"},
        )


def test_bound_parameters_are_validated_by_name() -> None:
    def create(name: str, count: int = 1) -> None:
        return None

    bound = bind_arguments(create, ("job",), {})
    assert bound == {"name": "job", "count": 1}
    assert validate_instance(
        bound,
        {
            "type": "object",
            "required": ["name", "count"],
            "properties": {
                "name": {"type": "string", "minLength": 2},
                "count": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        label="parameters",
    ) == {"name": "job", "count": 1}


def test_materialized_call_preserves_complex_python_signature() -> None:
    def target(
        first: str,
        /,
        second: str = "default",
        *extra: str,
        enabled: bool = True,
        **metadata: str,
    ) -> tuple[object, ...]:
        return first, second, extra, enabled, metadata

    parameters = validate_instance(
        bind_arguments(
            target,
            ("one", "two", "three", "four"),
            {"enabled": False, "tenant": "acme"},
        ),
        None,
        label="parameters",
    )
    args, kwargs = materialize_call(target, parameters)

    assert target(*args, **kwargs) == (
        "one",
        "two",
        ("three", "four"),
        False,
        {"tenant": "acme"},
    )


def test_contract_rejects_invalid_value_with_path() -> None:
    with pytest.raises(ContractValidationError, match=r"count.*minimum"):
        validate_instance(
            {"count": 0},
            {
                "type": "object",
                "properties": {"count": {"type": "integer", "minimum": 1}},
            },
            label="parameters",
        )


def test_canonicalization_never_calls_untrusted_repr() -> None:
    class Secret:
        def __repr__(self) -> str:
            raise AssertionError("repr must not be called")

    with pytest.raises(ContractValidationError, match="unsupported value type"):
        canonical_json_bytes({"secret": Secret()}, label="parameters")


def test_in_memory_idempotency_evicts_terminal_entries_by_lru() -> None:
    store = InMemoryIdempotencyStore(
        max_completed_entries=2,
        completed_ttl_seconds=60,
    )
    first = store.acquire("tenant/tool", "first", "a" * 64)
    second = store.acquire("tenant/tool", "second", "b" * 64)
    store.complete(first, 1)
    store.complete(second, 2)

    assert store.acquire("tenant/tool", "first", "a" * 64).future.result() == 1
    third = store.acquire("tenant/tool", "third", "c" * 64)
    store.complete(third, 3)

    assert store.acquire("tenant/tool", "first", "a" * 64).owner is False
    assert store.acquire("tenant/tool", "second", "b" * 64).owner is True


def test_in_memory_idempotency_evicts_terminal_entries_after_idle_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"value": 100.0}
    monkeypatch.setattr(
        "agent_runtime_governance.registry.monotonic",
        lambda: clock["value"],
    )
    store = InMemoryIdempotencyStore(completed_ttl_seconds=5)
    claim = store.acquire("tenant/tool", "request", "a" * 64)
    store.mark_unknown(claim, RuntimeError("uncertain"))
    retained = store.acquire("tenant/tool", "request", "a" * 64)
    with pytest.raises(IdempotencyOutcomeUnknownError):
        retained.future.result()

    clock["value"] += 6
    assert store.acquire("tenant/tool", "request", "a" * 64).owner is True


def test_sqlite_idempotency_failure_without_reconciliation_schema_releases_claim(
    tmp_path,
) -> None:
    """A standalone idempotency store must not require reconciliation tables."""

    store = SQLiteIdempotencyStore(tmp_path / "idempotency.db")
    claim = store.acquire("tenant/tool", "request", "a" * 64)

    store.fail(claim, ValueError("tool validation failed"))

    with pytest.raises(ValueError, match="tool validation failed"):
        claim.future.result()
    replacement = store.acquire("tenant/tool", "request", "a" * 64)
    assert replacement.owner is True
    assert replacement.generation == 1


@pytest.mark.parametrize("durable", [False, True])
def test_unknown_outcome_exposes_stable_execution_record_id(
    tmp_path, durable: bool
) -> None:
    path = tmp_path / "idempotency.db"
    store = SQLiteIdempotencyStore(path) if durable else InMemoryIdempotencyStore()
    claim = store.acquire("tenant/tool", "caller-visible-key", "a" * 64)
    assert claim.execution_record_id is not None
    store.mark_unknown(claim, RuntimeError("uncertain"))

    with pytest.raises(IdempotencyOutcomeUnknownError) as first:
        claim.future.result()
    assert first.value.execution_record_id == claim.execution_record_id
    assert "caller-visible-key" not in str(first.value)

    restarted = SQLiteIdempotencyStore(path) if durable else store
    repeated = restarted.acquire("tenant/tool", "caller-visible-key", "a" * 64)
    with pytest.raises(IdempotencyOutcomeUnknownError) as second:
        repeated.future.result()
    assert second.value.execution_record_id == claim.execution_record_id


def test_sqlite_idempotency_survives_restart(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    fingerprint = "a" * 64
    first = SQLiteIdempotencyStore(path)
    claim = first.acquire("tenant/tool", "request-1", fingerprint)
    first.complete(claim, {"ok": True})

    restarted = SQLiteIdempotencyStore(path)
    cached = restarted.acquire("tenant/tool", "request-1", fingerprint)
    assert cached.owner is False
    assert cached.future.result() == {"ok": True}


def test_sqlite_idempotency_ignores_unrelated_foreign_key_violations(tmp_path) -> None:
    """The idempotency startup check must not own another schema's integrity."""

    path = tmp_path / "idempotency.db"
    SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("CREATE TABLE unrelated_parent(id INTEGER PRIMARY KEY)")
            connection.execute(
                """
                CREATE TABLE unrelated_child(
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER REFERENCES unrelated_parent(id)
                )
                """
            )
            connection.execute("INSERT INTO unrelated_child(id, parent_id) VALUES (1, 99)")

    restarted = SQLiteIdempotencyStore(path)
    assert restarted.acquire("tenant/tool", "request-1", "a" * 64).owner is True


def test_sqlite_idempotency_rejects_orphaned_migration_staging_table(tmp_path) -> None:
    """A residual migration table must not be mistaken for a fresh database."""

    path = tmp_path / "orphaned-idempotency-staging.db"
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "CREATE TABLE idempotency_records_v07 (sentinel TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO idempotency_records_v07(sentinel) VALUES ('legacy')"
            )

    with pytest.raises(RuntimeError, match="reserved migration table name"):
        SQLiteIdempotencyStore(path)

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'idempotency_records'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT sentinel FROM idempotency_records_v07"
        ).fetchone() == ("legacy",)


def test_standalone_idempotency_migration_rejects_colocated_reconciliation(
    tmp_path,
) -> None:
    """Shared durable state has one atomic migration owner: the ledger."""

    path = tmp_path / "shared-legacy-idempotency.db"
    SQLiteReconciliationLedger(path)
    SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute("DROP TABLE idempotency_schema")

    with pytest.raises(RuntimeError, match="use SQLiteReconciliationLedger.migrate_legacy"):
        SQLiteIdempotencyStore.migrate_legacy(path)

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'idempotency_schema'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT version FROM reconciliation_schema WHERE singleton = 1"
        ).fetchone() == (5,)


def test_sqlite_idempotency_rejects_persistent_trigger_that_forges_retry(
    tmp_path,
) -> None:
    path = tmp_path / "idempotency.db"
    store = SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TRIGGER idempotency_forge_retry
                AFTER UPDATE OF state ON idempotency_records
                WHEN NEW.state = 'completed'
                BEGIN
                    UPDATE idempotency_records
                    SET state = 'not_applied', result_json = NULL,
                        error = 'forged retry', owner_token = NULL,
                        lease_expires_at = NULL
                    WHERE execution_record_id = NEW.execution_record_id;
                END
                """
            )

    claim = store.acquire("tenant/tool", "request-1", "a" * 64)
    store.complete(claim, {"ok": True})
    with closing(sqlite3.connect(path)) as connection:
        state = connection.execute(
            "SELECT state FROM idempotency_records WHERE key = 'request-1'"
        ).fetchone()[0]
    assert state == "not_applied"

    with pytest.raises(RuntimeError, match="unexpected persistent trigger"):
        SQLiteIdempotencyStore(path)


def test_sqlite_idempotency_rejects_schema_version_trigger(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TRIGGER idempotency_version_reset
                AFTER UPDATE OF version ON idempotency_schema
                BEGIN
                    UPDATE idempotency_schema SET version = 0 WHERE singleton = 1;
                END
                """
            )

    with pytest.raises(RuntimeError, match="unexpected persistent trigger"):
        SQLiteIdempotencyStore(path)


def test_sqlite_idempotency_rejects_modified_authority_table(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute("DROP TABLE idempotency_records")
            connection.execute(
                """
                CREATE TABLE idempotency_records (
                    execution_record_id TEXT PRIMARY KEY NOT NULL,
                    namespace TEXT NOT NULL,
                    key TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    owner_token TEXT,
                    lease_expires_at TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )

    with pytest.raises(RuntimeError, match="does not match the supported contract"):
        SQLiteIdempotencyStore(path)


def test_sqlite_idempotency_rejects_unexpected_explicit_index(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "CREATE INDEX idempotency_unexpected_index "
                "ON idempotency_records(namespace, state)"
            )

    with pytest.raises(RuntimeError, match="explicit indexes do not match"):
        SQLiteIdempotencyStore(path)


def test_sqlite_idempotency_rejects_forged_schema_version(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute("UPDATE idempotency_schema SET version = 1")

    with pytest.raises(RuntimeError, match="exactly the current version"):
        SQLiteIdempotencyStore(path)


def test_sqlite_idempotency_rejects_conflicting_payload(tmp_path) -> None:
    store = SQLiteIdempotencyStore(tmp_path / "idempotency.db")
    store.acquire("tenant/tool", "request-1", "a" * 64)
    with pytest.raises(IdempotencyConflictError):
        store.acquire("tenant/tool", "request-1", "b" * 64)


def test_sqlite_idempotency_rejects_concurrent_owner(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    first = SQLiteIdempotencyStore(path, lease_seconds=60)
    second = SQLiteIdempotencyStore(path, lease_seconds=60)
    first.acquire("tenant/tool", "request-1", "a" * 64)
    duplicate = second.acquire("tenant/tool", "request-1", "a" * 64)
    with pytest.raises(IdempotencyInProgressError):
        duplicate.future.result()


def test_expired_lease_becomes_unknown_and_is_not_reexecuted(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    store = SQLiteIdempotencyStore(path, lease_seconds=60)
    store.acquire("tenant/tool", "request-1", "a" * 64)
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "UPDATE idempotency_records SET lease_expires_at = ?",
                (expired,),
            )

    recovered = SQLiteIdempotencyStore(path).acquire(
        "tenant/tool", "request-1", "a" * 64
    )
    with pytest.raises(IdempotencyOutcomeUnknownError, match="lease expired"):
        recovered.future.result()


def test_only_completed_records_are_pruned(tmp_path) -> None:
    store = SQLiteIdempotencyStore(tmp_path / "idempotency.db")
    completed = store.acquire("tenant/tool", "done", "a" * 64)
    store.complete(completed, 1)
    store.acquire("tenant/tool", "pending", "b" * 64)

    deleted = store.prune_completed(
        older_than=datetime.now(timezone.utc) + timedelta(seconds=1)
    )
    assert deleted == 1
    pending = store.acquire("tenant/tool", "pending", "b" * 64)
    with pytest.raises(IdempotencyInProgressError):
        pending.future.result()
