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
