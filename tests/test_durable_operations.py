from pathlib import Path

import pytest

from agent_runtime_governance import (
    InMemoryIdempotencyStore,
    SQLiteIdempotencyStore,
    SQLiteReconciliationLedger,
)
from agent_runtime_governance._internal.runtime.durable_operations import (
    DurableOperationCapability,
    _ReconciliationDurability,
)

_FINGERPRINT = "a" * 64


class _RecordingLedger(SQLiteReconciliationLedger):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.prepared: tuple[object, object] | None = None
        self.unknown: tuple[object, object, BaseException] | None = None

    def prepare_action(self, claim: object, action: object) -> None:
        self.prepared = (claim, action)

    def record_unknown(
        self, claim: object, action: object, error: BaseException
    ) -> object:
        self.unknown = (claim, action, error)
        return object()


def test_capability_rejects_flags_without_a_colocated_sqlite_pair() -> None:
    store = InMemoryIdempotencyStore()
    capability = DurableOperationCapability(store, None)
    claim = store.acquire("tenant/charge", "request-1", _FINGERPRINT)

    assert (
        capability.reconciliation_durability
        is _ReconciliationDurability.DURABLE_LEDGER_REQUIRED
    )
    assert capability.prepare_non_atomic_sqlite_action(claim, object()) is False
    assert (
        capability.record_orphaned_prepared_claim_unknown(
            claim,
            object(),
            TimeoutError("request stopped waiting"),
        )
        is False
    )
    with pytest.raises(RuntimeError, match="co-located SQLite pair"):
        capability.acquire(
            "tenant/charge",
            "request-2",
            _FINGERPRINT,
            prepared_action=object(),
        )
    with pytest.raises(RuntimeError, match="SQLite reconciliation"):
        capability.record_unknown(claim, object(), RuntimeError("unknown"))
    with pytest.raises(RuntimeError, match="audit outbox"):
        capability.pending_audit_events()


def test_capability_routes_sqlite_compatibility_and_atomic_unknown_paths(
    tmp_path: Path,
) -> None:
    compatibility_path = tmp_path / "compatibility.db"
    # Initializes the idempotency schema required by _RecordingLedger preflight.
    SQLiteIdempotencyStore(compatibility_path)
    compatibility_ledger = _RecordingLedger(compatibility_path)
    memory_store = InMemoryIdempotencyStore()
    compatibility = DurableOperationCapability(memory_store, compatibility_ledger)
    compatibility_claim = memory_store.acquire(
        "tenant/charge", "request-1", _FINGERPRINT
    )
    compatibility_action = object()

    assert compatibility.prepare_non_atomic_sqlite_action(
        compatibility_claim, compatibility_action
    )
    assert compatibility_ledger.prepared == (
        compatibility_claim,
        compatibility_action,
    )

    atomic_path = tmp_path / "atomic.db"
    atomic_store = SQLiteIdempotencyStore(atomic_path)
    atomic_ledger = _RecordingLedger(atomic_path)
    atomic = DurableOperationCapability(atomic_store, atomic_ledger)
    atomic_claim = atomic_store.acquire("tenant/charge", "request-1", _FINGERPRINT)
    atomic_action = object()
    error = TimeoutError("request stopped waiting")

    assert atomic.supports_atomic_preparation
    assert atomic.record_orphaned_prepared_claim_unknown(
        atomic_claim, atomic_action, error
    )
    assert atomic_ledger.unknown == (atomic_claim, atomic_action, error)


def test_capability_rejects_independent_in_memory_sqlite_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Use adapter shells to isolate static path classification from database setup.
    store = object.__new__(SQLiteIdempotencyStore)
    store.path = Path(":memory:")
    ledger = object.__new__(SQLiteReconciliationLedger)
    ledger.path = Path(":memory:")
    monkeypatch.setattr(Path, "is_file", lambda _path: True)
    capability = DurableOperationCapability(store, ledger)

    assert capability.supports_atomic_preparation is False
    assert (
        capability.reconciliation_durability
        is _ReconciliationDurability.COLOCATED_DATABASE_REQUIRED
    )
