"""Private coordination for durable idempotency and reconciliation adapters."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from ...reconciliation import (
    ReconciliationAuditEnvelope,
    ReconciliationHead,
    ReconciliationLedger,
    SQLiteReconciliationLedger,
    UnknownAction,
)
from ...registry import IdempotencyClaim, IdempotencyStore, SQLiteIdempotencyStore


class _ReconciliationDurability(str, Enum):
    """Internal production-readiness result for the configured adapters."""

    DURABLE_LEDGER_REQUIRED = "durable_ledger_required"
    ATOMIC_ADAPTER_REQUIRED = "atomic_adapter_required"
    COLOCATED_DATABASE_REQUIRED = "colocated_database_required"
    READY = "ready"


class DurableOperationCapability:
    """Bound private operations for one idempotency store and ledger pair.

    The capability is deliberately built from the configured adapter instances;
    callers cannot enable durable coordination by advertising a boolean flag.
    """

    __slots__ = (
        "_idempotency_store",
        "_reconciliation_ledger",
        "_sqlite_idempotency_store",
        "_sqlite_reconciliation_ledger",
        "_same_database",
    )

    def __init__(
        self,
        idempotency_store: IdempotencyStore,
        reconciliation_ledger: ReconciliationLedger | None,
    ) -> None:
        self._idempotency_store = idempotency_store
        self._reconciliation_ledger = reconciliation_ledger
        self._sqlite_idempotency_store = (
            idempotency_store
            if isinstance(idempotency_store, SQLiteIdempotencyStore)
            else None
        )
        self._sqlite_reconciliation_ledger = (
            reconciliation_ledger
            if isinstance(reconciliation_ledger, SQLiteReconciliationLedger)
            else None
        )
        self._same_database = bool(
            self._sqlite_idempotency_store is not None
            and self._sqlite_reconciliation_ledger is not None
            and _same_sqlite_database(
                self._sqlite_idempotency_store,
                self._sqlite_reconciliation_ledger,
            )
        )

    def matches(
        self,
        idempotency_store: IdempotencyStore,
        reconciliation_ledger: ReconciliationLedger | None,
    ) -> bool:
        """Return whether this capability was composed for these exact adapters."""

        return (
            self._idempotency_store is idempotency_store
            and self._reconciliation_ledger is reconciliation_ledger
        )

    @property
    def reconciliation_durability(self) -> _ReconciliationDurability:
        ledger = self._reconciliation_ledger
        if getattr(ledger, "production_durable", False) is not True:
            return _ReconciliationDurability.DURABLE_LEDGER_REQUIRED
        if (
            self._sqlite_idempotency_store is None
            or self._sqlite_reconciliation_ledger is None
        ):
            return _ReconciliationDurability.ATOMIC_ADAPTER_REQUIRED
        if not self._same_database:
            return _ReconciliationDurability.COLOCATED_DATABASE_REQUIRED
        return _ReconciliationDurability.READY

    @property
    def supports_atomic_preparation(self) -> bool:
        return (
            self._sqlite_idempotency_store is not None
            and self._sqlite_reconciliation_ledger is not None
            and self._same_database
        )

    @property
    def supports_sqlite_reconciliation(self) -> bool:
        return self._sqlite_reconciliation_ledger is not None

    @property
    def supports_audit_outbox(self) -> bool:
        return self._sqlite_reconciliation_ledger is not None

    def acquire(
        self,
        namespace: str,
        key: str,
        fingerprint: str,
        *,
        prepared_action: UnknownAction | None = None,
    ) -> IdempotencyClaim:
        if prepared_action is None:
            return self._idempotency_store.acquire(namespace, key, fingerprint)
        store = self._sqlite_idempotency_store
        if store is None or not self.supports_atomic_preparation:
            raise RuntimeError(
                "atomic reconciliation preparation requires a co-located SQLite pair"
            )
        return store.acquire_prepared(namespace, key, fingerprint, prepared_action)

    def prepare_non_atomic_sqlite_action(
        self, claim: IdempotencyClaim, action: UnknownAction
    ) -> bool:
        """Persist the legacy SQLite descriptor path when it is configured."""

        ledger = self._sqlite_reconciliation_ledger
        if ledger is None or self.supports_atomic_preparation:
            return False
        ledger.prepare_action(claim, action)
        return True

    def record_orphaned_prepared_claim_unknown(
        self,
        claim: IdempotencyClaim,
        action: UnknownAction | None,
        error: BaseException,
    ) -> bool:
        """Materialize a timed-out atomic claim without splitting its authority."""

        ledger = self._sqlite_reconciliation_ledger
        if action is None or ledger is None or not self.supports_atomic_preparation:
            return False
        ledger.record_unknown(claim, action, error)
        return True

    def record_unknown(
        self,
        claim: IdempotencyClaim,
        action: UnknownAction,
        error: BaseException,
    ) -> ReconciliationHead:
        ledger = self._require_sqlite_reconciliation()
        return ledger.record_unknown(claim, action, error)

    def pending_audit_events(
        self,
        *,
        execution_record_id: str | None = None,
        limit: int = 128,
    ) -> tuple[ReconciliationAuditEnvelope, ...]:
        return self._require_audit_outbox().pending_audit_events(
            execution_record_id=execution_record_id,
            limit=limit,
        )

    def mark_audit_event_delivered(self, outbox_id: str) -> None:
        self._require_audit_outbox().mark_audit_event_delivered(outbox_id)

    def record_audit_delivery_failure(
        self, outbox_id: str, error: BaseException
    ) -> None:
        self._require_audit_outbox().record_audit_delivery_failure(outbox_id, error)

    def _require_sqlite_reconciliation(self) -> SQLiteReconciliationLedger:
        ledger = self._sqlite_reconciliation_ledger
        if ledger is None:
            raise RuntimeError("SQLite reconciliation is not configured")
        return ledger

    def _require_audit_outbox(self) -> SQLiteReconciliationLedger:
        ledger = self._sqlite_reconciliation_ledger
        if ledger is None:
            raise RuntimeError("durable reconciliation audit outbox is not configured")
        return ledger


def _same_sqlite_database(
    idempotency_store: SQLiteIdempotencyStore,
    reconciliation_ledger: SQLiteReconciliationLedger,
) -> bool:
    return (
        Path(idempotency_store.path).resolve()
        == Path(reconciliation_ledger.path).resolve()
    )


__all__ = ["DurableOperationCapability"]
