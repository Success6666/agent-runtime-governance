from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_runtime_governance import (
    IdempotencyAlreadyAppliedError,
    IdempotencyOutcomeUnknownError,
    InMemoryIdempotencyStore,
    InMemoryReconciliationLedger,
    InvalidReconciliationTransitionError,
    ManualResolution,
    ProviderDescriptor,
    ReconciliationAttemptContext,
    ReconciliationAttemptOutcome,
    ReconciliationConflictError,
    ReconciliationDisposition,
    ReconciliationError,
    ReconciliationEventKind,
    ReconciliationFinding,
    ReconciliationHead,
    ReconciliationRecord,
    ReconciliationState,
    ReconciliationTransition,
    ReconciliationTransitionSource,
    ReconciliationValidationError,
    SQLiteIdempotencyStore,
    SQLiteReconciliationLedger,
    UnknownAction,
    idempotency_namespace_digest,
)
from agent_runtime_governance._sqlite import (
    SQLiteJournalModeError,
    connect_sqlite,
    sqlite_journal_capabilities,
    sqlite_wal_is_safe,
)
from agent_runtime_governance.reconciliation import _require_legal_transition

_ACTION_DIGEST = "a" * 64
_OPERATOR_DIGEST = "b" * 64


async def _provider(context: ReconciliationAttemptContext) -> ReconciliationFinding:
    raise AssertionError(f"provider should not be called by the ledger: {context}")


def _descriptor() -> ProviderDescriptor:
    return ProviderDescriptor(
        provider_id="receipt-store",
        protocol_version="1",
        supported_evidence_kinds=("receipt", "probe"),
        provider=_provider,
    )


def _unknown(execution_record_id: str = "e" * 64) -> UnknownAction:
    return UnknownAction(
        execution_record_id=execution_record_id,
        action_digest=_ACTION_DIGEST,
        tool_name="charge",
        contract_id="billing.charge",
        contract_version=1,
        idempotency_namespace_digest=idempotency_namespace_digest("tenant/charge"),
        uncertainty_reason="connection dropped after dispatch",
        attempted_at=datetime.now(timezone.utc),
        receipt_schema={
            "type": "object",
            "properties": {"receipt_id": {"type": "string"}},
            "required": ["receipt_id"],
            "additionalProperties": False,
        },
        probe_schema={"type": "object"},
        result_schema={
            "type": ["object", "null"],
            "properties": {"status": {"const": "paid"}},
            "required": ["status"],
        },
        max_evidence_bytes=1024,
        max_result_bytes=1024,
        metadata={"region": "cn-east"},
    )


def _context(
    action: UnknownAction, attempt_id: str = "attempt-1"
) -> ReconciliationAttemptContext:
    return ReconciliationAttemptContext(
        attempt_id=attempt_id,
        deadline=datetime.now(timezone.utc) + timedelta(seconds=5),
        protocol_version="1",
        action=action,
    )


def _finding(
    state: ReconciliationState = ReconciliationState.CONFIRMED_SUCCEEDED,
    *,
    result: object | None = None,
    result_available: bool = False,
) -> ReconciliationFinding:
    return ReconciliationFinding(
        proposed_state=state,
        evidence_kind="receipt",
        evidence={"receipt_id": "rcpt-1"},
        observed_at=datetime.now(timezone.utc),
        retry_safe=state is ReconciliationState.CONFIRMED_NOT_APPLIED,
        resolved_result=result,
        resolved_result_available=result_available,
    )


@pytest.mark.parametrize(
    "ledger_factory",
    [
        lambda _: InMemoryReconciliationLedger(),
        lambda path: SQLiteReconciliationLedger(path),
    ],
)
def test_attempt_events_and_transition_have_distinct_revisions(
    tmp_path: Path, ledger_factory
) -> None:
    ledger = ledger_factory(tmp_path / "ledger.db")
    action = _unknown()
    context = _context(action)
    provider = _descriptor()
    finding = _finding(result={"status": "paid"})

    assert ledger.create_unknown(action).revision == 0
    started = ledger.start_attempt(context, provider, 0)
    finished = ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=finding,
    )
    head = ledger.compare_and_append_transition(
        action.execution_record_id,
        ReconciliationState.UNKNOWN,
        2,
        finding,
        provider=provider,
        attempt_id=context.attempt_id,
    )

    assert (started.revision, finished.revision, head.revision) == (1, 2, 3)
    assert started.state_before is started.state_after is ReconciliationState.UNKNOWN
    assert finished.state_before is finished.state_after is ReconciliationState.UNKNOWN
    assert head.state is ReconciliationState.CONFIRMED_SUCCEEDED
    assert head.disposition is ReconciliationDisposition.COMPLETED
    assert [record.kind for record in ledger.history(action.execution_record_id)] == [
        ReconciliationEventKind.ATTEMPT_STARTED,
        ReconciliationEventKind.ATTEMPT_FINISHED,
        ReconciliationEventKind.STATE_TRANSITION,
    ]


def test_finding_cannot_self_report_provider_identity() -> None:
    finding = _finding()
    assert not hasattr(finding, "provider_id")
    with pytest.raises((AttributeError, FrozenInstanceError, TypeError)):
        finding.provider_id = "forged"  # type: ignore[attr-defined]


def test_provider_descriptor_accepts_immutable_versioned_capabilities() -> None:
    descriptor = ProviderDescriptor(
        provider_id="probe-store",
        protocol_version=1,
        supported_evidence_kinds=frozenset({"probe"}),
        provider=_provider,
    )
    assert descriptor.protocol_version == 1
    assert descriptor.supported_evidence_kinds == ("probe",)


def test_protocol_values_round_trip_without_losing_json_null() -> None:
    action = _unknown()
    context = _context(action)
    finding = _finding(result=None, result_available=True)
    assert UnknownAction.from_dict(action.to_dict()) == action
    assert ReconciliationAttemptContext.from_dict(context.to_dict()) == context
    assert ReconciliationFinding.from_dict(finding.to_dict()) == finding


def test_transition_requires_matching_successful_attempt() -> None:
    ledger = InMemoryReconciliationLedger()
    action = _unknown()
    ledger.create_unknown(action)
    finding = _finding()
    with pytest.raises(ReconciliationConflictError, match="successful attempt"):
        ledger.compare_and_append_transition(
            action.execution_record_id,
            ReconciliationState.UNKNOWN,
            0,
            finding,
            provider=_descriptor(),
            attempt_id="missing-attempt",
        )


def test_stale_attempt_and_transition_cas_fail_closed() -> None:
    ledger = InMemoryReconciliationLedger()
    action = _unknown()
    context = _context(action)
    provider = _descriptor()
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)

    with pytest.raises(ReconciliationConflictError):
        ledger.start_attempt(_context(action, "attempt-2"), provider, 0)
    with pytest.raises(ReconciliationConflictError):
        ledger.finish_attempt(
            context,
            provider,
            ReconciliationAttemptOutcome.TIMEOUT,
            0,
        )


@pytest.mark.parametrize(
    "ledger_factory",
    [
        lambda _: InMemoryReconciliationLedger(),
        lambda path: SQLiteReconciliationLedger(path),
    ],
)
def test_expired_unfinished_attempt_is_closed_before_manual_quarantine(
    tmp_path: Path, ledger_factory
) -> None:
    now = datetime.now(timezone.utc)
    ledger = ledger_factory(tmp_path / "expired-attempt-recovery.db")
    action = _unknown()
    provider = _descriptor()
    expired = ReconciliationAttemptContext(
        attempt_id="expired-attempt",
        deadline=now - timedelta(seconds=1),
        protocol_version="1",
        action=action,
    )

    ledger.create_unknown(action)
    ledger.start_attempt(expired, provider, 0)
    with pytest.raises(ReconciliationConflictError, match="unfinished"):
        ledger.start_attempt(_context(action, "second-attempt"), provider, 1)

    recovered = ledger.recover_unfinished_attempts(action.execution_record_id, now=now)
    assert recovered is not None
    assert recovered.state is ReconciliationState.MANUAL_REVIEW
    assert recovered.disposition is ReconciliationDisposition.BLOCKED_MANUAL_REVIEW
    records = ledger.history(action.execution_record_id)
    assert [record.kind for record in records] == [
        ReconciliationEventKind.ATTEMPT_STARTED,
        ReconciliationEventKind.ATTEMPT_FINISHED,
        ReconciliationEventKind.STATE_TRANSITION,
    ]
    assert records[1].payload["attempt_id"] == expired.attempt_id
    assert (
        records[1].payload["outcome"]
        == ReconciliationAttemptOutcome.RECOVERY_REQUIRED.value
    )
    assert records[2].payload["transition"]["source"] == "recovery"


@pytest.mark.parametrize(
    "ledger_factory",
    [
        lambda _: InMemoryReconciliationLedger(),
        lambda path: SQLiteReconciliationLedger(path),
    ],
)
def test_unexpired_unfinished_attempt_blocks_a_competing_probe(
    tmp_path: Path, ledger_factory
) -> None:
    now = datetime.now(timezone.utc)
    ledger = ledger_factory(tmp_path / "unexpired-attempt-lease.db")
    action = _unknown()
    context = ReconciliationAttemptContext(
        attempt_id="active-attempt",
        deadline=now + timedelta(seconds=30),
        protocol_version="1",
        action=action,
    )

    ledger.create_unknown(action)
    ledger.start_attempt(context, _descriptor(), 0)

    observed = ledger.recover_unfinished_attempts(action.execution_record_id, now=now)
    assert observed is not None
    assert observed.state is ReconciliationState.UNKNOWN
    assert observed.revision == 1
    assert len(ledger.history(action.execution_record_id)) == 1


def test_manual_review_can_only_be_resolved_by_verified_manual_value() -> None:
    ledger = InMemoryReconciliationLedger()
    action = _unknown()
    context = _context(action)
    provider = _descriptor()
    review = ReconciliationFinding(
        proposed_state=ReconciliationState.MANUAL_REVIEW,
        evidence_kind="probe",
        evidence={"ambiguous": True},
        observed_at=datetime.now(timezone.utc),
    )
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=review,
    )
    review_head = ledger.compare_and_append_transition(
        action.execution_record_id,
        ReconciliationState.UNKNOWN,
        2,
        review,
        provider=provider,
        attempt_id=context.attempt_id,
    )

    with pytest.raises(InvalidReconciliationTransitionError, match="ManualResolution"):
        ledger.compare_and_append_transition(
            action.execution_record_id,
            ReconciliationState.MANUAL_REVIEW,
            review_head.revision,
            _finding(),
            provider=provider,
            attempt_id=context.attempt_id,
        )

    resolution = ManualResolution(
        execution_record_id=action.execution_record_id,
        operator_identity_digest=_OPERATOR_DIGEST,
        reason="verified with payment processor",
        expected_state=ReconciliationState.MANUAL_REVIEW,
        expected_revision=review_head.revision,
        new_state=ReconciliationState.CONFIRMED_NOT_APPLIED,
        resolved_at=datetime.now(timezone.utc),
        evidence_kind="manual",
        evidence={"ticket": "OPS-42"},
        retry_safe=True,
    )
    resolved = ledger.compare_and_append_transition(
        action.execution_record_id,
        review_head.state,
        review_head.revision,
        resolution,
    )
    assert resolved.disposition is ReconciliationDisposition.RETRY_ALLOWED


@pytest.mark.parametrize(
    ("state", "new_state"),
    [
        (ReconciliationState.CONFIRMED_SUCCEEDED, ReconciliationState.MANUAL_REVIEW),
        (
            ReconciliationState.CONFIRMED_NOT_APPLIED,
            ReconciliationState.CONFIRMED_SUCCEEDED,
        ),
    ],
)
def test_confirmed_states_are_terminal(
    state: ReconciliationState, new_state: ReconciliationState
) -> None:
    ledger = InMemoryReconciliationLedger()
    action = _unknown()
    context = _context(action)
    provider = _descriptor()
    finding = _finding(state)
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=finding,
    )
    head = ledger.compare_and_append_transition(
        action.execution_record_id,
        ReconciliationState.UNKNOWN,
        2,
        finding,
        provider=provider,
        attempt_id=context.attempt_id,
    )
    with pytest.raises(InvalidReconciliationTransitionError):
        ledger.start_attempt(_context(action, "later"), provider, head.revision)


@given(
    st.sampled_from(tuple(ReconciliationState)),
    st.sampled_from(tuple(ReconciliationState)),
)
def test_transition_relation_is_exhaustive(
    current: ReconciliationState, new: ReconciliationState
) -> None:
    legal = {
        (ReconciliationState.UNKNOWN, ReconciliationState.CONFIRMED_SUCCEEDED),
        (ReconciliationState.UNKNOWN, ReconciliationState.CONFIRMED_NOT_APPLIED),
        (ReconciliationState.UNKNOWN, ReconciliationState.MANUAL_REVIEW),
        (
            ReconciliationState.MANUAL_REVIEW,
            ReconciliationState.CONFIRMED_SUCCEEDED,
        ),
        (
            ReconciliationState.MANUAL_REVIEW,
            ReconciliationState.CONFIRMED_NOT_APPLIED,
        ),
    }
    if (current, new) in legal:
        _require_legal_transition(current, new)
    else:
        with pytest.raises(InvalidReconciliationTransitionError):
            _require_legal_transition(current, new)


def test_json_null_result_is_distinct_from_missing_result() -> None:
    with_null = _finding(result=None, result_available=True)
    without_result = _finding()
    assert with_null.resolved_result_available is True
    assert without_result.resolved_result_available is False


def test_evidence_bounds_schema_and_sensitive_fields_fail_closed() -> None:
    with pytest.raises(ReconciliationValidationError, match="cannot be empty"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence={},
            observed_at=datetime.now(timezone.utc),
        )
    with pytest.raises(ReconciliationValidationError, match="sensitive"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence={"password": "do-not-store"},
            observed_at=datetime.now(timezone.utc),
        )
    with pytest.raises(ReconciliationValidationError, match="provider_id"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence={"provider_id": "self-asserted"},
            observed_at=datetime.now(timezone.utc),
        )

    ledger = InMemoryReconciliationLedger()
    action = _unknown()
    context = _context(action)
    provider = _descriptor()
    malformed = ReconciliationFinding(
        proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
        evidence_kind="receipt",
        evidence={"unexpected": True},
        observed_at=datetime.now(timezone.utc),
    )
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=malformed,
    )
    with pytest.raises(ReconciliationValidationError, match="contract violation"):
        ledger.compare_and_append_transition(
            action.execution_record_id,
            ReconciliationState.UNKNOWN,
            2,
            malformed,
            provider=provider,
            attempt_id=context.attempt_id,
        )


def test_evidence_depth_non_finite_and_size_limits_fail_closed() -> None:
    nested: dict[str, object] = {}
    cursor = nested
    for _ in range(34):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    with pytest.raises(ReconciliationValidationError, match="maximum depth"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence=nested,
            observed_at=datetime.now(timezone.utc),
        )

    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(ReconciliationValidationError, match="cyclic"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence=cyclic,
            observed_at=datetime.now(timezone.utc),
        )

    class Code(str, Enum):
        OK = "ok"

    for invalid in (Code.OK, ("tuple",)):
        with pytest.raises(ReconciliationValidationError, match="unsupported type"):
            ReconciliationFinding(
                proposed_state=ReconciliationState.MANUAL_REVIEW,
                evidence_kind="probe",
                evidence={"value": invalid},
                observed_at=datetime.now(timezone.utc),
            )
    with pytest.raises(ReconciliationValidationError, match="non-finite"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence={"value": float("nan")},
            observed_at=datetime.now(timezone.utc),
        )
    with pytest.raises(ReconciliationValidationError, match="exceeds"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence={"value": "x" * 70_000},
            observed_at=datetime.now(timezone.utc),
        )


def test_sqlite_transition_updates_idempotency_authority_atomically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "shared.db"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    store.mark_unknown(claim, RuntimeError("uncertain"))
    assert claim.execution_record_id is not None

    ledger = SQLiteReconciliationLedger(path)
    action = _unknown(claim.execution_record_id)
    context = _context(action)
    provider = _descriptor()
    finding = _finding(result=None, result_available=True)
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=finding,
    )
    head = ledger.compare_and_append_transition(
        action.execution_record_id,
        ReconciliationState.UNKNOWN,
        2,
        finding,
        provider=provider,
        attempt_id=context.attempt_id,
    )

    assert head.disposition is ReconciliationDisposition.COMPLETED
    assert (
        store.acquire("tenant/charge", "request-1", _ACTION_DIGEST).future.result()
        is None
    )
    with closing(sqlite3.connect(path)) as connection:
        state, result_json = connection.execute(
            """
            SELECT state, result_json FROM idempotency_records
            WHERE execution_record_id = ?
            """,
            (claim.execution_record_id,),
        ).fetchone()
    assert (state, result_json) == ("completed", "null")


def test_sqlite_record_unknown_commits_authority_and_head_together(
    tmp_path: Path,
) -> None:
    path = tmp_path / "atomic-unknown.db"
    raw_key = "caller-visible-idempotency-key"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", raw_key, _ACTION_DIGEST)
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)

    head = ledger.record_unknown(
        claim,
        _unknown(claim.execution_record_id),
        TimeoutError("external call outcome is uncertain"),
    )

    assert head.state is ReconciliationState.UNKNOWN
    with closing(sqlite3.connect(path)) as connection:
        state = connection.execute(
            """
            SELECT state FROM idempotency_records
            WHERE execution_record_id = ?
            """,
            (claim.execution_record_id,),
        ).fetchone()[0]
        head_count = connection.execute(
            """
            SELECT COUNT(*) FROM reconciliation_heads
            WHERE execution_record_id = ?
            """,
            (claim.execution_record_id,),
        ).fetchone()[0]
    assert state == "unknown"
    assert head_count == 1

    duplicate = SQLiteIdempotencyStore(path).acquire(
        "tenant/charge", raw_key, _ACTION_DIGEST
    )
    with pytest.raises(IdempotencyOutcomeUnknownError) as blocked:
        duplicate.future.result()
    assert blocked.value.execution_record_id == claim.execution_record_id
    assert raw_key not in str(blocked.value)


def test_expired_prepared_lease_materializes_reconciliation_head(
    tmp_path: Path,
) -> None:
    path = tmp_path / "expired-prepared.db"
    raw_key = "caller-visible-idempotency-key"
    store = SQLiteIdempotencyStore(path, lease_seconds=60)
    claim = store.acquire("tenant/charge", raw_key, _ACTION_DIGEST)
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown(claim.execution_record_id)
    ledger.prepare_action(claim, action)

    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                UPDATE idempotency_records SET lease_expires_at = ?
                WHERE execution_record_id = ?
                """,
                (expired, claim.execution_record_id),
            )

    duplicate = SQLiteIdempotencyStore(path).acquire(
        "tenant/charge", raw_key, _ACTION_DIGEST
    )
    with pytest.raises(IdempotencyOutcomeUnknownError) as blocked:
        duplicate.future.result()
    assert blocked.value.execution_record_id == claim.execution_record_id
    head = ledger.current(claim.execution_record_id)
    assert head.state is ReconciliationState.UNKNOWN
    assert head.action.to_dict() == action.to_dict()
    with closing(sqlite3.connect(path)) as connection:
        prepared = connection.execute(
            """
            SELECT action_json FROM reconciliation_prepared_actions
            WHERE execution_record_id = ?
            """,
            (claim.execution_record_id,),
        ).fetchone()[0]
    assert raw_key not in prepared


def test_atomic_prepared_acquire_rolls_back_claim_when_descriptor_insert_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "atomic-prepared-rollback.db"
    store = SQLiteIdempotencyStore(path)
    SQLiteReconciliationLedger(path)
    action = _unknown("f" * 64)

    def fail_insert(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated descriptor persistence failure")

    monkeypatch.setattr(store, "_insert_prepared_action", fail_insert)

    with pytest.raises(RuntimeError, match="descriptor persistence"):
        store.acquire_prepared("tenant/charge", "request-1", _ACTION_DIGEST, action)

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM idempotency_records"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM reconciliation_prepared_actions"
        ).fetchone()[0] == 0


def test_expired_atomically_prepared_lease_materializes_reconciliation_head(
    tmp_path: Path,
) -> None:
    path = tmp_path / "expired-atomic-prepared.db"
    raw_key = "caller-visible-idempotency-key"
    store = SQLiteIdempotencyStore(path, lease_seconds=60)
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown("f" * 64)

    claim = store.acquire_prepared("tenant/charge", raw_key, _ACTION_DIGEST, action)
    assert claim.execution_record_id == action.execution_record_id

    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                UPDATE idempotency_records SET lease_expires_at = ?
                WHERE execution_record_id = ?
                """,
                (expired, action.execution_record_id),
            )

    duplicate = SQLiteIdempotencyStore(path).acquire(
        "tenant/charge", raw_key, _ACTION_DIGEST
    )
    with pytest.raises(IdempotencyOutcomeUnknownError) as blocked:
        duplicate.future.result()
    assert blocked.value.execution_record_id == action.execution_record_id
    assert ledger.current(action.execution_record_id).action.to_dict() == action.to_dict()


def test_legacy_lease_recovery_backfills_audit_snapshot_during_v4_migration(
    tmp_path: Path,
) -> None:
    """A recovery performed before the outbox migration must remain auditable."""

    path = tmp_path / "legacy-recovery-audit-migration.db"
    raw_key = "caller-visible-idempotency-key"
    store = SQLiteIdempotencyStore(path, lease_seconds=60)
    # Materialize the v0.6 ledger tables, then remove the v0.7 outbox to
    # reproduce a process that recovers an expired lease before this migration
    # has been initialized.
    SQLiteReconciliationLedger(path)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "DROP TRIGGER IF EXISTS reconciliation_audit_outbox_immutable"
            )
            connection.execute(
                "DROP TRIGGER IF EXISTS reconciliation_audit_outbox_no_delete"
            )
            connection.execute("DROP TABLE reconciliation_audit_outbox")
            connection.execute(
                "UPDATE reconciliation_schema SET version = 3 WHERE singleton = 1"
            )

    claim = store.acquire("tenant/charge", raw_key, _ACTION_DIGEST)
    assert claim.execution_record_id is not None
    action = _unknown(claim.execution_record_id)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO reconciliation_prepared_actions(
                    execution_record_id, action_json, prepared_at
                ) VALUES (?, ?, ?)
                """,
                (
                    claim.execution_record_id,
                    json.dumps(action.to_dict(), sort_keys=True),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            connection.execute(
                """
                UPDATE idempotency_records SET lease_expires_at = ?
                WHERE execution_record_id = ?
                """,
                (
                    (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                    claim.execution_record_id,
                ),
            )

    duplicate = SQLiteIdempotencyStore(path).acquire(
        "tenant/charge", raw_key, _ACTION_DIGEST
    )
    with pytest.raises(IdempotencyOutcomeUnknownError):
        duplicate.future.result()

    migrated = SQLiteReconciliationLedger(path)
    head = migrated.current(claim.execution_record_id)
    assert head.state is ReconciliationState.UNKNOWN
    pending = migrated.pending_audit_events(
        execution_record_id=claim.execution_record_id
    )
    assert [event.event_type for event in pending] == [
        "migration_snapshot_recorded"
    ]
    assert raw_key not in str(pending[0].to_dict())
    with closing(sqlite3.connect(path)) as connection:
        version = connection.execute(
            "SELECT version FROM reconciliation_schema WHERE singleton = 1"
        ).fetchone()[0]
    assert version == 4


def test_reconciliation_audit_outbox_is_ordered_and_redacted(tmp_path: Path) -> None:
    path = tmp_path / "reconciliation-audit-outbox.db"
    raw_key = "caller-visible-idempotency-key"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", raw_key, _ACTION_DIGEST)
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown(claim.execution_record_id)
    head = ledger.record_unknown(claim, action, TimeoutError("outcome uncertain"))
    context = _context(action)
    provider = _descriptor()
    started = ledger.start_attempt(context, provider, head.revision)
    finding = _finding()
    finished = ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        started.revision,
        finding=finding,
    )
    ledger.compare_and_append_transition(
        action.execution_record_id,
        ReconciliationState.UNKNOWN,
        finished.revision,
        finding,
        provider=provider,
        attempt_id=context.attempt_id,
    )

    delivered_types: list[str] = []
    while pending := ledger.pending_audit_events(
        execution_record_id=action.execution_record_id
    ):
        assert len(pending) == 1
        envelope = pending[0]
        delivered_types.append(envelope.event_type)
        serialized = str(envelope.to_dict())
        assert raw_key not in serialized
        assert "tenant/charge" not in serialized
        assert "rcpt-1" not in serialized
        assert "region" not in serialized
        ledger.mark_audit_event_delivered(envelope.outbox_id)

    assert delivered_types == [
        "unknown_recorded",
        "attempt_started",
        "attempt_finished",
        "transition_recorded",
    ]


def test_reconciliation_audit_outbox_rejects_tampered_payload(tmp_path: Path) -> None:
    path = tmp_path / "reconciliation-audit-integrity.db"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    ledger.record_unknown(
        claim,
        _unknown(claim.execution_record_id),
        TimeoutError("outcome uncertain"),
    )

    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "DROP TRIGGER IF EXISTS reconciliation_audit_outbox_immutable"
            )
            connection.execute(
                """
                UPDATE reconciliation_audit_outbox
                SET event_json = '{"stage":"reconciliation","forged":true}'
                """
            )

    with pytest.raises(ReconciliationError, match="payload digest mismatch"):
        ledger.pending_audit_events(execution_record_id=claim.execution_record_id)


def test_known_failure_removes_atomically_prepared_descriptor(tmp_path: Path) -> None:
    path = tmp_path / "prepared-failure-cleanup.db"
    store = SQLiteIdempotencyStore(path)
    SQLiteReconciliationLedger(path)
    action = _unknown("f" * 64)
    claim = store.acquire_prepared("tenant/charge", "request-1", _ACTION_DIGEST, action)

    store.fail(claim, ValueError("validation failed before dispatch"))

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM idempotency_records"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM reconciliation_prepared_actions"
        ).fetchone()[0] == 0


def test_sqlite_prepared_actions_are_database_enforced_immutable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "prepared-immutable.db"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    ledger.prepare_action(claim, _unknown(claim.execution_record_id))

    with closing(sqlite3.connect(path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE reconciliation_prepared_actions SET prepared_at = 'x'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute("DELETE FROM reconciliation_prepared_actions")


def test_prune_completed_removes_only_safe_prepared_actions(tmp_path: Path) -> None:
    path = tmp_path / "prepared-retention.db"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    ledger.prepare_action(claim, _unknown(claim.execution_record_id))
    store.complete(claim, {"ok": True})

    assert store.prune_completed(
        older_than=datetime.now(timezone.utc) + timedelta(seconds=1)
    ) == 1
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM reconciliation_prepared_actions"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM idempotency_records"
        ).fetchone()[0] == 0


def test_sqlite_transition_rolls_back_head_and_event_when_authority_is_stale(
    tmp_path: Path,
) -> None:
    path = tmp_path / "atomic-rollback.db"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    store.mark_unknown(claim, RuntimeError("uncertain"))
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown(claim.execution_record_id)
    context = _context(action)
    provider = _descriptor()
    finding = _finding(result={"status": "paid"})
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=finding,
    )

    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            """
            UPDATE idempotency_records
            SET state = 'completed', result_json = '{"status":"already-completed"}',
                error = NULL
            WHERE execution_record_id = ?
            """,
            (claim.execution_record_id,),
        )
        connection.commit()

    with pytest.raises(ReconciliationConflictError, match="authority"):
        ledger.compare_and_append_transition(
            action.execution_record_id,
            ReconciliationState.UNKNOWN,
            2,
            finding,
            provider=provider,
            attempt_id=context.attempt_id,
        )
    assert ledger.current(action.execution_record_id).revision == 2
    assert (
        ledger.current(action.execution_record_id).state is ReconciliationState.UNKNOWN
    )
    assert len(ledger.history(action.execution_record_id)) == 2


def test_confirmed_not_applied_allows_explicit_next_generation(tmp_path: Path) -> None:
    path = tmp_path / "generations.db"
    store = SQLiteIdempotencyStore(path)
    first = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    store.mark_unknown(first, RuntimeError("uncertain"))
    assert first.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown(first.execution_record_id)
    context = _context(action)
    provider = _descriptor()
    finding = _finding(ReconciliationState.CONFIRMED_NOT_APPLIED)
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=finding,
    )
    ledger.compare_and_append_transition(
        action.execution_record_id,
        ReconciliationState.UNKNOWN,
        2,
        finding,
        provider=provider,
        attempt_id=context.attempt_id,
    )

    second = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    assert second.owner is True
    assert second.generation == 2
    assert second.execution_record_id != first.execution_record_id


def test_confirmed_success_without_result_remains_blocked(tmp_path: Path) -> None:
    path = tmp_path / "applied.db"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    store.mark_unknown(claim, RuntimeError("uncertain"))
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown(claim.execution_record_id)
    context = _context(action)
    provider = _descriptor()
    finding = _finding()
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.SUCCESS,
        1,
        finding=finding,
    )
    ledger.compare_and_append_transition(
        action.execution_record_id,
        ReconciliationState.UNKNOWN,
        2,
        finding,
        provider=provider,
        attempt_id=context.attempt_id,
    )
    duplicate = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    with pytest.raises(IdempotencyAlreadyAppliedError):
        duplicate.future.result()


def test_sqlite_events_are_database_enforced_append_only(tmp_path: Path) -> None:
    path = tmp_path / "append-only.db"
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown()
    ledger.create_unknown(action)
    ledger.start_attempt(_context(action), _descriptor(), 0)

    with closing(sqlite3.connect(path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE reconciliation_events SET revision = 99")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM reconciliation_events")


def test_sqlite_connections_enforce_reconciliation_foreign_keys(tmp_path: Path) -> None:
    path = tmp_path / "foreign-keys.db"
    SQLiteReconciliationLedger(path)
    with connect_sqlite(path, 1.0) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            connection.execute(
                """
                INSERT INTO reconciliation_events(
                    event_id, execution_record_id, revision, kind, state_before,
                    state_after, occurred_at, payload_json
                ) VALUES (?, ?, 1, 'ATTEMPT_STARTED', 'UNKNOWN', 'UNKNOWN', ?, '{}')
                """,
                (
                    "event-orphan",
                    "missing-execution",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


def test_colocated_ledger_rejects_mismatched_action_identity(tmp_path: Path) -> None:
    path = tmp_path / "identity-link.db"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", "request-1", _ACTION_DIGEST)
    store.mark_unknown(claim, RuntimeError("uncertain"))
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)

    wrong_digest_data = _unknown(claim.execution_record_id).to_dict()
    wrong_digest_data["action_digest"] = "f" * 64
    wrong_digest = UnknownAction.from_dict(wrong_digest_data)
    with pytest.raises(ReconciliationValidationError, match="digest"):
        ledger.create_unknown(wrong_digest)

    wrong_namespace_data = _unknown(claim.execution_record_id).to_dict()
    wrong_namespace_data["idempotency_namespace_digest"] = idempotency_namespace_digest(
        "another/namespace"
    )
    wrong_namespace = UnknownAction.from_dict(wrong_namespace_data)
    with pytest.raises(ReconciliationValidationError, match="namespace"):
        ledger.create_unknown(wrong_namespace)


def test_sqlite_restarts_without_losing_history(tmp_path: Path) -> None:
    path = tmp_path / "restart.db"
    first = SQLiteReconciliationLedger(path)
    action = _unknown()
    first.create_unknown(action)
    first.start_attempt(_context(action), _descriptor(), 0)

    restarted = SQLiteReconciliationLedger(path)
    assert restarted.current(action.execution_record_id).revision == 1
    assert len(restarted.attempts(action.execution_record_id)) == 1
    assert restarted.journal_mode == sqlite_journal_capabilities(
        "auto"
    ).selected_mode
    with connect_sqlite(path, 1.0) as connection:
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2


@pytest.mark.parametrize(
    "ledger_factory",
    [
        lambda _: InMemoryReconciliationLedger(),
        lambda path: SQLiteReconciliationLedger(path),
    ],
)
def test_concurrent_transition_cas_has_exactly_one_winner(
    tmp_path: Path, ledger_factory
) -> None:
    ledger = ledger_factory(tmp_path / "race.db")
    action = _unknown()
    provider = _descriptor()
    ledger.create_unknown(action)
    findings: list[tuple[ReconciliationAttemptContext, ReconciliationFinding]] = []
    revision = 0
    for index in range(2):
        context = _context(action, f"attempt-{index}")
        finding = ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": f"rcpt-{index}"},
            observed_at=datetime.now(timezone.utc),
        )
        ledger.start_attempt(context, provider, revision)
        ledger.finish_attempt(
            context,
            provider,
            ReconciliationAttemptOutcome.SUCCESS,
            revision + 1,
            finding=finding,
        )
        revision += 2
        findings.append((context, finding))

    def transition(item) -> str:
        context, finding = item
        try:
            ledger.compare_and_append_transition(
                action.execution_record_id,
                ReconciliationState.UNKNOWN,
                revision,
                finding,
                provider=provider,
                attempt_id=context.attempt_id,
            )
        except ReconciliationConflictError:
            return "conflict"
        return "committed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(transition, findings))
    assert sorted(outcomes) == ["committed", "conflict"]


def test_v06_idempotency_schema_is_rebuilt_without_data_loss(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            """
            CREATE TABLE idempotency_records (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                state TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                owner_token TEXT,
                lease_expires_at TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(namespace, key)
            )
            """
        )
        now = datetime.now(timezone.utc).isoformat()
        connection.executemany(
            """
            INSERT INTO idempotency_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("ns", "done", "a" * 64, "completed", "1", None, None, None, now),
                (
                    "ns",
                    "pending",
                    "b" * 64,
                    "pending",
                    None,
                    None,
                    "owner",
                    (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    now,
                ),
                ("ns", "unknown", "c" * 64, "unknown", None, "lost", None, None, now),
            ],
        )
        connection.commit()

    ledger = SQLiteReconciliationLedger(path, journal_mode="delete")
    assert ledger.journal_mode == "delete"
    with closing(sqlite3.connect(path)) as connection:
        columns = {
            row[1]: row
            for row in connection.execute("PRAGMA table_info(idempotency_records)")
        }
        rows = connection.execute(
            """
            SELECT key, state, result_json, error, owner_token, lease_expires_at,
                   execution_record_id, generation
            FROM idempotency_records ORDER BY key
            """
        ).fetchall()
    assert columns["execution_record_id"][3] == 1
    assert columns["generation"][3] == 1
    assert [row[0] for row in rows] == ["done", "pending", "unknown"]
    assert all(len(row[6]) == 64 and row[7] == 1 for row in rows)
    migrated_ids = {row[0]: row[6] for row in rows}

    SQLiteIdempotencyStore(path)
    with closing(sqlite3.connect(path)) as connection:
        reopened_ids = dict(
            connection.execute(
                "SELECT key, execution_record_id FROM idempotency_records"
            ).fetchall()
        )
    assert reopened_ids == migrated_ids


def test_v06_migration_normalizes_malformed_rows_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "malformed-legacy.db"
    now = datetime.now(timezone.utc).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            """
            CREATE TABLE idempotency_records (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                state TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                owner_token TEXT,
                lease_expires_at TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(namespace, key)
            )
            """
        )
        connection.executemany(
            "INSERT INTO idempotency_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("ns", "missing-result", "1" * 64, "completed", None, None, "stale", future, now),
                ("ns", "invalid-state", "2" * 64, "corrupt", "1", None, "stale", future, now),
                ("ns", "missing-lease", "3" * 64, "pending", None, None, "owner", None, now),
                ("ns", "invalid-lease", "4" * 64, "pending", None, None, "owner", "not-a-time", now),
                ("ns", "stale-pending-result", "5" * 64, "pending", "1", None, "owner", future, now),
                ("ns", "invalid-result", "6" * 64, "completed", "{", None, None, None, now),
                ("ns", "unknown-residue", "7" * 64, "unknown", "1", "lost", "stale", future, now),
                ("ns", "valid", "8" * 64, "completed", "{ \"ok\" : true }", "stale", None, None, now),
            ],
        )
        connection.commit()

    SQLiteIdempotencyStore(path, journal_mode="delete")
    with connect_sqlite(path, 1.0) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        rows = {
            key: (state, result_json, error, owner, lease)
            for key, state, result_json, error, owner, lease in connection.execute(
                """
                SELECT key, state, result_json, error, owner_token, lease_expires_at
                FROM idempotency_records
                """
            )
        }

    assert rows["missing-result"][0] == "applied_no_result"
    assert rows["invalid-state"][0] == "unknown"
    assert rows["missing-lease"][0] == "unknown"
    assert rows["invalid-lease"][0] == "unknown"
    assert rows["stale-pending-result"][0] == "unknown"
    assert rows["invalid-result"][0] == "applied_no_result"
    assert rows["unknown-residue"] == ("unknown", None, "lost", None, None)
    assert rows["valid"] == ("completed", '{"ok":true}', None, None, None)
    assert all(row[3] is None and row[4] is None for row in rows.values())


@pytest.mark.parametrize("durable", [False, True])
def test_same_action_with_different_keys_has_distinct_execution_records(
    tmp_path: Path, durable: bool
) -> None:
    store = (
        SQLiteIdempotencyStore(tmp_path / "different-keys.db")
        if durable
        else InMemoryIdempotencyStore()
    )
    first = store.acquire("tenant/charge", "one", _ACTION_DIGEST)
    second = store.acquire("tenant/charge", "two", _ACTION_DIGEST)
    assert first.execution_record_id != second.execution_record_id


def test_in_memory_idempotency_claims_report_first_generation_only() -> None:
    store = InMemoryIdempotencyStore()
    first = store.acquire("tenant/charge", "one", _ACTION_DIGEST)
    repeated = store.acquire("tenant/charge", "one", _ACTION_DIGEST)
    assert first.generation == repeated.generation == 1


def test_sqlite_reconciliation_storage_does_not_persist_raw_idempotency_key(
    tmp_path: Path,
) -> None:
    path = tmp_path / "privacy.db"
    raw_key = "customer-visible-request-987654"
    store = SQLiteIdempotencyStore(path)
    claim = store.acquire("tenant/charge", raw_key, _ACTION_DIGEST)
    store.mark_unknown(claim, RuntimeError("uncertain"))
    assert claim.execution_record_id is not None
    ledger = SQLiteReconciliationLedger(path)
    action = _unknown(claim.execution_record_id)
    ledger.create_unknown(action)
    ledger.start_attempt(_context(action), _descriptor(), 0)

    with closing(sqlite3.connect(path)) as connection:
        action_json = connection.execute(
            "SELECT action_json FROM reconciliation_heads"
        ).fetchone()[0]
        event_json = connection.execute(
            "SELECT payload_json FROM reconciliation_events"
        ).fetchone()[0]
    assert raw_key not in action_json
    assert raw_key not in event_json


@pytest.mark.parametrize(
    ("version", "safe"),
    [
        ((3, 44, 5), False),
        ((3, 44, 6), True),
        ((3, 45, 3), False),
        ((3, 50, 6), False),
        ((3, 50, 7), True),
        ((3, 51, 2), False),
        ((3, 51, 3), True),
        ((3, 52, 0), True),
    ],
)
def test_sqlite_wal_version_gate(version: tuple[int, int, int], safe: bool) -> None:
    assert sqlite_wal_is_safe(version) is safe
    assert sqlite_journal_capabilities("auto", version=version).selected_mode == (
        "wal" if safe else "delete"
    )
    if not safe:
        with pytest.raises(SQLiteJournalModeError):
            sqlite_journal_capabilities("wal", version=version)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True])
def test_sqlite_connection_rejects_invalid_timeout_at_public_boundary(
    tmp_path: Path, timeout: float
) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        connect_sqlite(tmp_path / "invalid-timeout.db", timeout)


def test_sqlite_journal_capability_input_validation() -> None:
    assert sqlite_wal_is_safe((3, 50)) is False  # type: ignore[arg-type]
    assert sqlite_wal_is_safe((3, "50", 7)) is False  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="string"):
        sqlite_journal_capabilities(1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="auto"):
        sqlite_journal_capabilities("truncate")


def test_explicit_wal_requirement_fails_closed_on_affected_runtime(
    tmp_path: Path,
) -> None:
    if sqlite_wal_is_safe():
        pytest.skip("linked SQLite runtime contains the WAL-reset race fix")
    with pytest.raises(SQLiteJournalModeError):
        SQLiteReconciliationLedger(tmp_path / "unsafe-wal.db", journal_mode="wal")


def test_unknown_action_validation_and_repr_fail_closed() -> None:
    action = _unknown()
    assert action.execution_record_id in repr(action)
    for field, value, message in (
        ("contract_version", 0, "positive integer"),
        ("max_evidence_bytes", 0, "between"),
        ("max_result_bytes", 1_048_577, "between"),
    ):
        payload = action.to_dict()
        payload[field] = value
        with pytest.raises(ReconciliationValidationError, match=message):
            UnknownAction.from_dict(payload)
    payload = action.to_dict()
    payload["receipt_schema"] = {"type": "not-a-json-type"}
    with pytest.raises(ReconciliationValidationError, match="invalid receipt_schema"):
        UnknownAction.from_dict(payload)

    bound_payload = action.to_dict()
    bound_payload.update(
        {
            "reconciliation_provider_id": "receipt-store",
            "reconciliation_protocol_version": "1",
            "reconciliation_supported_evidence_kinds": ["receipt", "probe"],
        }
    )
    restored = UnknownAction.from_dict(bound_payload)
    assert restored.reconciliation_provider_id == "receipt-store"
    assert restored.reconciliation_protocol_version == "1"
    assert restored.reconciliation_supported_evidence_kinds == ("probe", "receipt")

    malformed_provider = action.to_dict()
    malformed_provider["reconciliation_provider_id"] = "receipt-store"
    with pytest.raises(ReconciliationValidationError, match="protocol version"):
        UnknownAction.from_dict(malformed_provider)
    malformed_kinds = action.to_dict()
    malformed_kinds.update(
        {
            "reconciliation_provider_id": "receipt-store",
            "reconciliation_protocol_version": "1",
            "reconciliation_supported_evidence_kinds": "receipt",
        }
    )
    with pytest.raises(ReconciliationValidationError, match="must be an array"):
        UnknownAction.from_dict(malformed_kinds)


def test_finding_state_and_retry_assertions_fail_closed() -> None:
    common = {
        "evidence_kind": "probe",
        "evidence": {"observed": True},
        "observed_at": datetime.now(timezone.utc),
    }
    with pytest.raises(ReconciliationValidationError, match="inconclusive"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.UNKNOWN,
            **common,
        )
    with pytest.raises(ReconciliationValidationError, match="retry-safe"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_NOT_APPLIED,
            **common,
        )
    with pytest.raises(ReconciliationValidationError, match="valid only"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            retry_safe=True,
            **common,
        )
    with pytest.raises(ReconciliationValidationError, match="resolved_result"):
        ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            resolved_result_available=True,
            **common,
        )


def test_provider_descriptor_rejects_ambiguous_capabilities() -> None:
    with pytest.raises(TypeError, match="tuple or frozenset"):
        ProviderDescriptor(
            provider_id="provider",
            protocol_version=1,
            supported_evidence_kinds=["probe"],  # type: ignore[arg-type]
            provider=_provider,
        )
    with pytest.raises(ReconciliationValidationError, match="cannot be empty"):
        ProviderDescriptor(
            provider_id="provider",
            protocol_version=1,
            supported_evidence_kinds=(),
            provider=_provider,
        )
    with pytest.raises(ReconciliationValidationError, match="duplicates"):
        ProviderDescriptor(
            provider_id="provider",
            protocol_version=1,
            supported_evidence_kinds=("probe", "probe"),
            provider=_provider,
        )
    with pytest.raises(TypeError, match="callable"):
        ProviderDescriptor(
            provider_id="provider",
            protocol_version=1,
            supported_evidence_kinds=("probe",),
            provider=object(),  # type: ignore[arg-type]
        )


def test_attempt_finish_contract_rejects_malformed_lifecycle() -> None:
    ledger = InMemoryReconciliationLedger()
    action = _unknown()
    context = _context(action)
    provider = _descriptor()
    ledger.create_unknown(action)
    ledger.start_attempt(context, provider, 0)
    with pytest.raises(ReconciliationValidationError, match="requires a finding"):
        ledger.finish_attempt(
            context,
            provider,
            ReconciliationAttemptOutcome.SUCCESS,
            1,
        )
    with pytest.raises(ReconciliationValidationError, match="successful attempt"):
        ledger.finish_attempt(
            context,
            provider,
            ReconciliationAttemptOutcome.TIMEOUT,
            1,
            finding=_finding(),
        )
    finished = ledger.finish_attempt(
        context,
        provider,
        ReconciliationAttemptOutcome.TIMEOUT,
        1,
        error="provider deadline elapsed",
    )
    assert finished.revision == 2
    with pytest.raises(ReconciliationConflictError, match="unmatched"):
        ledger.finish_attempt(
            context,
            provider,
            ReconciliationAttemptOutcome.TIMEOUT,
            2,
        )
    with pytest.raises(ReconciliationConflictError, match="already"):
        ledger.start_attempt(context, provider, 2)


def test_manual_resolution_round_trip_and_validation() -> None:
    action = _unknown()
    base = {
        "execution_record_id": action.execution_record_id,
        "operator_identity_digest": _OPERATOR_DIGEST,
        "reason": "verified by operator",
        "expected_state": ReconciliationState.MANUAL_REVIEW,
        "expected_revision": 3,
        "new_state": ReconciliationState.CONFIRMED_SUCCEEDED,
        "resolved_at": datetime.now(timezone.utc),
        "evidence_kind": "manual",
        "evidence": {"ticket": "OPS-7"},
        "resolved_result_available": True,
        "resolved_result": None,
    }
    resolution = ManualResolution(**base)
    assert ManualResolution.from_dict(resolution.to_dict()) == resolution
    for field, value, message in (
        ("expected_state", ReconciliationState.UNKNOWN, "MANUAL_REVIEW"),
        ("expected_revision", -1, "non-negative"),
        ("new_state", ReconciliationState.MANUAL_REVIEW, "terminal"),
    ):
        invalid = dict(base)
        invalid[field] = value
        with pytest.raises(
            (ReconciliationValidationError, InvalidReconciliationTransitionError),
            match=message,
        ):
            ManualResolution(**invalid)


def test_attempt_context_round_trip_and_input_boundaries() -> None:
    context = _context(_unknown())
    assert ReconciliationAttemptContext.from_dict(context.to_dict()) == context

    with pytest.raises(TypeError, match="UnknownAction"):
        ReconciliationAttemptContext(
            attempt_id="attempt",
            deadline=datetime.now(timezone.utc),
            protocol_version=1,
            action=object(),  # type: ignore[arg-type]
        )

    for deadline in (None, "not-a-timestamp"):
        payload = context.to_dict()
        payload["deadline"] = deadline
        with pytest.raises(ReconciliationValidationError, match="timestamp"):
            ReconciliationAttemptContext.from_dict(payload)


def test_reconciliation_finding_type_and_json_boundaries() -> None:
    common = {
        "proposed_state": ReconciliationState.CONFIRMED_SUCCEEDED,
        "evidence_kind": "probe",
        "evidence": {"observed": True},
        "observed_at": datetime.now(timezone.utc),
    }
    with pytest.raises(TypeError, match="proposed_state"):
        ReconciliationFinding(**{**common, "proposed_state": "confirmed_succeeded"})
    with pytest.raises(TypeError, match="retry_safe"):
        ReconciliationFinding(**common, retry_safe=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="resolved_result_available"):
        ReconciliationFinding(
            **common,
            resolved_result_available=1,  # type: ignore[arg-type]
        )

    implicit_result = ReconciliationFinding(**common, resolved_result={"ok": True})
    assert implicit_result.resolved_result_available is True
    assert implicit_result.state is ReconciliationState.CONFIRMED_SUCCEEDED
    assert ReconciliationFinding.from_dict(implicit_result.to_dict()) == implicit_result

    invalid_evidence = (
        [],
        {},
        {1: "not-a-string-key"},
        {"unsupported": object()},
        {"integer": 2**53},
        {"negative_zero": -0.0},
        {"bad_unicode": "\ud800"},
    )
    for evidence in invalid_evidence:
        with pytest.raises(ReconciliationValidationError):
            ReconciliationFinding(**{**common, "evidence": evidence})

    cyclic_object: dict[str, object] = {}
    cyclic_object["self"] = cyclic_object
    cyclic_array: list[object] = []
    cyclic_array.append(cyclic_array)
    for evidence in ({"cycle": cyclic_object}, {"cycle": cyclic_array}):
        with pytest.raises(ReconciliationValidationError, match="cyclic"):
            ReconciliationFinding(**{**common, "evidence": evidence})

    nested_sensitive = {"items": [{"Authorization": "secret"}]}
    with pytest.raises(ReconciliationValidationError, match="sensitive"):
        ReconciliationFinding(**{**common, "evidence": nested_sensitive})

    list_result = ReconciliationFinding(
        **common,
        resolved_result_available=True,
        resolved_result=[{"ok": True}, [1, 2]],
    )
    assert list_result.to_dict()["resolved_result"] == [{"ok": True}, [1, 2]]


def test_manual_resolution_enforces_terminal_evidence_semantics() -> None:
    base = {
        "execution_record_id": "e" * 64,
        "operator_identity_digest": _OPERATOR_DIGEST,
        "reason": "operator verified provider receipt",
        "expected_state": ReconciliationState.MANUAL_REVIEW,
        "expected_revision": 2,
        "new_state": ReconciliationState.CONFIRMED_SUCCEEDED,
        "resolved_at": datetime.now(timezone.utc),
        "evidence_kind": "manual",
        "evidence": {"ticket": "OPS-9"},
    }
    with pytest.raises(TypeError, match="retry_safe"):
        ManualResolution(**base, retry_safe=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="resolved_result_available"):
        ManualResolution(
            **base,
            resolved_result_available=1,  # type: ignore[arg-type]
        )
    with pytest.raises(ReconciliationValidationError, match="retry-safe"):
        ManualResolution(
            **{**base, "new_state": ReconciliationState.CONFIRMED_NOT_APPLIED}
        )
    with pytest.raises(ReconciliationValidationError, match="valid only"):
        ManualResolution(**base, retry_safe=True)
    with pytest.raises(ReconciliationValidationError, match="valid only"):
        ManualResolution(
            **{**base, "new_state": ReconciliationState.CONFIRMED_NOT_APPLIED},
            retry_safe=True,
            resolved_result_available=True,
            resolved_result={"status": "paid"},
        )

    implicit_result = ManualResolution(**base, resolved_result={"status": "paid"})
    assert implicit_result.resolved_result_available is True


def _transition(**overrides: object) -> ReconciliationTransition:
    values: dict[str, object] = {
        "execution_record_id": "e" * 64,
        "expected_state": ReconciliationState.UNKNOWN,
        "expected_revision": 2,
        "new_state": ReconciliationState.CONFIRMED_SUCCEEDED,
        "source": ReconciliationTransitionSource.PROVIDER,
        "evidence_kind": "receipt",
        "evidence": {"receipt_id": "rcpt-1"},
        "occurred_at": datetime.now(timezone.utc),
        "retry_safe": False,
        "resolved_result_available": False,
        "provider_id": "receipt-store",
        "attempt_id": "attempt-1",
    }
    values.update(overrides)
    return ReconciliationTransition(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value", "error", "message"),
    [
        ("expected_state", "unknown", TypeError, "expected_state"),
        ("new_state", "confirmed_succeeded", TypeError, "new_state"),
        ("source", "provider", TypeError, "source"),
        ("expected_revision", -1, ReconciliationValidationError, "non-negative"),
        ("retry_safe", 1, TypeError, "retry_safe"),
        (
            "resolved_result_available",
            1,
            TypeError,
            "resolved_result_available",
        ),
    ],
)
def test_transition_rejects_ambiguous_types(
    field: str, value: object, error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        _transition(**{field: value})


def test_transition_source_identity_and_round_trip_boundaries() -> None:
    transition = _transition()
    assert ReconciliationTransition.from_dict(transition.to_dict()) == transition

    with pytest.raises(ReconciliationValidationError, match="requires provider"):
        _transition(provider_id=None)
    with pytest.raises(ReconciliationValidationError, match="cannot carry operator"):
        _transition(operator_identity_digest=_OPERATOR_DIGEST)
    with pytest.raises(ReconciliationValidationError, match="manual transition"):
        _transition(
            source=ReconciliationTransitionSource.MANUAL,
            provider_id=None,
            attempt_id=None,
        )
    with pytest.raises(ReconciliationValidationError, match="requires resolved"):
        _transition(resolved_result={"status": "paid"})

    manual = _transition(
        source=ReconciliationTransitionSource.MANUAL,
        provider_id=None,
        attempt_id=None,
        operator_identity_digest=_OPERATOR_DIGEST,
        reason="verified manually",
    )
    assert manual.source is ReconciliationTransitionSource.MANUAL


def test_record_and_head_round_trip_and_validation_boundaries() -> None:
    now = datetime.now(timezone.utc)
    record_values: dict[str, object] = {
        "event_id": "f" * 64,
        "execution_record_id": "e" * 64,
        "revision": 1,
        "kind": ReconciliationEventKind.STATE_TRANSITION,
        "state_before": ReconciliationState.UNKNOWN,
        "state_after": ReconciliationState.MANUAL_REVIEW,
        "occurred_at": now,
        "payload": {"operator": {"ticket": "OPS-10"}},
    }
    record = ReconciliationRecord(**record_values)  # type: ignore[arg-type]
    assert ReconciliationRecord.from_dict(record.to_dict()) == record
    for field, value, error, message in (
        ("kind", "state_transition", TypeError, "kind"),
        ("state_before", "unknown", TypeError, "states"),
        ("revision", 0, ReconciliationValidationError, "positive"),
    ):
        with pytest.raises(error, match=message):
            ReconciliationRecord(**{**record_values, field: value})  # type: ignore[arg-type]

    action = _unknown()
    head_values: dict[str, object] = {
        "action": action,
        "state": ReconciliationState.UNKNOWN,
        "revision": 0,
        "disposition": ReconciliationDisposition.BLOCKED_UNKNOWN,
        "updated_at": now,
    }
    head = ReconciliationHead(**head_values)  # type: ignore[arg-type]
    assert head.execution_record_id == action.execution_record_id
    assert ReconciliationHead.from_dict(head.to_dict()) == head
    for field, value, error, message in (
        ("action", object(), TypeError, "UnknownAction"),
        ("state", "unknown", TypeError, "state"),
        ("revision", -1, ReconciliationValidationError, "non-negative"),
        ("disposition", "blocked_unknown", TypeError, "disposition"),
        ("resolved_result_available", 1, TypeError, "resolved_result_available"),
    ):
        with pytest.raises(error, match=message):
            ReconciliationHead(**{**head_values, field: value})  # type: ignore[arg-type]
    with pytest.raises(ReconciliationValidationError, match="requires"):
        ReconciliationHead(**head_values, resolved_result={"status": "paid"})  # type: ignore[arg-type]
