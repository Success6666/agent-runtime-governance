from __future__ import annotations

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
    InMemoryIdempotencyStore,
    InMemoryReconciliationLedger,
    InvalidReconciliationTransitionError,
    ManualResolution,
    ProviderDescriptor,
    ReconciliationAttemptContext,
    ReconciliationAttemptOutcome,
    ReconciliationConflictError,
    ReconciliationDisposition,
    ReconciliationEventKind,
    ReconciliationFinding,
    ReconciliationState,
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
    wrong_namespace_data["idempotency_namespace_digest"] = (
        idempotency_namespace_digest("another/namespace")
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
    assert restarted.journal_mode == "delete"
    with closing(sqlite3.connect(path)) as connection:
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

    SQLiteReconciliationLedger(path)
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


def test_explicit_wal_requirement_fails_closed_on_affected_runtime(
    tmp_path: Path,
) -> None:
    if sqlite_wal_is_safe():
        pytest.skip("linked SQLite runtime contains the WAL-reset race fix")
    with pytest.raises(SQLiteJournalModeError):
        SQLiteReconciliationLedger(tmp_path / "unsafe-wal.db", journal_mode="wal")
