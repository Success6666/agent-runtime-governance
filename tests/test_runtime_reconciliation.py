from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_runtime_governance import (
    ActionContract,
    AuditMiddleware,
    ExecutionMode,
    ExecutionStatus,
    InMemoryAuditSink,
    InvocationOptions,
    JSONLAuditSink,
    ProductionProfile,
    ProductionReadinessError,
    ProviderDescriptor,
    ReconciliationAttemptContext,
    ReconciliationAttemptOutcome,
    ReconciliationFinding,
    ReconciliationState,
    Runtime,
    RuntimeLimits,
    SQLiteIdempotencyStore,
    SQLiteReconciliationLedger,
    StaticIdentityProvider,
    ToolExecutionError,
    VerifiedPrincipal,
)

_RESULT_SCHEMA = {
    "type": "object",
    "properties": {"status": {"const": "paid"}},
    "required": ["status"],
    "additionalProperties": False,
}


def _runtime(path: Path, *, limits: RuntimeLimits | None = None) -> Runtime:
    return Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        limits=limits,
    )


@pytest.mark.asyncio
async def test_explicit_reconciliation_restores_only_a_validated_cached_result(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime-reconciliation.db"
    provider_calls: list[str] = []
    dispatches = 0

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        provider_calls.append(context.action.execution_record_id)
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
            resolved_result_available=True,
            resolved_result={"status": "paid"},
        )

    runtime = _runtime(path)

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        result_schema=_RESULT_SCHEMA,
        reconciliation_provider=ProviderDescriptor(
            provider_id="payment-receipt",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=provider,
        ),
    )
    async def charge(amount: int) -> dict[str, str]:
        nonlocal dispatches
        dispatches += 1
        raise TimeoutError(f"charge {amount} may have reached the payment provider")

    options = InvocationOptions(idempotency_key="customer-visible-key")
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun("charge", 100, _governance=options)
        assert failed.value.context.status is ExecutionStatus.UNKNOWN
        execution_record_id = failed.value.context.metadata["execution_record_id"]
        assert isinstance(execution_record_id, str)
        assert provider_calls == []
        pending = runtime.reconciliation_ledger.current(execution_record_id)  # type: ignore[union-attr]
        assert (
            pending.action.uncertainty_reason
            == "execution outcome may require explicit reconciliation"
        )

        head = await runtime.areconcile(execution_record_id)
        assert head.state is ReconciliationState.CONFIRMED_SUCCEEDED
        assert provider_calls == [execution_record_id]
        assert dispatches == 1

        cached = await runtime.ainvoke("charge", 100, _governance=options)
        assert cached == {"status": "paid"}
        assert dispatches == 1
    finally:
        await runtime.aclose()


def _strict_control_plane_runtime(
    path: Path,
    principals: dict[str, VerifiedPrincipal],
) -> tuple[Runtime, list[str]]:
    class KeyProvider:
        def get_key(self, *, tenant: str, version: str) -> bytes:
            assert version == "key-v1"
            assert tenant in {principal.tenant for principal in principals.values()}
            return b"k" * 32

    class ClaimsIdentityProvider:
        production_trusted = True

        def verify(
            self, claims: dict[str, object] | None = None
        ) -> VerifiedPrincipal:
            if claims is None or not isinstance(claims.get("actor"), str):
                raise ValueError("trusted reconciliation claims are required")
            return principals[claims["actor"]]

    provider_calls: list[str] = []
    runtime = Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(path.with_suffix(".audit.jsonl"), sign_key=b"a" * 32),
                fail_closed=True,
            )
        ],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        identity_provider=ClaimsIdentityProvider(),
        require_verified_identity=True,
        production_profile=ProductionProfile(
            identity_digest_key_provider=KeyProvider(),
            identity_digest_key_version="key-v1",
            policy_version="policy-v1",
            policy_digest="a" * 64,
        ),
    )

    contract = ActionContract(
        contract_id="payments.charge",
        contract_version=1,
        tool_name="charge",
        execution_mode=ExecutionMode.IDEMPOTENT,
        parameters_schema={"type": "object", "additionalProperties": False},
        effect_class="payment.charge",
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        provider_calls.append(context.action.execution_record_id)
        return ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence={"case_id": "case-1"},
            observed_at=datetime.now(timezone.utc),
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=contract,
        reconciliation_provider=ProviderDescriptor(
            provider_id="payment-probe",
            protocol_version="1",
            supported_evidence_kinds=("probe",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("payment outcome is uncertain")

    runtime.seal_production()
    return runtime, provider_calls


async def _strict_unknown_execution(runtime: Runtime, *, actor: str) -> str:
    with pytest.raises(ToolExecutionError) as failed:
        await runtime.arun(
            "charge",
            _governance=InvocationOptions(
                idempotency_key="customer-visible-key",
                identity_claims={"actor": actor},
            ),
        )
    execution_record_id = failed.value.execution_record_id
    assert execution_record_id is not None
    return execution_record_id


@pytest.mark.asyncio
async def test_strict_reconciliation_rejects_missing_or_unprivileged_identity(
    tmp_path: Path,
) -> None:
    principals = {
        "writer": VerifiedPrincipal(
            issuer="gateway",
            subject="writer",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:probe"}),
        ),
        "unprivileged": VerifiedPrincipal(
            issuer="gateway",
            subject="unprivileged",
            tenant="tenant-a",
        ),
    }
    runtime, provider_calls = _strict_control_plane_runtime(
        tmp_path / "strict-control.db", principals
    )
    try:
        execution_record_id = await _strict_unknown_execution(runtime, actor="writer")
        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.areconcile(execution_record_id)
        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.areconcile(
                execution_record_id,
                identity_claims={"actor": "unprivileged"},
            )
        assert provider_calls == []
        assert runtime.reconciliation_ledger is not None
        assert runtime.reconciliation_ledger.attempts(execution_record_id) == ()
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_strict_reconciliation_denies_cross_tenant_probe_without_attempt(
    tmp_path: Path,
) -> None:
    principals = {
        "tenant-a": VerifiedPrincipal(
            issuer="gateway",
            subject="tenant-a-operator",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:probe"}),
        ),
        "tenant-b": VerifiedPrincipal(
            issuer="gateway",
            subject="tenant-b-operator",
            tenant="tenant-b",
            permissions=frozenset({"reconciliation:probe", "reconciliation:resolve"}),
        ),
    }
    runtime, provider_calls = _strict_control_plane_runtime(
        tmp_path / "cross-tenant-control.db", principals
    )
    try:
        execution_record_id = await _strict_unknown_execution(runtime, actor="tenant-a")
        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.areconcile(
                execution_record_id,
                identity_claims={"actor": "tenant-b"},
            )
        assert provider_calls == []
        assert runtime.reconciliation_ledger is not None
        assert runtime.reconciliation_ledger.attempts(execution_record_id) == ()
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_strict_manual_resolution_requires_resolve_permission(
    tmp_path: Path,
) -> None:
    principals = {
        "operator": VerifiedPrincipal(
            issuer="gateway",
            subject="operator",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:probe", "reconciliation:resolve"}),
        ),
        "probe-only": VerifiedPrincipal(
            issuer="gateway",
            subject="probe-only",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:probe"}),
        ),
    }
    runtime, _provider_calls = _strict_control_plane_runtime(
        tmp_path / "manual-permission.db", principals
    )
    try:
        execution_record_id = await _strict_unknown_execution(runtime, actor="operator")
        manual = await runtime.areconcile(
            execution_record_id,
            identity_claims={"actor": "operator"},
        )
        assert manual.state is ReconciliationState.MANUAL_REVIEW
        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.aresolve_reconciliation(
                execution_record_id,
                expected_state=manual.state,
                expected_revision=manual.revision,
                new_state=ReconciliationState.CONFIRMED_SUCCEEDED,
                reason="operator review",
                evidence_kind="operator",
                evidence={"case_id": "case-1"},
                identity_claims={"actor": "probe-only"},
            )
        assert runtime.reconciliation_ledger is not None
        current = runtime.reconciliation_ledger.current(execution_record_id)
        assert (current.state, current.revision) == (manual.state, manual.revision)
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_atomically_prepares_recovery_descriptor_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "runtime-atomic-prepare.db"
    runtime = _runtime(path)
    ledger = runtime.reconciliation_ledger
    assert isinstance(ledger, SQLiteReconciliationLedger)
    legacy_prepare_called = False

    def fail_legacy_prepare(*_args: object, **_kwargs: object) -> None:
        nonlocal legacy_prepare_called
        legacy_prepare_called = True
        raise AssertionError("runtime must not use the split prepare path")

    monkeypatch.setattr(ledger, "prepare_action", fail_legacy_prepare)

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def charge() -> dict[str, bool]:
        with sqlite3.connect(path) as connection:
            prepared = connection.execute(
                "SELECT COUNT(*) FROM reconciliation_prepared_actions"
            ).fetchone()[0]
        assert prepared == 1
        return {"ok": True}

    try:
        result = await runtime.ainvoke(
            "charge", _governance=InvocationOptions(idempotency_key="request-1")
        )
        assert result == {"ok": True}
        assert not legacy_prepare_called
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_missing_provider_is_recorded_and_never_auto_dispatches(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missing-provider.db"
    dispatches = 0
    runtime = _runtime(path)

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def charge() -> None:
        nonlocal dispatches
        dispatches += 1
        raise TimeoutError("connection dropped after dispatch")

    options = InvocationOptions(idempotency_key="request-1")
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun("charge", _governance=options)
        execution_record_id = failed.value.context.metadata["execution_record_id"]
        head = await runtime.areconcile(execution_record_id)

        assert head.state is ReconciliationState.UNKNOWN
        assert dispatches == 1
        attempts = runtime.reconciliation_ledger.attempts(execution_record_id)  # type: ignore[union-attr]
        assert attempts[-1].payload["outcome"] == ReconciliationAttemptOutcome.UNAVAILABLE.value
        with pytest.raises(ToolExecutionError) as blocked:
            await runtime.ainvoke("charge", _governance=options)
        assert blocked.value.execution_record_id == execution_record_id
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_reconciliation_rejects_provider_drift_after_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "provider-drift.db"
    drifted_provider_calls = 0
    original_runtime = _runtime(path)

    async def original_provider(
        _context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        raise AssertionError("provider calls must remain explicit")

    @original_runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="payment-receipt-v1",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=original_provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    options = InvocationOptions(idempotency_key="request-1")
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await original_runtime.arun("charge", _governance=options)
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        unknown = original_runtime.reconciliation_ledger.current(execution_record_id)  # type: ignore[union-attr]
        assert unknown.action.reconciliation_provider_id == "payment-receipt-v1"
        assert unknown.action.reconciliation_protocol_version == "1"
    finally:
        await original_runtime.aclose()

    async def drifted_provider(
        _context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        nonlocal drifted_provider_calls
        drifted_provider_calls += 1
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "replacement-provider"},
            observed_at=datetime.now(timezone.utc),
        )

    restarted_runtime = _runtime(path)

    @restarted_runtime.tool(
        name="charge",
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="payment-receipt-v2",
            protocol_version="2",
            supported_evidence_kinds=("receipt",),
            provider=drifted_provider,
        ),
    )
    async def restarted_charge() -> None:
        raise AssertionError("the retained idempotency key must not redispatch")

    try:
        head = await restarted_runtime.areconcile(execution_record_id)
        assert head.state is ReconciliationState.UNKNOWN
        assert drifted_provider_calls == 0
        attempts = restarted_runtime.reconciliation_ledger.attempts(execution_record_id)  # type: ignore[union-attr]
        assert attempts[-1].payload["outcome"] == ReconciliationAttemptOutcome.UNAVAILABLE.value
    finally:
        await restarted_runtime.aclose()


@pytest.mark.asyncio
async def test_late_provider_result_is_discarded_and_provider_is_poisoned(
    tmp_path: Path,
) -> None:
    path = tmp_path / "late-provider.db"
    late_results: list[str] = []
    entered = asyncio.Event()

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        entered.set()
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            await asyncio.sleep(0.03)
            late_results.append(context.attempt_id)
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "late"},
            observed_at=context.deadline,
            resolved_result_available=True,
            resolved_result={"status": "paid"},
        )

    runtime = _runtime(
        path,
        limits=RuntimeLimits(
            reconciliation_provider_timeout_seconds=0.05,
            cancellation_grace_seconds=0.005,
        ),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        result_schema=_RESULT_SCHEMA,
        reconciliation_provider=ProviderDescriptor(
            provider_id="slow-receipt",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
        execution_record_id = failed.value.context.metadata["execution_record_id"]
        first = await runtime.areconcile(execution_record_id)
        assert first.state is ReconciliationState.UNKNOWN
        await asyncio.wait_for(entered.wait(), timeout=0.2)
        await asyncio.sleep(0.1)
        assert late_results
        assert runtime.reconciliation_ledger.current(  # type: ignore[union-attr]
            execution_record_id
        ).state is ReconciliationState.UNKNOWN

        second = await runtime.areconcile(execution_record_id)
        assert second.state is ReconciliationState.UNKNOWN
        attempts = runtime.reconciliation_ledger.attempts(execution_record_id)  # type: ignore[union-attr]
        assert attempts[-1].payload["outcome"] == ReconciliationAttemptOutcome.UNAVAILABLE.value
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_reconciliation_audit_records_digests_without_raw_probe_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reconciliation-audit.db"
    sink = InMemoryAuditSink()

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "sensitive-receipt-value"},
            observed_at=context.deadline,
        )

    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="payment-receipt",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("payment outcome is uncertain")

    options = InvocationOptions(idempotency_key="customer-visible-key")
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun("charge", _governance=options)
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        await runtime.areconcile(execution_record_id)

        events = [event for event in sink.events if event["stage"] == "reconciliation"]
        assert [event["event_type"] for event in events] == [
            "unknown_recorded",
            "transition_recorded",
        ]
        transition = events[-1]
        assert transition["provider"]["provider_id"] == "payment-receipt"
        assert transition["evidence_digest"] is not None
        serialized = str(events)
        assert "customer-visible-key" not in serialized
        assert "sensitive-receipt-value" not in serialized
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_manual_reconciliation_requires_sealed_identity_and_audits_digest(
    tmp_path: Path,
) -> None:
    class KeyProvider:
        def get_key(self, *, tenant: str, version: str) -> bytes:
            assert (tenant, version) == ("tenant-a", "key-v1")
            return b"k" * 32

    path = tmp_path / "manual-reconciliation.db"
    sink = JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32)
    profile = ProductionProfile(
        identity_digest_key_provider=KeyProvider(),
        identity_digest_key_version="key-v1",
        policy_version="policy-v1",
        policy_digest="a" * 64,
    )
    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        identity_provider=StaticIdentityProvider(
            VerifiedPrincipal(
                issuer="trusted-gateway",
                subject="operator@example.test",
                tenant="tenant-a",
                permissions=frozenset(
                    {"reconciliation:probe", "reconciliation:resolve"}
                ),
                source="test",
            )
        ),
        require_verified_identity=True,
        production_profile=profile,
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="probe",
            evidence={"case_id": "case-1"},
            observed_at=datetime.now(timezone.utc),
        )

    contract = ActionContract(
        contract_id="payments.charge",
        contract_version=1,
        tool_name="charge",
        execution_mode=ExecutionMode.IDEMPOTENT,
        parameters_schema={"type": "object", "additionalProperties": False},
        effect_class="payment.charge",
    )

    @runtime.tool(
        name="charge",
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=contract,
        reconciliation_provider=ProviderDescriptor(
            provider_id="payment-probe",
            protocol_version="1",
            supported_evidence_kinds=("probe",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("payment outcome is uncertain")

    options = InvocationOptions(idempotency_key="customer-visible-key")
    try:
        with pytest.raises(ProductionReadinessError):
            await runtime.aresolve_reconciliation(
                "not-a-real-record",
                expected_state=ReconciliationState.MANUAL_REVIEW,
                expected_revision=0,
                new_state=ReconciliationState.CONFIRMED_SUCCEEDED,
                reason="operator review",
                evidence_kind="operator",
                evidence={"case_id": "case-1"},
            )
        runtime.seal_production()
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun("charge", _governance=options)
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        manual = await runtime.areconcile(execution_record_id)
        assert manual.state is ReconciliationState.MANUAL_REVIEW

        resolved = await runtime.aresolve_reconciliation(
            execution_record_id,
            expected_state=manual.state,
            expected_revision=manual.revision,
            new_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            reason="operator reviewed provider evidence",
            evidence_kind="operator",
            evidence={"case_id": "operator-secret-case"},
        )
        assert resolved.state is ReconciliationState.CONFIRMED_SUCCEEDED
        events = [
            event
            for event in sink.read_verified()
            if event["stage"] == "reconciliation"
        ]
        manual_event = events[-1]
        assert manual_event["event_type"] == "manual_transition_recorded"
        assert manual_event["operator_identity_digest"] is not None
        assert "operator@example.test" not in str(manual_event)
        assert "operator-secret-case" not in str(manual_event)
    finally:
        await runtime.aclose()
