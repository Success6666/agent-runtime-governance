from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import sys
import textwrap
import threading
from collections.abc import Callable
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic, sleep

import pytest

import agent_runtime_governance._internal.runtime.durable_operations as durable_operations
import agent_runtime_governance.runtime as runtime_module
from agent_runtime_governance import (
    ActionContract,
    AuditMiddleware,
    ExecutionMode,
    ExecutionStatus,
    IdempotencyAlreadyAppliedError,
    InMemoryAuditSink,
    InvocationOptions,
    ProductionProfile,
    ProductionReadinessError,
    ProviderDescriptor,
    ReconciliationAttemptContext,
    ReconciliationAttemptOutcome,
    ReconciliationAuditDeliveryPendingError,
    ReconciliationConflictError,
    ReconciliationDisposition,
    ReconciliationFinding,
    ReconciliationHead,
    ReconciliationState,
    Runtime,
    RuntimeLimits,
    SQLiteAuditSink,
    SQLiteIdempotencyStore,
    SQLiteReconciliationLedger,
    StageTimeoutError,
    StaticIdentityProvider,
    ToolExecutionError,
    VerifiedPrincipal,
)
from agent_runtime_governance.reconciliation import (
    ReconciliationAuditEnvelope,
    UnknownAction,
    tenant_partition_digest,
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


def test_durable_operation_capability_rebuilds_on_store_or_ledger_reassignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "shared.db"
    calls = 0
    original = durable_operations._same_sqlite_database

    def counted(store, ledger) -> bool:
        nonlocal calls
        calls += 1
        return original(store, ledger)

    monkeypatch.setattr(durable_operations, "_same_sqlite_database", counted)
    runtime = _runtime(path)
    try:
        first_capability = runtime._durable_operation_capability
        assert runtime._supports_atomic_reconciliation_preparation() is True
        assert runtime._supports_atomic_reconciliation_preparation() is True
        assert calls == 1

        runtime.reconciliation_ledger = SQLiteReconciliationLedger(
            tmp_path / "separate.db"
        )

        assert runtime._durable_operation_capability is not first_capability
        assert runtime._supports_atomic_reconciliation_preparation() is False
        assert calls == 2
        assert "SQLiteIdempotencyStore" not in runtime_module.__dict__
        assert "SQLiteReconciliationLedger" not in runtime_module.__dict__
    finally:
        runtime.close()


async def _wait_until(predicate: Callable[[], bool], *, timeout: float = 1.0) -> None:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition was not reached before the timeout")


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


@pytest.mark.asyncio
async def test_reconciliation_without_result_prevents_redispatch(tmp_path: Path) -> None:
    path = tmp_path / "runtime-reconciliation-no-result.db"
    dispatches = 0

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    runtime = _runtime(path)

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
        nonlocal dispatches
        dispatches += 1
        raise TimeoutError("charge may have reached the payment provider")

    options = InvocationOptions(idempotency_key="customer-visible-key")
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun("charge", _governance=options)
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        head = await runtime.areconcile(execution_record_id)
        assert head.state is ReconciliationState.CONFIRMED_SUCCEEDED
        assert head.disposition is ReconciliationDisposition.APPLIED_NO_RESULT

        with pytest.raises(ToolExecutionError) as replayed:
            await runtime.arun("charge", _governance=options)
        assert isinstance(replayed.value.cause, IdempotencyAlreadyAppliedError)
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
                SQLiteAuditSink(path.with_suffix(".audit.db"), sign_key=b"a" * 32),
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
async def test_strict_global_audit_recovery_requires_its_own_permission(
    tmp_path: Path,
) -> None:
    principals = {
        "probe": VerifiedPrincipal(
            issuer="gateway",
            subject="probe-operator",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:probe"}),
        ),
        "audit-worker": VerifiedPrincipal(
            issuer="gateway",
            subject="audit-worker",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:audit:drain"}),
        ),
    }
    runtime, _provider_calls = _strict_control_plane_runtime(
        tmp_path / "strict-audit-drain.db", principals
    )
    try:
        await _strict_unknown_execution(runtime, actor="probe")
        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.adrain_reconciliation_audit_outbox(
                identity_claims={"actor": "probe"}
            )
        delivered = await runtime.adrain_reconciliation_audit_outbox(
            identity_claims={"actor": "audit-worker"}
        )
        assert delivered == 0
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_verified_identity_without_profile_secures_reconciliation_control_plane(
    tmp_path: Path,
) -> None:
    class ClaimsIdentityProvider:
        def __init__(self, principals: dict[str, VerifiedPrincipal]) -> None:
            self._principals = principals

        def verify(self, claims: dict[str, object] | None = None) -> VerifiedPrincipal:
            if claims is None or not isinstance(claims.get("actor"), str):
                raise ValueError("identity claims are required")
            return self._principals[claims["actor"]]

    principals = {
        "tenant-a": VerifiedPrincipal(
            issuer="gateway",
            subject="tenant-a-operator",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:probe"}),
        ),
        "unprivileged": VerifiedPrincipal(
            issuer="gateway",
            subject="unprivileged",
            tenant="tenant-a",
        ),
        "tenant-b": VerifiedPrincipal(
            issuer="gateway",
            subject="tenant-b-operator",
            tenant="tenant-b",
            permissions=frozenset({"reconciliation:probe"}),
        ),
        "audit-worker": VerifiedPrincipal(
            issuer="gateway",
            subject="audit-worker",
            tenant="tenant-a",
            permissions=frozenset({"reconciliation:audit:drain"}),
        ),
    }
    path = tmp_path / "verified-identity-without-profile.db"
    provider_calls: list[str] = []
    runtime = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        identity_provider=ClaimsIdentityProvider(principals),
        require_verified_identity=True,
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        provider_calls.append(context.action.execution_record_id)
        return ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="verified-identity-provider",
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
                "charge",
                _governance=InvocationOptions(
                    idempotency_key="request-1",
                    identity_claims={"actor": "tenant-a"},
                ),
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.areconcile(execution_record_id)
        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.areconcile(
                execution_record_id,
                identity_claims={"actor": "unprivileged"},
            )
        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.areconcile(
                execution_record_id,
                identity_claims={"actor": "tenant-b"},
            )
        assert provider_calls == []

        with pytest.raises(PermissionError, match="authorization denied"):
            await runtime.adrain_reconciliation_audit_outbox(
                identity_claims={"actor": "tenant-a"}
            )
        delivered = await runtime.adrain_reconciliation_audit_outbox(
            identity_claims={"actor": "audit-worker"}
        )
        assert delivered == 0

        head = await runtime.areconcile(
            execution_record_id,
            identity_claims={"actor": "tenant-a"},
        )
        assert head.state is ReconciliationState.MANUAL_REVIEW
        assert provider_calls == [execution_record_id]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_reconciliation_control_plane_helpers_reject_closing_runtime() -> None:
    runtime = Runtime()
    try:
        with runtime._lifecycle_lock:
            runtime._closing = True

        with pytest.raises(RuntimeError, match="runtime is closed"):
            await runtime._adrain_reconciliation_audit_outbox(
                limit=1,
                identity_claims=None,
                deadline=None,
            )
        with pytest.raises(RuntimeError, match="runtime is closed"):
            await runtime._aresolve_reconciliation(
                "execution-1",
                expected_state=ReconciliationState.MANUAL_REVIEW,
                expected_revision=1,
                new_state=ReconciliationState.CONFIRMED_SUCCEEDED,
                reason="operator verification",
                evidence_kind="receipt",
                evidence={},
            )
    finally:
        with runtime._lifecycle_lock:
            runtime._closing = False
        await runtime.aclose()


@pytest.mark.asyncio
async def test_tenantless_unknown_action_is_not_recoverable_by_global_tenant(
    tmp_path: Path,
) -> None:
    path = tmp_path / "tenantless-unknown.db"
    provider_calls: list[str] = []
    producer = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        provider_calls.append(context.action.execution_record_id)
        return ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    def register_charge(runtime: Runtime) -> None:
        @runtime.tool(
            execution_mode=ExecutionMode.IDEMPOTENT,
            reconciliation_provider=ProviderDescriptor(
                provider_id="tenantless-provider",
                protocol_version="1",
                supported_evidence_kinds=("receipt",),
                provider=provider,
            ),
        )
        async def charge() -> None:
            raise TimeoutError("outcome is uncertain")

    register_charge(producer)
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await producer.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        assert producer.reconciliation_ledger is not None
        assert (
            producer.reconciliation_ledger.current(
                execution_record_id
            ).action.tenant_partition_digest
            is None
        )
    finally:
        await producer.aclose()

    recovery = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        identity_provider=StaticIdentityProvider(
            VerifiedPrincipal(
                issuer="gateway",
                subject="global-operator",
                tenant="global",
                permissions=frozenset({"reconciliation:probe"}),
            )
        ),
        require_verified_identity=True,
    )
    register_charge(recovery)
    try:
        with pytest.raises(PermissionError, match="authorization denied"):
            await recovery.areconcile(execution_record_id)
        assert provider_calls == []
    finally:
        await recovery.aclose()


def test_legacy_global_tenant_partition_is_fail_closed_without_binding_marker() -> None:
    action_fields = {
        "execution_record_id": "r" * 16,
        "action_digest": "a" * 64,
        "tool_name": "charge",
        "contract_id": "runtime.charge",
        "contract_version": 1,
        "idempotency_namespace_digest": "b" * 64,
        "tenant_partition_digest": tenant_partition_digest("global"),
        "uncertainty_reason": "outcome is uncertain",
        "attempted_at": datetime.now(timezone.utc),
    }
    principal = VerifiedPrincipal(
        issuer="gateway",
        subject="global-operator",
        tenant="global",
        permissions=frozenset({"reconciliation:probe"}),
    )

    with pytest.raises(PermissionError, match="authorization denied"):
        Runtime._assert_reconciliation_tenant_access(
            principal, UnknownAction(**action_fields)
        )

    Runtime._assert_reconciliation_tenant_access(
        principal,
        UnknownAction(
            **action_fields,
            metadata={"tenant_partition_bound": True},
        ),
    )


@pytest.mark.asyncio
async def test_close_rejects_pending_reconciliation_without_closing_runtime(
    tmp_path: Path,
) -> None:
    path = tmp_path / "close-pending-reconciliation.db"
    entered = asyncio.Event()
    release = asyncio.Event()
    runtime = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        entered.set()
        await release.wait()
        return ReconciliationFinding(
            proposed_state=ReconciliationState.MANUAL_REVIEW,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="close-pending-provider",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    async def inspect() -> str:
        return "ready"

    pending: asyncio.Task[ReconciliationHead] | None = None
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        pending = asyncio.create_task(runtime.areconcile(execution_record_id))
        await asyncio.wait_for(entered.wait(), timeout=1.0)

        with pytest.raises(RuntimeError, match="reconciliation work is pending"):
            runtime.close()
        assert await runtime.ainvoke("inspect") == "ready"

        release.set()
        assert (await pending).state is ReconciliationState.MANUAL_REVIEW
    finally:
        release.set()
        if pending is not None and not pending.done():
            await asyncio.gather(pending, return_exceptions=True)
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
        with closing(sqlite3.connect(path)) as connection:
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
async def test_expired_provider_budget_is_not_dispatched_after_attempt_start(
    tmp_path: Path,
) -> None:
    class DelayedStartLedger(SQLiteReconciliationLedger):
        def start_attempt(self, *args: object, **kwargs: object) -> object:
            sleep(0.05)
            return super().start_attempt(*args, **kwargs)

    path = tmp_path / "expired-provider-budget.db"
    provider_calls: list[str] = []
    release = asyncio.Event()
    ledger = DelayedStartLedger(path)
    runtime = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=ledger,
        limits=RuntimeLimits(reconciliation_provider_timeout_seconds=0.01),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        provider_calls.append(context.attempt_id)
        await release.wait()
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "late"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="expired-provider-budget",
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

        head = await runtime.areconcile(execution_record_id)
        assert head.state is ReconciliationState.UNKNOWN
        await asyncio.sleep(0)
        assert provider_calls == []
        assert not runtime._reconciliation_tasks
        attempts = ledger.attempts(execution_record_id)
        assert len(attempts) == 2
        assert attempts[0].payload["attempt_id"] == attempts[1].payload["attempt_id"]
        assert attempts[-1].payload["outcome"] == ReconciliationAttemptOutcome.TIMEOUT.value
    finally:
        release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_late_provider_result_is_discarded_and_provider_is_poisoned(
    tmp_path: Path,
) -> None:
    path = tmp_path / "late-provider.db"
    late_results: list[str] = []
    entered = asyncio.Event()
    late_result_observed = asyncio.Event()

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        entered.set()
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            await asyncio.sleep(0.03)
            late_results.append(context.attempt_id)
            late_result_observed.set()
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
            reconciliation_provider_timeout_seconds=0.25,
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
        await asyncio.wait_for(late_result_observed.wait(), timeout=3.0)
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
async def test_aclose_waits_for_a_cancellation_ignoring_provider(
    tmp_path: Path,
) -> None:
    """Shutdown cannot release runtime executors while a provider still runs."""

    path = tmp_path / "close-draining-provider.db"
    entered = asyncio.Event()
    release = asyncio.Event()
    runtime = _runtime(
        path,
        limits=RuntimeLimits(
            reconciliation_provider_timeout_seconds=0.25,
            cancellation_grace_seconds=0.005,
        ),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        entered.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "late"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="close-draining-provider",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    closing: asyncio.Task[None] | None = None
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        reconciled = await runtime.areconcile(execution_record_id)
        assert reconciled.state is ReconciliationState.UNKNOWN
        await asyncio.wait_for(entered.wait(), timeout=1)
        assert any(not task.done() for task in runtime._reconciliation_tasks)

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
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
            "attempt_started",
            "attempt_finished",
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
async def test_terminal_reconciliation_audit_is_replayed_without_provider_rerun(
    tmp_path: Path,
) -> None:
    class FailTransitionOnceSink:
        def __init__(self) -> None:
            self.events: list[dict[str, object]] = []
            self.failed = False

        def write(self, event: dict[str, object]) -> None:
            if (
                event.get("stage") == "reconciliation"
                and event.get("event_type") == "transition_recorded"
                and not self.failed
            ):
                self.failed = True
                raise OSError("temporary audit sink outage")
            self.events.append(dict(event))

    path = tmp_path / "terminal-audit-replay.db"
    sink = FailTransitionOnceSink()
    provider_calls = 0

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        nonlocal provider_calls
        provider_calls += 1
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],  # type: ignore[arg-type]
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

    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun(
                "charge",
                _governance=InvocationOptions(idempotency_key="request-1"),
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        with pytest.raises(ReconciliationAuditDeliveryPendingError) as pending:
            await runtime.areconcile(execution_record_id)
        assert pending.value.execution_record_id == execution_record_id
        assert provider_calls == 1
        assert runtime.reconciliation_ledger is not None
        assert (
            runtime.reconciliation_ledger.current(execution_record_id).state
            is ReconciliationState.CONFIRMED_SUCCEEDED
        )
        queued = runtime.reconciliation_ledger.pending_audit_events(
            execution_record_id=execution_record_id
        )
        assert [item.event_type for item in queued] == ["transition_recorded"]

        recovered = await runtime.areconcile(execution_record_id)
        assert recovered.state is ReconciliationState.CONFIRMED_SUCCEEDED
        assert provider_calls == 1
        events = [
            event
            for event in sink.events
            if event.get("stage") == "reconciliation"
        ]
        assert [event["event_type"] for event in events] == [
            "unknown_recorded",
            "attempt_started",
            "attempt_finished",
            "transition_recorded",
        ]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_sqlite_audit_source_id_prevents_duplicate_after_ack_failure(
    tmp_path: Path,
) -> None:
    class FailTransitionAcknowledgementLedger(SQLiteReconciliationLedger):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self._failed = False

        def mark_audit_event_delivered(self, outbox_id: str) -> None:
            pending = self.pending_audit_events(limit=1_000)
            event = next(item for item in pending if item.outbox_id == outbox_id)
            if event.event_type == "transition_recorded" and not self._failed:
                self._failed = True
                raise sqlite3.OperationalError("simulated acknowledgement interruption")
            super().mark_audit_event_delivered(outbox_id)

    path = tmp_path / "sqlite-audit-retry.db"
    ledger = FailTransitionAcknowledgementLedger(path)
    sink = SQLiteAuditSink(tmp_path / "audit.db", sign_key=b"a" * 32)
    provider_calls = 0

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        nonlocal provider_calls
        provider_calls += 1
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=ledger,
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

    try:
        with pytest.raises(ToolExecutionError) as failed:
            await runtime.arun(
                "charge",
                _governance=InvocationOptions(idempotency_key="request-1"),
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        with pytest.raises(ReconciliationAuditDeliveryPendingError):
            await runtime.areconcile(execution_record_id)
        recovered = await runtime.areconcile(execution_record_id)
        assert recovered.state is ReconciliationState.CONFIRMED_SUCCEEDED
        assert provider_calls == 1
        events = [
            event
            for event in sink.read_verified()
            if event.get("stage") == "reconciliation"
        ]
        assert [event["event_type"] for event in events] == [
            "unknown_recorded",
            "attempt_started",
            "attempt_finished",
            "transition_recorded",
        ]
        assert len({event["reconciliation_audit_id"] for event in events}) == 4
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
    sink = SQLiteAuditSink(tmp_path / "audit.db", sign_key=b"a" * 32)
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


@pytest.mark.asyncio
async def test_caller_deadline_expiry_still_finishes_started_attempt(
    tmp_path: Path,
) -> None:
    path = tmp_path / "deadline-finalization.db"
    runtime = _runtime(
        path,
        limits=RuntimeLimits(
            reconciliation_provider_timeout_seconds=1.0,
            reconciliation_finalization_timeout_seconds=0.1,
        ),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            # Let the original request deadline elapse before the provider
            # acknowledges cancellation. The persisted finish must still use
            # its independent finalization budget.
            await asyncio.sleep(0.05)
            raise

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="deadline-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        with pytest.raises(StageTimeoutError):
            await runtime.areconcile(
                execution_record_id,
                deadline=datetime.now(timezone.utc) + timedelta(seconds=0.25),
            )

        assert runtime.reconciliation_ledger is not None
        attempts = runtime.reconciliation_ledger.attempts(execution_record_id)
        assert len(attempts) == 2
        assert attempts[0].payload["attempt_id"] == attempts[1].payload["attempt_id"]
        assert (
            attempts[1].payload["outcome"]
            == ReconciliationAttemptOutcome.TIMEOUT.value
        )
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_cancellation_during_finish_keeps_finalization_running(
    tmp_path: Path,
) -> None:
    class BlockingFinishLedger(SQLiteReconciliationLedger):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.entered = threading.Event()
            self.release = threading.Event()
            self.finished = threading.Event()

        def finish_attempt(self, *args: object, **kwargs: object) -> object:
            self.entered.set()
            if not self.release.wait(timeout=2):
                raise RuntimeError("test finalizer was not released")
            result = super().finish_attempt(*args, **kwargs)
            self.finished.set()
            return result

    path = tmp_path / "cancel-finalization.db"
    ledger = BlockingFinishLedger(path)
    runtime = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=ledger,
        limits=RuntimeLimits(reconciliation_finalization_timeout_seconds=1.0),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="cancel-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        reconciliation = asyncio.create_task(runtime.areconcile(execution_record_id))
        assert await asyncio.to_thread(ledger.entered.wait, 1.0)
        reconciliation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await reconciliation

        ledger.release.set()
        assert await asyncio.to_thread(ledger.finished.wait, 1.0)
        attempts = ledger.attempts(execution_record_id)
        assert len(attempts) == 2
        assert attempts[0].payload["attempt_id"] == attempts[1].payload["attempt_id"]
        assert attempts[1].payload["outcome"] == ReconciliationAttemptOutcome.SUCCESS.value
    finally:
        ledger.release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_finalization_timeout_poison_reconciliation_fail_closed(
    tmp_path: Path,
) -> None:
    class BlockingFinishLedger(SQLiteReconciliationLedger):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.entered = threading.Event()
            self.release = threading.Event()
            self.finished = threading.Event()

        def finish_attempt(self, *args: object, **kwargs: object) -> object:
            self.entered.set()
            if not self.release.wait(timeout=2):
                raise RuntimeError("test finalizer was not released")
            result = super().finish_attempt(*args, **kwargs)
            self.finished.set()
            return result

    path = tmp_path / "timed-out-finalization.db"
    ledger = BlockingFinishLedger(path)
    runtime = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=ledger,
        limits=RuntimeLimits(
            reconciliation_operation_timeout_seconds=1.0,
            reconciliation_finalization_timeout_seconds=0.01,
        ),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="timeout-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        with pytest.raises(StageTimeoutError, match="reconciliation finish attempt"):
            await runtime.areconcile(execution_record_id)
        assert ledger.entered.is_set()
        assert len(ledger.attempts(execution_record_id)) == 1
        with pytest.raises(ReconciliationConflictError, match="disabled"):
            await runtime.areconcile(execution_record_id)

        ledger.release.set()
        assert await asyncio.to_thread(ledger.finished.wait, 1.0)
    finally:
        ledger.release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_finalization_storage_failure_poison_reconciliation(
    tmp_path: Path,
) -> None:
    class FailingFinishLedger(SQLiteReconciliationLedger):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.fail_once = True

        def finish_attempt(self, *args: object, **kwargs: object) -> object:
            if self.fail_once:
                self.fail_once = False
                raise sqlite3.OperationalError("simulated finalization storage failure")
            return super().finish_attempt(*args, **kwargs)

    path = tmp_path / "failing-finalization.db"
    ledger = FailingFinishLedger(path)
    runtime = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=ledger,
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="failing-finalizer-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        with pytest.raises(sqlite3.OperationalError, match="simulated finalization"):
            await runtime.areconcile(execution_record_id)
        await _wait_until(lambda: not runtime.reconciliation_ledger_healthy)
        with pytest.raises(ReconciliationConflictError, match="disabled"):
            await runtime.areconcile(execution_record_id)
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_finalization_conflict_without_durable_progress_poisons_reconciliation(
    tmp_path: Path,
) -> None:
    class ConflictingFinishLedger(SQLiteReconciliationLedger):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.conflict_once = True

        def finish_attempt(self, *args: object, **kwargs: object) -> object:
            if self.conflict_once:
                self.conflict_once = False
                raise ReconciliationConflictError("simulated concurrent resolution")
            return super().finish_attempt(*args, **kwargs)

    path = tmp_path / "conflicting-finalization.db"
    ledger = ConflictingFinishLedger(path)
    runtime = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=ledger,
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="conflict-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        with pytest.raises(ReconciliationConflictError, match="simulated concurrent"):
            await runtime.areconcile(execution_record_id)
        await _wait_until(lambda: not runtime.reconciliation_ledger_healthy)
        assert len(ledger.attempts(execution_record_id)) == 1
        with pytest.raises(ReconciliationConflictError, match="disabled"):
            await runtime.areconcile(execution_record_id)
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_restart_quarantines_an_expired_unfinished_provider_attempt(
    tmp_path: Path,
) -> None:
    class FailingFinishLedger(SQLiteReconciliationLedger):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self.fail_once = True

        def finish_attempt(self, *args: object, **kwargs: object) -> object:
            if self.fail_once:
                self.fail_once = False
                raise sqlite3.OperationalError("simulated finalization storage failure")
            return super().finish_attempt(*args, **kwargs)

    path = tmp_path / "restart-unfinished-attempt.db"
    calls: list[str] = []
    limits = RuntimeLimits(reconciliation_provider_timeout_seconds=0.25)
    first = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=FailingFinishLedger(path),
        limits=limits,
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        calls.append(context.attempt_id)
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    descriptor = ProviderDescriptor(
        provider_id="restart-recovery-provider",
        protocol_version="1",
        supported_evidence_kinds=("receipt",),
        provider=provider,
    )

    @first.tool(
        name="charge",
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=descriptor,
    )
    async def charge_first() -> None:
        raise TimeoutError("outcome is uncertain")

    recovery: Runtime | None = None
    try:
        with pytest.raises(ToolExecutionError) as failed:
            await first.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        with pytest.raises(sqlite3.OperationalError, match="simulated finalization"):
            await first.areconcile(execution_record_id)
        assert len(calls) == 1
    finally:
        await first.aclose()

    await asyncio.sleep(0.3)
    recovery = Runtime(
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        limits=limits,
    )

    @recovery.tool(
        name="charge",
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=descriptor,
    )
    async def charge_recovery() -> None:
        raise TimeoutError("outcome is uncertain")

    try:
        head = await recovery.areconcile(execution_record_id)
        assert head.state is ReconciliationState.MANUAL_REVIEW
        assert len(calls) == 1
        attempts = recovery.reconciliation_ledger.attempts(execution_record_id)  # type: ignore[union-attr]
        assert [record.kind.value for record in attempts] == [
            "ATTEMPT_STARTED",
            "ATTEMPT_FINISHED",
        ]
        assert (
            attempts[1].payload["outcome"]
            == ReconciliationAttemptOutcome.RECOVERY_REQUIRED.value
        )
    finally:
        await recovery.aclose()


@pytest.mark.asyncio
async def test_reconciliation_outbox_acknowledges_after_async_idempotent_write() -> None:
    class AsyncIdempotentSink:
        reconciliation_delivery_idempotent = True

        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.completed = asyncio.Event()

        async def write_idempotent(
            self, _source_event_id: str, _event: object
        ) -> None:
            self.started.set()
            await self.release.wait()
            self.completed.set()

        async def write(self, event: object) -> None:
            await self.write_idempotent("non-reconciliation", event)

    class RecordingLedger:
        def __init__(self, sink: AsyncIdempotentSink) -> None:
            self._sink = sink
            self.delivered = False
            self.envelope = ReconciliationAuditEnvelope(
                outbox_id="outbox-1",
                execution_record_id="execution-1",
                revision=0,
                event_type="transition_recorded",
                event={"event": "recorded"},
                created_at=datetime.now(timezone.utc),
            )

        def pending_audit_events(
            self,
            *,
            execution_record_id: str | None = None,
            limit: int = 128,
        ) -> tuple[ReconciliationAuditEnvelope, ...]:
            del execution_record_id, limit
            return () if self.delivered else (self.envelope,)

        def mark_audit_event_delivered(self, outbox_id: str) -> None:
            assert outbox_id == self.envelope.outbox_id
            assert self._sink.completed.is_set()
            self.delivered = True

    sink = AsyncIdempotentSink()
    ledger = RecordingLedger(sink)
    runtime = Runtime([AuditMiddleware(sink, fail_closed=True)])  # type: ignore[arg-type]
    try:
        drain = asyncio.create_task(runtime._drain_reconciliation_audit_outbox(ledger))
        await asyncio.wait_for(sink.started.wait(), timeout=1)
        assert not ledger.delivered
        assert not drain.done()

        sink.release.set()

        assert await drain == 1
        assert ledger.delivered
    finally:
        sink.release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_cancelling_outbox_delivery_keeps_reconciliation_recoverable(
    tmp_path: Path,
) -> None:
    class BlockingIdempotentSink:
        reconciliation_delivery_idempotent = True

        def __init__(self) -> None:
            self.block = False
            self.entered = threading.Event()
            self.release = threading.Event()
            self.completed = threading.Event()
            self.events: dict[str, dict[str, object]] = {}

        def write_idempotent(self, source_event_id: str, event: object) -> None:
            if self.block:
                self.entered.set()
                if not self.release.wait(timeout=2):
                    raise RuntimeError("test audit delivery was not released")
                self.completed.set()
            assert isinstance(event, dict)
            self.events.setdefault(source_event_id, dict(event))

        def write(self, event: object) -> None:
            self.write_idempotent("non-reconciliation", event)

    path = tmp_path / "cancelled-outbox-delivery.db"
    sink = BlockingIdempotentSink()
    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],  # type: ignore[arg-type]
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="audit-cancellation-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        sink.completed.clear()
        sink.block = True
        reconciliation = asyncio.create_task(runtime.areconcile(execution_record_id))
        assert await asyncio.to_thread(sink.entered.wait, 1.0)
        reconciliation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await reconciliation

        sink.block = False
        sink.release.set()
        assert await asyncio.to_thread(sink.completed.wait, 1.0)
        await _wait_until(lambda: runtime.reconciliation_ledger_healthy)

        recovered = await runtime.areconcile(execution_record_id)
        assert recovered.state is ReconciliationState.CONFIRMED_SUCCEEDED
        assert runtime.reconciliation_ledger_healthy
    finally:
        sink.block = False
        sink.release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_timed_out_outbox_delivery_recovers_without_poisoning_ledger(
    tmp_path: Path,
) -> None:
    class BlockingIdempotentSink:
        reconciliation_delivery_idempotent = True

        def __init__(self) -> None:
            self.block = False
            self.entered = threading.Event()
            self.release = threading.Event()
            self.completed = threading.Event()
            self.events: dict[str, dict[str, object]] = {}

        def write_idempotent(self, source_event_id: str, event: object) -> None:
            if self.block:
                self.entered.set()
                if not self.release.wait(timeout=2):
                    raise RuntimeError("test audit delivery was not released")
            assert isinstance(event, dict)
            self.events.setdefault(source_event_id, dict(event))
            self.completed.set()

        def write(self, event: object) -> None:
            self.write_idempotent("non-reconciliation", event)

    path = tmp_path / "timed-out-outbox-delivery.db"
    sink = BlockingIdempotentSink()
    provider_calls = 0
    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],  # type: ignore[arg-type]
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        limits=RuntimeLimits(
            reconciliation_audit_delivery_timeout_seconds=0.1,
            max_reconciliation_audit_delivery_in_flight=1,
        ),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        nonlocal provider_calls
        provider_calls += 1
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="timed-out-audit-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None

        await runtime.adrain_reconciliation_audit_outbox(limit=16)
        sink.completed.clear()
        sink.block = True
        with pytest.raises(ReconciliationAuditDeliveryPendingError) as pending:
            await runtime.areconcile(
                execution_record_id,
                deadline=datetime.now(timezone.utc) + timedelta(seconds=5),
            )
        assert pending.value.execution_record_id == execution_record_id
        assert await asyncio.to_thread(sink.entered.wait, 1.0)
        assert runtime.reconciliation_ledger_healthy
        assert provider_calls == 1

        sink.block = False
        sink.release.set()
        assert await asyncio.to_thread(sink.completed.wait, 1.0)
        delivered = await runtime.adrain_reconciliation_audit_outbox(limit=16)
        assert delivered == 3
        assert runtime.reconciliation_ledger_healthy
        assert provider_calls == 1
        reconciliation_events = [
            event
            for event in sink.events.values()
            if event.get("stage") == "reconciliation"
        ]
        assert len(reconciliation_events) == 4
    finally:
        sink.block = False
        sink.release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_does_not_wait_for_a_timed_out_audit_sink_thread(
    tmp_path: Path,
) -> None:
    class BlockingIdempotentSink:
        reconciliation_delivery_idempotent = True

        def __init__(self) -> None:
            self.entered = threading.Event()
            self.release = threading.Event()
            self.completed = threading.Event()

        def write_idempotent(self, _source_event_id: str, _event: object) -> None:
            self.entered.set()
            self.release.wait()
            self.completed.set()

        def write(self, event: object) -> None:
            self.write_idempotent("non-reconciliation", event)

    path = tmp_path / "aclose-timed-out-audit-sink.db"
    producer = _runtime(path)

    @producer.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    try:
        with pytest.raises(ToolExecutionError):
            await producer.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
    finally:
        await producer.aclose()

    sink = BlockingIdempotentSink()
    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        limits=RuntimeLimits(reconciliation_audit_delivery_timeout_seconds=0.03),
    )
    close_task: asyncio.Task[None] | None = None
    try:
        with pytest.raises(ReconciliationAuditDeliveryPendingError):
            await runtime.adrain_reconciliation_audit_outbox(limit=1)
        assert await asyncio.to_thread(sink.entered.wait, 1.0)
        assert not sink.completed.is_set()

        close_task = asyncio.create_task(runtime.aclose())
        await asyncio.wait_for(asyncio.shield(close_task), timeout=0.5)
    finally:
        sink.release.set()
        assert await asyncio.to_thread(sink.completed.wait, 1.0)
        if close_task is None:
            await runtime.aclose()
        else:
            await asyncio.wait_for(close_task, timeout=2.0)


def test_blocked_reconciliation_audit_sink_cannot_hold_python_process_open() -> None:
    """A durable, idempotent outbox makes abandoned daemon delivery safe."""

    script = textwrap.dedent(
        """
        import asyncio
        import tempfile
        import threading
        from pathlib import Path

        from agent_runtime_governance import (
            AuditMiddleware,
            ExecutionMode,
            InvocationOptions,
            ReconciliationAuditDeliveryPendingError,
            Runtime,
            RuntimeLimits,
            SQLiteIdempotencyStore,
            SQLiteReconciliationLedger,
            ToolExecutionError,
        )


        class BlockingSink:
            reconciliation_delivery_idempotent = True

            def write_idempotent(self, _source_event_id, _event):
                threading.Event().wait()

            def write(self, event):
                self.write_idempotent("non-reconciliation", event)


        async def main():
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "runtime.db"
                producer = Runtime(
                    idempotency_store=SQLiteIdempotencyStore(path),
                    reconciliation_ledger=SQLiteReconciliationLedger(path),
                )

                @producer.tool(execution_mode=ExecutionMode.IDEMPOTENT)
                async def charge():
                    raise TimeoutError("outcome is uncertain")

                try:
                    try:
                        await producer.arun(
                            "charge",
                            _governance=InvocationOptions(idempotency_key="request-1"),
                        )
                    except ToolExecutionError:
                        pass
                finally:
                    await producer.aclose()

                runtime = Runtime(
                    [AuditMiddleware(BlockingSink(), fail_closed=True)],
                    idempotency_store=SQLiteIdempotencyStore(path),
                    reconciliation_ledger=SQLiteReconciliationLedger(path),
                    limits=RuntimeLimits(
                        reconciliation_audit_delivery_timeout_seconds=0.1
                    ),
                )
                try:
                    try:
                        await runtime.adrain_reconciliation_audit_outbox(limit=1)
                    except ReconciliationAuditDeliveryPendingError:
                        pass
                finally:
                    await runtime.aclose()


        asyncio.run(main())
        print("runtime-closed")
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "runtime-closed"


@pytest.mark.asyncio
async def test_global_audit_recovery_honors_its_caller_deadline(
    tmp_path: Path,
) -> None:
    class BlockingIdempotentSink:
        reconciliation_delivery_idempotent = True

        def __init__(self) -> None:
            self.entered = threading.Event()
            self.release = threading.Event()
            self.completed = threading.Event()

        def write_idempotent(self, _source_event_id: str, _event: object) -> None:
            self.entered.set()
            if not self.release.wait(timeout=1.0):
                raise RuntimeError("test audit sink was not released")
            self.completed.set()

        def write(self, event: object) -> None:
            self.write_idempotent("non-reconciliation", event)

    path = tmp_path / "global-audit-recovery-deadline.db"
    producer = _runtime(path)

    @producer.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    try:
        with pytest.raises(ToolExecutionError):
            await producer.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
    finally:
        await producer.aclose()

    sink = BlockingIdempotentSink()
    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        limits=RuntimeLimits(
            reconciliation_audit_delivery_timeout_seconds=1.0,
            reconciliation_operation_timeout_seconds=1.0,
        ),
    )
    try:
        deadline = datetime.now(timezone.utc) + timedelta(seconds=0.5)
        with pytest.raises(StageTimeoutError, match="reconciliation audit delivery"):
            await runtime.adrain_reconciliation_audit_outbox(
                limit=1, deadline=deadline
            )
        assert await asyncio.to_thread(sink.entered.wait, 1.0)

        sink.release.set()
        assert await asyncio.to_thread(sink.completed.wait, 1.0)
        assert await runtime.adrain_reconciliation_audit_outbox(limit=1) == 1
    finally:
        sink.release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_public_reconciliation_deadline_rejects_naive_datetimes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "naive-reconciliation-deadline.db"
    producer = _runtime(path)

    @producer.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    try:
        with pytest.raises(ToolExecutionError):
            await producer.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
    finally:
        await producer.aclose()

    runtime = Runtime(
        [AuditMiddleware(InMemoryAuditSink())],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )
    try:
        with pytest.raises(ValueError, match="deadline must be timezone-aware"):
            await runtime.adrain_reconciliation_audit_outbox(
                deadline=datetime.now()
            )
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_reconciliation_audit_delivery_honors_its_caller_deadline(
    tmp_path: Path,
) -> None:
    class BlockingIdempotentSink:
        reconciliation_delivery_idempotent = True

        def __init__(self) -> None:
            self.block = False
            self.entered = threading.Event()
            self.release = threading.Event()
            self.completed = threading.Event()
            self.events: dict[str, dict[str, object]] = {}

        def write_idempotent(self, source_event_id: str, event: object) -> None:
            if self.block:
                self.entered.set()
                if not self.release.wait(timeout=2):
                    raise RuntimeError("test audit sink was not released")
                self.completed.set()
            assert isinstance(event, dict)
            self.events.setdefault(source_event_id, dict(event))

        def write(self, event: object) -> None:
            self.write_idempotent("non-reconciliation", event)

    path = tmp_path / "reconciliation-audit-deadline.db"
    sink = BlockingIdempotentSink()
    runtime = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
        limits=RuntimeLimits(reconciliation_audit_delivery_timeout_seconds=1.0),
    )

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @runtime.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="audit-deadline-provider",
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
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        sink.block = True

        deadline = datetime.now(timezone.utc) + timedelta(seconds=1.0)
        with pytest.raises(StageTimeoutError, match="reconciliation audit delivery"):
            await runtime.areconcile(execution_record_id, deadline=deadline)
        assert await asyncio.to_thread(sink.entered.wait, 1.0)

        head = runtime.reconciliation_ledger.current(execution_record_id)  # type: ignore[union-attr]
        assert head.state is ReconciliationState.CONFIRMED_SUCCEEDED
        sink.block = False
        sink.release.set()
        assert await asyncio.to_thread(sink.completed.wait, 1.0)
        assert await runtime.adrain_reconciliation_audit_outbox(limit=16) == 3
    finally:
        sink.block = False
        sink.release.set()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_recovery_runtime_drains_persisted_outbox_after_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "outbox-recovery-restart.db"
    producer = _runtime(path)

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @producer.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="restart-recovery-provider",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    try:
        with pytest.raises(ToolExecutionError) as failed:
            await producer.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        assert (
            await producer.areconcile(execution_record_id)
        ).state is ReconciliationState.CONFIRMED_SUCCEEDED
    finally:
        await producer.aclose()

    sink = SQLiteAuditSink(tmp_path / "recovered-audit.db", sign_key=b"a" * 32)
    recovery = Runtime(
        [AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )
    try:
        assert await recovery.adrain_reconciliation_audit_outbox(limit=2) == 2
        assert await recovery.adrain_reconciliation_audit_outbox(limit=16) == 2
        events = [
            event
            for event in sink.read_verified()
            if event.get("stage") == "reconciliation"
        ]
        assert [event["event_type"] for event in events] == [
            "unknown_recorded",
            "attempt_started",
            "attempt_finished",
            "transition_recorded",
        ]
    finally:
        await recovery.aclose()


@pytest.mark.asyncio
async def test_concurrent_recovery_workers_deduplicate_outbox_delivery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "outbox-concurrent-recovery.db"
    producer = _runtime(path)

    async def provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="receipt",
            evidence={"receipt_id": "receipt-1"},
            observed_at=context.deadline,
        )

    @producer.tool(
        execution_mode=ExecutionMode.IDEMPOTENT,
        reconciliation_provider=ProviderDescriptor(
            provider_id="concurrent-recovery-provider",
            protocol_version="1",
            supported_evidence_kinds=("receipt",),
            provider=provider,
        ),
    )
    async def charge() -> None:
        raise TimeoutError("outcome is uncertain")

    try:
        with pytest.raises(ToolExecutionError) as failed:
            await producer.arun(
                "charge", _governance=InvocationOptions(idempotency_key="request-1")
            )
        execution_record_id = failed.value.execution_record_id
        assert execution_record_id is not None
        await producer.areconcile(execution_record_id)
    finally:
        await producer.aclose()

    audit_path = tmp_path / "concurrent-recovered-audit.db"
    first = Runtime(
        [AuditMiddleware(SQLiteAuditSink(audit_path, sign_key=b"a" * 32), fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )
    second = Runtime(
        [AuditMiddleware(SQLiteAuditSink(audit_path, sign_key=b"a" * 32), fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(path),
        reconciliation_ledger=SQLiteReconciliationLedger(path),
    )
    try:
        await asyncio.gather(
            first.adrain_reconciliation_audit_outbox(limit=16),
            second.adrain_reconciliation_audit_outbox(limit=16),
        )
        sink = SQLiteAuditSink(audit_path, sign_key=b"a" * 32)
        events = [
            event
            for event in sink.read_verified()
            if event.get("stage") == "reconciliation"
        ]
        assert [event["event_type"] for event in events] == [
            "unknown_recorded",
            "attempt_started",
            "attempt_finished",
            "transition_recorded",
        ]
        assert len({event["reconciliation_audit_id"] for event in events}) == 4
    finally:
        await first.aclose()
        await second.aclose()


@pytest.mark.asyncio
async def test_reconciliation_timeout_registers_one_deferred_release_per_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CallbackTarget:
        def __init__(self) -> None:
            self._callbacks: list[Callable[[object], object]] = []
            self._done = False

        def add_done_callback(self, callback: Callable[[object], object]) -> None:
            self._callbacks.append(callback)

        def done(self) -> bool:
            return self._done

        def result(self) -> None:
            return None

        def complete(self) -> None:
            self._done = True
            for callback in tuple(self._callbacks):
                callback(self)

    class RecordingExecutor:
        def __init__(self) -> None:
            self.submitted: list[CallbackTarget] = []

        def submit(self, _function: object) -> CallbackTarget:
            future = CallbackTarget()
            self.submitted.append(future)
            return future

    class CountingLease:
        def __init__(self) -> None:
            self.release_count = 0

        def release(self) -> None:
            self.release_count += 1

    class StaticBulkhead:
        def __init__(self, lease: CountingLease) -> None:
            self._lease = lease

        async def acquire(self, _timeout: float) -> CountingLease:
            return self._lease

    executor = RecordingExecutor()
    wrapped_tasks: list[CallbackTarget] = []

    def wrap_future(_future: object, *, loop: object) -> CallbackTarget:
        del loop
        task = CallbackTarget()
        wrapped_tasks.append(task)
        return task

    async def wait_for_timeout(
        _tasks: object,
        *,
        timeout: float | None = None,
    ) -> tuple[set[object], set[object]]:
        del timeout
        return set(), set()

    monkeypatch.setattr(runtime_module.asyncio, "wrap_future", wrap_future)
    monkeypatch.setattr(runtime_module.asyncio, "wait", wait_for_timeout)

    runtime = Runtime(
        reconciliation_executor=executor,  # type: ignore[arg-type]
        reconciliation_audit_executor=executor,  # type: ignore[arg-type]
    )
    audit_lease = CountingLease()
    ledger_lease = CountingLease()
    runtime._reconciliation_audit_bulkhead = StaticBulkhead(audit_lease)  # type: ignore[assignment]
    runtime._reconciliation_bulkhead = StaticBulkhead(ledger_lease)  # type: ignore[assignment]
    try:
        with pytest.raises(StageTimeoutError, match="reconciliation audit delivery"):
            await runtime._run_reconciliation_audit_delivery(lambda: None)
        with pytest.raises(StageTimeoutError, match="reconciliation ledger operation"):
            await runtime._run_reconciliation_operation(lambda: None)

        assert len(executor.submitted) == 2
        assert len(wrapped_tasks) == 2
        for future, task in zip(executor.submitted, wrapped_tasks, strict=True):
            future.complete()
            task.complete()

        assert audit_lease.release_count == 1
        assert ledger_lease.release_count == 1
        assert runtime._reconciliation_draining == 0
    finally:
        runtime.close()
