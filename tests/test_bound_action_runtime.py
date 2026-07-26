from __future__ import annotations

import asyncio
import json
from dataclasses import FrozenInstanceError
from typing import Any, Mapping

import pytest

from agent_runtime_governance import (
    ActionContract,
    ApprovalRequest,
    AuditMiddleware,
    DecisionMiddleware,
    ExecutionMode,
    GovernanceCancelledError,
    GovernanceDenied,
    HumanDecisionProvider,
    InMemoryIdempotencyStore,
    InvocationOptions,
    JSONLAuditSink,
    PolicyMiddleware,
    ProductionProfile,
    ProductionReadinessError,
    RiskTier,
    Runtime,
    RuntimeLimits,
    SimplePolicy,
    SQLiteApprovalStore,
    StaticIdentityProvider,
    VerifiedPrincipal,
)
from agent_runtime_governance.errors import ToolExecutionError
from agent_runtime_governance.hooks import HookPoint
from agent_runtime_governance.middleware import GatingMiddleware


class RotatingKeyProvider:
    def __init__(self) -> None:
        self.key = b"k" * 32

    def get_key(self, *, tenant: str, version: str) -> bytes:
        assert tenant == "tenant-a"
        assert version == "key-v1"
        return self.key


class MutablePreconditionProvider:
    def __init__(self) -> None:
        self.digest = "b" * 64

    def get_digest(
        self,
        *,
        contract: ActionContract,
        parameters: Mapping[str, Any],
        principal: str,
        tenant: str,
    ) -> str:
        assert contract.precondition_requirements == ("resource.etag",)
        assert parameters["target"] == "node-a"
        assert principal == "service-account"
        assert tenant == "tenant-a"
        return self.digest


class RecordingIdempotencyStore(InMemoryIdempotencyStore):
    production_durable = True

    def __init__(self) -> None:
        super().__init__()
        self.acquisitions: list[tuple[str, str, str]] = []

    def acquire(self, namespace: str, key: str, fingerprint: str):
        self.acquisitions.append((namespace, key, fingerprint))
        return super().acquire(namespace, key, fingerprint)


def _principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="trusted-gateway",
        subject="service-account",
        tenant="tenant-a",
        source="static",
    )


def _contract(
    *,
    execution_mode: ExecutionMode = ExecutionMode.MUTATING,
    preconditions: tuple[str, ...] = (),
    receipt_schema: Mapping[str, Any] | None = None,
) -> ActionContract:
    return ActionContract(
        contract_id="ops.operate",
        contract_version=1,
        tool_name="operate",
        execution_mode=execution_mode,
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "payload": {
                    "type": "object",
                    "properties": {
                        "items": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["items"],
                    "additionalProperties": False,
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        effect_class="service.change",
        precondition_requirements=preconditions,
        receipt_schema=receipt_schema,
    )


def _profile(
    key_provider: RotatingKeyProvider,
    *,
    precondition_provider: MutablePreconditionProvider | None = None,
) -> ProductionProfile:
    return ProductionProfile(
        identity_digest_key_provider=key_provider,
        identity_digest_key_version="key-v1",
        policy_version="policy-v1",
        policy_digest="a" * 64,
        precondition_digest_provider=precondition_provider,
    )


def _runtime(
    tmp_path,
    *,
    key_provider: RotatingKeyProvider | None = None,
    precondition_provider: MutablePreconditionProvider | None = None,
    middlewares=(),
    idempotency_store=None,
) -> tuple[Runtime, JSONLAuditSink, RotatingKeyProvider]:
    keys = key_provider or RotatingKeyProvider()
    sink = JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32)
    runtime = Runtime(
        [*middlewares, AuditMiddleware(sink, fail_closed=True)],
        idempotency_store=idempotency_store or RecordingIdempotencyStore(),
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=_profile(
            keys, precondition_provider=precondition_provider
        ),
    )
    return runtime, sink, keys


@pytest.mark.asyncio
async def test_exact_bound_snapshot_reaches_tool_and_audit(tmp_path) -> None:
    received: list[object] = []
    runtime, sink, _ = _runtime(tmp_path)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str, payload: Mapping[str, object] | None = None) -> bool:
        assert target == "node-a"
        received.append(payload)
        return True

    runtime.seal_production()
    caller_payload = {"items": ["one", "two"]}
    result = await runtime.arun("operate", "node-a", caller_payload)
    action = result.context.bound_action

    assert action is not None
    assert received == [action.parameters["payload"]]
    assert received[0] is action.parameters["payload"]
    caller_payload["items"].append("caller-mutation")
    assert tuple(action.parameters["payload"]["items"]) == ("one", "two")
    events = sink.read_verified()
    assert events
    assert {event["action_digest"] for event in events} == {action.action_digest}
    assert {event["contract_id"] for event in events} == {"ops.operate"}
    assert all("parameters" not in event["context"]["bound_action"] for event in events)


@pytest.mark.asyncio
async def test_key_rotation_fails_before_tool_entry(tmp_path) -> None:
    calls: list[str] = []
    keys = RotatingKeyProvider()
    runtime, _, _ = _runtime(tmp_path, key_provider=keys)

    @runtime.hook(HookPoint.BEFORE_EXECUTE, critical=True)
    def rotate_key(context):
        keys.key = b"r" * 32

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str) -> bool:
        calls.append(target)
        return True

    runtime.seal_production()
    with pytest.raises(GovernanceDenied) as caught:
        await runtime.arun("operate", "node-a")

    assert calls == []
    assert caught.value.context.decision is not None
    assert caught.value.context.decision.reason == "action.executor_digest_mismatch"
    assert caught.value.context.bound_action is not None


@pytest.mark.asyncio
async def test_precondition_change_fails_before_tool_entry(tmp_path) -> None:
    calls: list[str] = []
    preconditions = MutablePreconditionProvider()
    runtime, _, _ = _runtime(
        tmp_path, precondition_provider=preconditions
    )

    @runtime.hook(HookPoint.BEFORE_EXECUTE, critical=True)
    def change_precondition(context):
        preconditions.digest = "c" * 64

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(preconditions=("resource.etag",)),
    )
    def operate(target: str) -> bool:
        calls.append(target)
        return True

    runtime.seal_production()
    with pytest.raises(GovernanceDenied) as caught:
        await runtime.arun("operate", "node-a")

    assert calls == []
    assert caught.value.context.decision is not None
    assert caught.value.context.decision.reason == "action.executor_digest_mismatch"


@pytest.mark.asyncio
async def test_policy_identity_mismatch_fails_closed(tmp_path) -> None:
    calls: list[str] = []
    policy = PolicyMiddleware(
        SimplePolicy(),
        version="policy-v2",
        digest="d" * 64,
    )
    runtime, _, _ = _runtime(tmp_path, middlewares=(policy,))

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str) -> bool:
        calls.append(target)
        return True

    with pytest.raises(ProductionReadinessError) as caught:
        runtime.seal_production()

    assert calls == []
    assert "policy.identity_mismatch" in str(caught.value)


@pytest.mark.asyncio
async def test_contracted_idempotency_uses_versioned_action_identity(tmp_path) -> None:
    store = RecordingIdempotencyStore()
    runtime, _, _ = _runtime(tmp_path, idempotency_store=store)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=_contract(execution_mode=ExecutionMode.IDEMPOTENT),
    )
    def operate(target: str) -> str:
        return target

    runtime.seal_production()
    result = await runtime.arun(
        "operate",
        "node-a",
        _governance=InvocationOptions(idempotency_key="request-1"),
    )
    action = result.context.bound_action

    assert action is not None
    assert store.acquisitions == [
        (
            f"action/v1:{action.tenant_digest}:ops.operate",
            "request-1",
            action.action_digest,
        )
    ]


@pytest.mark.asyncio
async def test_legacy_idempotency_namespace_cannot_satisfy_action_claim(tmp_path) -> None:
    store = RecordingIdempotencyStore()
    legacy = store.acquire("tenant-a:operate", "request-1", "f" * 64)
    store.complete(legacy, "legacy-result")
    calls: list[str] = []
    runtime, _, _ = _runtime(tmp_path, idempotency_store=store)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=_contract(execution_mode=ExecutionMode.IDEMPOTENT),
    )
    def operate(target: str) -> str:
        calls.append(target)
        return "v0.6-result"

    runtime.seal_production()
    result = await runtime.arun(
        "operate",
        "node-a",
        _governance=InvocationOptions(idempotency_key="request-1"),
    )

    assert result.value == "v0.6-result"
    assert calls == ["node-a"]
    assert store.acquisitions[-1][0].startswith("action/v1:")


@pytest.mark.asyncio
async def test_middleware_cannot_replace_or_mutate_bound_action(tmp_path) -> None:
    class ReplaceAction(GatingMiddleware):
        name = "replace_action"

        async def process(self, context):
            action = context.bound_action
            assert action is not None
            with pytest.raises(TypeError):
                action.parameters["target"] = "node-b"
            with pytest.raises(FrozenInstanceError):
                action.action_digest = "f" * 64
            replacement = action.contract.bind(
                {"target": "node-b"},
                identity_issuer="trusted-gateway",
                principal="service-account",
                tenant="tenant-a",
                identity_digest_key=b"k" * 32,
                identity_digest_key_version="key-v1",
                policy_version="policy-v1",
                policy_digest="a" * 64,
            )
            payload = context.to_dict()
            payload["bound_action"] = replacement.to_dict()
            return type(context).from_dict(payload)

    calls: list[str] = []
    runtime, _, _ = _runtime(tmp_path, middlewares=(ReplaceAction(),))

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str) -> bool:
        calls.append(target)
        return True

    runtime.seal_production()
    with pytest.raises(GovernanceDenied) as caught:
        await runtime.arun("operate", "node-a")

    assert calls == []
    assert any("request identity" in entry.reason for entry in caught.value.context.history)


@pytest.mark.asyncio
async def test_critical_hook_cannot_replace_bound_action(tmp_path) -> None:
    calls: list[str] = []
    runtime, _, _ = _runtime(tmp_path)

    @runtime.hook(HookPoint.BEFORE_EXECUTE, critical=True)
    def replace_action(context):
        action = context.bound_action
        assert action is not None
        replacement = action.contract.bind(
            {"target": "node-b"},
            identity_issuer="trusted-gateway",
            principal="service-account",
            tenant="tenant-a",
            identity_digest_key=b"k" * 32,
            identity_digest_key_version="key-v1",
            policy_version="policy-v1",
            policy_digest="a" * 64,
        )
        payload = context.to_dict()
        payload["bound_action"] = replacement.to_dict()
        return type(context).from_dict(payload)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str) -> bool:
        calls.append(target)
        return True

    runtime.seal_production()
    with pytest.raises(GovernanceDenied):
        await runtime.arun("operate", "node-a")
    assert calls == []


@pytest.mark.asyncio
async def test_exception_and_timeout_keep_bound_action_in_audit(tmp_path) -> None:
    runtime, sink, _ = _runtime(tmp_path)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    async def operate(target: str) -> bool:
        if target == "error":
            raise RuntimeError("tool failed")
        await asyncio.sleep(0.05)
        return True

    runtime.seal_production()
    with pytest.raises(ToolExecutionError) as failed:
        await runtime.arun("operate", "error")
    failed_action = failed.value.context.bound_action
    assert failed_action is not None
    assert sink.read_verified()[-1]["action_digest"] == failed_action.action_digest

    runtime.limits = RuntimeLimits(execution_timeout_seconds=0.01)
    with pytest.raises(ToolExecutionError) as timed_out:
        await runtime.arun("operate", "node-a")
    timeout_action = timed_out.value.context.bound_action
    assert timeout_action is not None
    assert sink.read_verified()[-1]["action_digest"] == timeout_action.action_digest


@pytest.mark.asyncio
async def test_cancellation_keeps_bound_action_in_audit(tmp_path) -> None:
    entered = asyncio.Event()
    runtime, sink, _ = _runtime(tmp_path)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    async def operate(target: str) -> bool:
        entered.set()
        await asyncio.Event().wait()
        return True

    runtime.seal_production()
    task = asyncio.create_task(runtime.arun("operate", "node-a"))
    await entered.wait()
    task.cancel()
    with pytest.raises(GovernanceCancelledError) as cancelled:
        await task

    action = cancelled.value.context.bound_action
    assert action is not None
    assert sink.read_verified()[-1]["action_digest"] == action.action_digest


@pytest.mark.asyncio
async def test_contract_receipt_schema_is_enforced(tmp_path) -> None:
    runtime, sink, _ = _runtime(tmp_path)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(
            receipt_schema={
                "type": "object",
                "properties": {"changed": {"type": "boolean"}},
                "required": ["changed"],
                "additionalProperties": False,
            }
        ),
    )
    def operate(target: str) -> dict[str, str]:
        return {"changed": "yes"}

    runtime.seal_production()
    with pytest.raises(ToolExecutionError) as caught:
        await runtime.arun("operate", "node-a")

    action = caught.value.context.bound_action
    assert action is not None
    assert "action receipt" in str(caught.value.cause)
    assert sink.read_verified()[-1]["action_digest"] == action.action_digest


@pytest.mark.asyncio
async def test_approval_is_bound_to_action_digest(tmp_path) -> None:
    requests: list[ApprovalRequest] = []

    def approve(context, request: ApprovalRequest) -> bool:
        requests.append(request)
        return True

    approvals = SQLiteApprovalStore(
        tmp_path / "approvals.db", sign_key=b"p" * 32
    )
    middleware = DecisionMiddleware(
        HumanDecisionProvider(approve), store=approvals
    )
    runtime, _, _ = _runtime(tmp_path, middlewares=(middleware,))

    @runtime.tool(
        name="operate",
        risk=RiskTier.HIGH,
        requires_approval=True,
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str) -> bool:
        return True

    runtime.seal_production()
    result = await runtime.arun(
        "operate",
        "node-a",
        _governance=InvocationOptions(request_id="approval-1"),
    )
    action = result.context.bound_action

    assert action is not None
    assert requests[0].action_digest == action.action_digest
    assert result.context.decision is not None
    assert result.context.decision.action_digest == action.action_digest


@pytest.mark.asyncio
async def test_v05_approval_fails_closed_for_contracted_tool(tmp_path) -> None:
    provider_called = False

    def approve(context, request: ApprovalRequest) -> bool:
        nonlocal provider_called
        provider_called = True
        return True

    approvals = SQLiteApprovalStore(
        tmp_path / "approvals.db", sign_key=b"p" * 32
    )
    approvals.pending(
        ApprovalRequest(
            trace_id="legacy-trace",
            request_id="approval-legacy",
            tool_name="operate",
            arguments={"args": ["node-a"], "kwargs": {}},
            risk_tier="HIGH",
            reason="legacy v0.5 approval",
            policy_version="policy-v1",
            policy_digest="a" * 64,
            subject="service-account",
            tenant="tenant-a",
            identity_issuer="trusted-gateway",
        )
    )
    middleware = DecisionMiddleware(
        HumanDecisionProvider(approve), store=approvals
    )
    runtime, _, _ = _runtime(tmp_path, middlewares=(middleware,))

    @runtime.tool(
        name="operate",
        risk=RiskTier.HIGH,
        requires_approval=True,
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str) -> bool:
        raise AssertionError("legacy approval must not reach the tool")

    runtime.seal_production()
    with pytest.raises(GovernanceDenied) as caught:
        await runtime.arun(
            "operate",
            "node-a",
            _governance=InvocationOptions(request_id="approval-legacy"),
        )

    assert provider_called is False
    assert caught.value.context.decision is not None
    assert caught.value.context.decision.reason == (
        "approval.action_digest_missing: re-approval required"
    )


def test_audit_bound_action_never_duplicates_raw_parameters(tmp_path) -> None:
    runtime, _, _ = _runtime(tmp_path)

    @runtime.tool(
        name="operate",
        execution_mode=ExecutionMode.MUTATING,
        action_contract=_contract(),
    )
    def operate(target: str) -> bool:
        return True

    runtime.seal_production()
    result = runtime.invoke("operate", "node-a")
    assert result is True
    records = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert all(
        "parameters" not in record["context"]["bound_action"]
        for record in records
    )
