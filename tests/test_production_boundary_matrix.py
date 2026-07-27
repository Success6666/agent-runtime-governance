from __future__ import annotations

import asyncio
import sqlite3
import sys
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from types import ModuleType
from uuid import uuid4

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from agent_runtime_governance.approval_store import (
    InMemoryApprovalStore,
    SQLiteApprovalStore,
)
from agent_runtime_governance.context import (
    ExecutionContext,
    ExecutionStatus,
    HistoryEntry,
    RiskTier,
    ToolCall,
)
from agent_runtime_governance.decisions import (
    ApprovalRequest,
    DecisionOutcome,
    DecisionRecord,
    HumanDecisionProvider,
)
from agent_runtime_governance.errors import (
    GovernanceCancelledError,
    get_cancellation_context,
)
from agent_runtime_governance.identity import (
    HMACClaimsIdentityProvider,
    InMemoryIdentityReplayStore,
    SQLiteIdentityReplayStore,
    StaticIdentityProvider,
    VerifiedPrincipal,
)
from agent_runtime_governance.middleware.decision import DecisionMiddleware
from agent_runtime_governance.plugins import opa as opa_module
from agent_runtime_governance.plugins.core import PluginManager, RuntimeBuilder
from agent_runtime_governance.plugins.opa import (
    OPAClient,
    OPAMiddleware,
    OPAPlugin,
)
from agent_runtime_governance.plugins.prometheus import (
    PrometheusMiddleware,
    PrometheusPlugin,
)
from agent_runtime_governance.reconciliation import InMemoryReconciliationLedger
from agent_runtime_governance.registry import (
    IdempotencyClaim,
    IdempotencyConflictError,
    IdempotencyOutcomeUnknownError,
    InMemoryIdempotencyStore,
    SQLiteIdempotencyStore,
    ToolSpec,
)
from agent_runtime_governance.resilience import RuntimeLimits

HMAC_KEY = "production-boundary-key-32-bytes!!"


def _request(**changes: object) -> ApprovalRequest:
    values: dict[str, object] = {
        "trace_id": "trace-boundary",
        "request_id": "request-boundary",
        "tool_name": "delete_file",
        "arguments": {"args": ["a.txt"], "kwargs": {"force": True}},
        "risk_tier": "HIGH",
        "reason": "operator approval required",
    }
    values.update(changes)
    return ApprovalRequest(**values)  # type: ignore[arg-type]


def _claims(**changes: object) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    values: dict[str, object] = {
        "issuer": "gateway",
        "audience": "agent-runtime",
        "subject": "alice",
        "tenant": "tenant-a",
        "permissions": ["file:write"],
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + timedelta(minutes=2)).timestamp(),
        "jti": uuid4().hex,
    }
    values.update(changes)
    return values


def _provider() -> HMACClaimsIdentityProvider:
    return HMACClaimsIdentityProvider(
        HMAC_KEY,
        expected_issuer="gateway",
        expected_audience="agent-runtime",
    )


def _context(*, approval: bool = False) -> ExecutionContext:
    return ExecutionContext.create(
        ToolCall("delete_file", ("a.txt",), {"force": True}),
        request_id="request-boundary",
        user="alice",
        tenant="tenant-a",
        permissions={"file:write"},
        risk_tier=RiskTier.HIGH,
        requires_approval=approval,
    )


@pytest.mark.parametrize("field", ["issuer", "subject", "tenant"])
def test_verified_principal_requires_all_identity_fields(field: str) -> None:
    values = {"issuer": "gateway", "subject": "alice", "tenant": "tenant-a"}
    values[field] = ""

    with pytest.raises(ValueError, match=f"{field} is required"):
        VerifiedPrincipal(**values)


def test_verified_principal_enforces_permission_and_timestamp_boundaries() -> None:
    with pytest.raises(ValueError, match="more than 256"):
        VerifiedPrincipal(
            "gateway", "alice", "tenant-a", frozenset(f"p:{i}" for i in range(257))
        )
    with pytest.raises(ValueError, match="permission"):
        VerifiedPrincipal("gateway", "alice", "tenant-a", frozenset({"bad permission"}))
    with pytest.raises(ValueError, match="ISO 8601"):
        VerifiedPrincipal("gateway", "alice", "tenant-a", verified_at="not-a-time")
    with pytest.raises(ValueError, match="timezone-aware"):
        VerifiedPrincipal(
            "gateway", "alice", "tenant-a", verified_at="2026-01-01T00:00:00"
        )


def test_verified_principal_serializes_an_isolated_claim_snapshot() -> None:
    claims = {"nested": {"roles": ["ops"], "zones": {"b", "a"}}}
    principal = VerifiedPrincipal(
        "gateway", "alice", "tenant-a", claims=claims
    )
    claims["nested"]["roles"].append("admin")  # type: ignore[index,union-attr]

    serialized = principal.to_dict()
    assert serialized["claims"] == {
        "nested": {"roles": ["ops"], "zones": ["a", "b"]}
    }


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_identity_replay_store_rejects_duplicates_and_prunes_expired(
    tmp_path, store_kind: str
) -> None:
    store = (
        InMemoryIdentityReplayStore()
        if store_kind == "memory"
        else SQLiteIdentityReplayStore(tmp_path / "identity.db")
    )
    future = datetime.now(timezone.utc) + timedelta(minutes=1)
    assert store.claim("gateway", "replay-token-0001", future) is True
    assert store.claim("gateway", "replay-token-0001", future) is False

    expired = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert store.claim("gateway", "expired-token-01", expired) is True
    assert store.claim("gateway", "expired-token-01", future) is True


def test_sqlite_identity_replay_store_rejects_invalid_timeout(tmp_path) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        SQLiteIdentityReplayStore(tmp_path / "identity.db", timeout_seconds=0)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"expected_issuer": ""}, "expected_issuer"),
        ({"expected_audience": ""}, "expected_audience"),
        ({"max_lifetime_seconds": 0}, "lifetime"),
        ({"clock_skew_seconds": -1}, "clock skew"),
        ({"max_claims_bytes": 0}, "max_claims_bytes"),
    ],
)
def test_hmac_provider_rejects_invalid_configuration(
    kwargs: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "expected_issuer": "gateway",
        "expected_audience": "agent-runtime",
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=message):
        HMACClaimsIdentityProvider(HMAC_KEY, **values)  # type: ignore[arg-type]


def test_hmac_provider_rejects_empty_or_invalid_key_sets() -> None:
    with pytest.raises(ValueError, match="at least one"):
        HMACClaimsIdentityProvider(
            {}, expected_issuer="gateway", expected_audience="agent-runtime"
        )
    with pytest.raises(ValueError, match="key id"):
        HMACClaimsIdentityProvider(
            {"bad key": HMAC_KEY},
            expected_issuer="gateway",
            expected_audience="agent-runtime",
        )


@pytest.mark.parametrize(
    ("envelope", "message"),
    [
        (None, "required"),
        ({"claims": "bad", "signature": "value"}, "contain claims"),
        ({"claims": {}, "signature": "value", "kid": "missing"}, "unknown"),
    ],
)
def test_hmac_provider_rejects_malformed_envelopes(
    envelope: dict[str, object] | None, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _provider().verify(envelope)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"issuer": "other"}, "issuer"),
        ({"audience": 42}, "audience"),
        ({"iat": True}, "iat"),
        ({"exp": 10**30}, "exp"),
        ({"subject": ""}, "subject"),
        ({"tenant": ""}, "tenant"),
        ({"jti": "short"}, "jti"),
        ({"permissions": {"role": "admin"}}, "sequence"),
        ({"permissions": [f"p:{i}" for i in range(257)]}, "entry limit"),
        ({"permissions": ["bad permission"]}, "permission"),
    ],
)
def test_hmac_provider_rejects_invalid_claim_shapes(
    changes: dict[str, object], message: str
) -> None:
    claims = _claims(**changes)
    envelope = HMACClaimsIdentityProvider.sign_claims(claims, HMAC_KEY)
    with pytest.raises(ValueError, match=message):
        _provider().verify(envelope)


def test_hmac_provider_accepts_audience_list_and_single_permission() -> None:
    claims = _claims(audience=["other", "agent-runtime"], permissions="file:write")
    principal = _provider().verify(
        HMACClaimsIdentityProvider.sign_claims(claims, HMAC_KEY)
    )
    assert principal.permissions == frozenset({"file:write"})


def test_identity_replay_retention_includes_clock_skew_window() -> None:
    now = datetime.now(timezone.utc)
    claims = _claims(
        iat=(now - timedelta(seconds=60)).timestamp(),
        nbf=(now - timedelta(seconds=60)).timestamp(),
        exp=(now - timedelta(seconds=5)).timestamp(),
    )
    envelope = HMACClaimsIdentityProvider.sign_claims(claims, HMAC_KEY)
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY,
        expected_issuer="gateway",
        expected_audience="agent-runtime",
        clock_skew_seconds=30,
    )

    assert provider.verify(envelope).subject == "alice"
    with pytest.raises(ValueError, match="already used"):
        provider.verify(envelope)


def test_cancellation_context_rejects_arbitrary_exception_attributes() -> None:
    context = _context()
    arbitrary = RuntimeError("not governed")
    arbitrary.context = context  # type: ignore[attr-defined]
    assert get_cancellation_context(arbitrary) is None

    carrier = GovernanceCancelledError(context)
    try:
        raise asyncio.CancelledError() from carrier
    except asyncio.CancelledError as rematerialized:
        assert get_cancellation_context(rematerialized) is context


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"name": "bad name"}, ValueError),
        ({"function": "not-callable"}, TypeError),
        ({"max_parameters_bytes": 0}, ValueError),
        ({"max_result_bytes": 0}, ValueError),
    ],
)
def test_tool_spec_rejects_invalid_registration_boundaries(
    changes: dict[str, object], error: type[Exception]
) -> None:
    values: dict[str, object] = {
        "name": "read_file",
        "function": lambda: None,
        "risk": RiskTier.LOW,
        "requires_approval": False,
        "description": "read a file",
    }
    values.update(changes)
    with pytest.raises(error):
        ToolSpec(**values)  # type: ignore[arg-type]


def test_tool_spec_freezes_nested_contract_schemas() -> None:
    schema = {
        "type": "object",
        "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
    }
    spec = ToolSpec(
        "read_file",
        lambda: None,
        RiskTier.LOW,
        False,
        "read a file",
        parameters_schema=schema,
        result_schema={"type": "array", "items": {"type": "string"}},
    )
    schema["properties"]["paths"]["type"] = "string"  # type: ignore[index]
    assert spec.parameters_schema["properties"]["paths"]["type"] == "array"  # type: ignore[index]
    assert isinstance(spec.result_schema["type"], str)  # type: ignore[index]


def test_in_memory_idempotency_store_covers_owner_and_waiter_lifecycles() -> None:
    store = InMemoryIdempotencyStore()
    owner = store.acquire("tenant/tool", "request-1", "a" * 64)
    waiter = store.acquire("tenant/tool", "request-1", "a" * 64)
    with pytest.raises(IdempotencyConflictError):
        store.acquire("tenant/tool", "request-1", "b" * 64)

    store.complete(waiter, {"ignored": True})
    store.fail(waiter, RuntimeError("ignored"))
    store.mark_unknown(waiter, RuntimeError("ignored"))
    with pytest.raises(RuntimeError, match="owner"):
        store.renew(waiter)

    result = {"items": [1]}
    store.complete(owner, result)
    result["items"].append(2)
    assert waiter.future.result() == {"items": [1]}
    store.complete(owner, {"ignored": True})

    failed = store.acquire("tenant/tool", "request-2", "c" * 64)
    store.fail(failed, RuntimeError("retryable"))
    replacement = store.acquire("tenant/tool", "request-2", "c" * 64)
    assert replacement.owner is True

    unknown = store.acquire("tenant/tool", "request-3", "d" * 64)
    store.mark_unknown(unknown, RuntimeError("uncertain"))
    with pytest.raises(IdempotencyOutcomeUnknownError, match="uncertain"):
        unknown.future.result()
    store.renew(owner)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"lease_seconds": 0}, "lease_seconds"),
        ({"timeout_seconds": 0}, "timeout_seconds"),
    ],
)
def test_sqlite_idempotency_store_rejects_invalid_configuration(
    tmp_path, kwargs: dict[str, float], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        SQLiteIdempotencyStore(tmp_path / "idempotency.db", **kwargs)


@pytest.mark.parametrize(
    ("namespace", "key", "fingerprint", "message"),
    [
        ("bad namespace", "request", "a" * 64, "namespace"),
        ("tenant/tool", "bad key", "a" * 64, "key"),
        ("tenant/tool", "request", "not-a-digest", "fingerprint"),
    ],
)
def test_sqlite_idempotency_store_rejects_invalid_claim_identity(
    tmp_path, namespace: str, key: str, fingerprint: str, message: str
) -> None:
    store = SQLiteIdempotencyStore(tmp_path / "idempotency.db")
    with pytest.raises(ValueError, match=message):
        store.acquire(namespace, key, fingerprint)


def test_sqlite_idempotency_store_preserves_unknown_and_non_owner_states(tmp_path) -> None:
    store = SQLiteIdempotencyStore(tmp_path / "idempotency.db")
    owner = store.acquire("tenant/tool", "request", "a" * 64)
    waiter = IdempotencyClaim(
        owner.namespace, owner.key, owner.fingerprint, False, Future()
    )
    store.complete(waiter, {"ignored": True})
    store.fail(waiter, RuntimeError("ignored"))
    store.mark_unknown(waiter, RuntimeError("ignored"))
    with pytest.raises(RuntimeError, match="owner"):
        store.renew(waiter)

    store.mark_unknown(owner, RuntimeError("uncertain"))
    recovered = store.acquire("tenant/tool", "request", "a" * 64)
    with pytest.raises(IdempotencyOutcomeUnknownError, match="uncertain"):
        recovered.future.result()
    with pytest.raises(ValueError, match="timezone-aware"):
        store.prune_completed(older_than=datetime.now())


def test_sqlite_idempotency_store_fails_closed_on_invalid_persisted_state(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    store = SQLiteIdempotencyStore(path)
    owner = store.acquire("tenant/tool", "request", "a" * 64)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "UPDATE idempotency_records SET state = 'completed', "
                "result_json = 'null', owner_token = NULL, "
                "lease_expires_at = NULL WHERE key = 'request'"
            )
    with pytest.raises(RuntimeError, match="ownership was lost"):
        store.renew(owner)
    with pytest.raises(RuntimeError, match="ownership was lost"):
        store.fail(owner, RuntimeError("late failure"))


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_approval_store_rejects_request_id_reuse_and_invalid_lease(
    tmp_path, store_kind: str
) -> None:
    store = (
        InMemoryApprovalStore()
        if store_kind == "memory"
        else SQLiteApprovalStore(tmp_path / "approvals.db")
    )
    request = _request(request_id=f"reuse-{store_kind}")
    store.pending(request)
    store.pending(request)
    with pytest.raises(ValueError, match="different request"):
        store.pending(
            _request(request_id=request.request_id, tool_name="different_tool")
        )
    with pytest.raises(ValueError, match="lease_seconds"):
        store.reserve(request, lease_seconds=0)
    with pytest.raises(KeyError):
        store.decide("missing", DecisionRecord(DecisionOutcome.DENY, "no", "human"))


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_approval_store_denies_missing_pending_and_expired_decisions(
    tmp_path, store_kind: str
) -> None:
    store = (
        InMemoryApprovalStore()
        if store_kind == "memory"
        else SQLiteApprovalStore(tmp_path / "approvals.db")
    )
    missing = _request(request_id=f"missing-{store_kind}")
    assert store.reserve(missing, lease_seconds=1).decision.outcome is DecisionOutcome.DENY

    pending = _request(request_id=f"pending-{store_kind}")
    store.pending(pending)
    pending_result = store.reserve(pending, lease_seconds=1)
    assert "pending" in pending_result.decision.reason

    now = datetime.now(timezone.utc)
    expired_decision = DecisionRecord(
        DecisionOutcome.ALLOW,
        "approved",
        "human",
        approver="operator",
        issued_at=(now - timedelta(seconds=10)).isoformat(),
        expires_at=(now - timedelta(seconds=5)).isoformat(),
    )
    store.decide(pending.request_id, expired_decision)
    expired_result = store.reserve(pending, lease_seconds=1)
    assert "decision expired" in expired_result.decision.reason
    assert store.commit(missing, "missing-token").outcome is DecisionOutcome.DENY
    assert store.release("missing", "missing-token") is False


@pytest.mark.asyncio
async def test_decision_middleware_constructor_and_non_approval_boundaries() -> None:
    with pytest.raises(ValueError, match="provider or store"):
        DecisionMiddleware()
    with pytest.raises(ValueError, match="provider_timeout_seconds"):
        DecisionMiddleware(store=InMemoryApprovalStore(), provider_timeout_seconds=0)
    with pytest.raises(ValueError, match="approval_ttl_seconds"):
        DecisionMiddleware(store=InMemoryApprovalStore(), approval_ttl_seconds=0)
    with pytest.raises(ValueError, match="reservation_ttl_seconds"):
        DecisionMiddleware(store=InMemoryApprovalStore(), reservation_ttl_seconds=0)
    principal = VerifiedPrincipal("gateway", "alice", "tenant-a")
    with pytest.raises(ValueError, match="configured on Runtime"):
        DecisionMiddleware(
            store=InMemoryApprovalStore(),
            identity_provider=StaticIdentityProvider(principal),
        )

    middleware = DecisionMiddleware(store=InMemoryApprovalStore())
    skipped = await middleware.process(_context())
    assert skipped.history[-1].outcome == "skip"
    assert await middleware.commit_approval(skipped) is skipped
    assert await middleware.release_approval(skipped) is skipped


@pytest.mark.asyncio
async def test_decision_middleware_handles_human_pending_and_missing_approver() -> None:
    class Provider:
        def __init__(self, decision: DecisionRecord) -> None:
            self.decision = decision

        async def decide(self, context, request):
            return self.decision

    pending = DecisionMiddleware(
        Provider(DecisionRecord(DecisionOutcome.REQUIRE_HUMAN, "wait", "human"))
    )
    denied = await pending.process(_context(approval=True))
    assert denied.decision.outcome is DecisionOutcome.DENY
    assert "must return allow or deny" in denied.decision.reason

    allow = DecisionRecord(DecisionOutcome.ALLOW, "ok", "human")
    required = await DecisionMiddleware(Provider(allow)).process(_context(approval=True))
    assert required.decision.outcome is DecisionOutcome.DENY
    optional = await DecisionMiddleware(
        Provider(allow), require_approver=False
    ).process(_context(approval=True))
    assert optional.decision.outcome is DecisionOutcome.ALLOW


@pytest.mark.asyncio
async def test_human_provider_applies_configured_approver_to_full_record() -> None:
    provider = HumanDecisionProvider(
        lambda context, request: DecisionRecord(
            DecisionOutcome.ALLOW, "approved", "human"
        ),
        approver="operator-1",
    )
    decision = await provider.decide(_context(approval=True), _request())
    assert decision.approver == "operator-1"


@pytest.mark.asyncio
async def test_pruned_approval_reservation_denies_at_delayed_execution_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Provider:
        async def decide(self, context, request):
            return DecisionRecord(
                DecisionOutcome.ALLOW,
                "approved",
                "human",
                approver="operator",
            )

    clock = {"value": 0.0}
    monkeypatch.setattr(
        "agent_runtime_governance.middleware.decision.monotonic",
        lambda: clock["value"],
    )
    middleware = DecisionMiddleware(
        Provider(),
        store=InMemoryApprovalStore(),
        reservation_ttl_seconds=1.0,
    )
    first = await middleware.process(_context(approval=True))
    assert first.decision.outcome is DecisionOutcome.ALLOW
    assert middleware.active_reservation_count == 1
    clock["value"] = 2.0
    second_context = ExecutionContext.create(
        ToolCall("delete_file"),
        request_id="request-second",
        risk_tier=RiskTier.HIGH,
        requires_approval=True,
    )
    second = await middleware.process(second_context)
    assert second.decision.outcome is DecisionOutcome.ALLOW
    assert middleware.active_reservation_count == 1

    delayed = await middleware.commit_approval(first)
    assert delayed.denied
    assert "unavailable at the execution boundary" in delayed.decision.reason
    assert middleware.active_reservation_count == 1
    await middleware.release_approval(second)
    assert middleware.active_reservation_count == 0


def test_runtime_builder_applies_all_runtime_dependencies() -> None:
    principal = VerifiedPrincipal("gateway", "alice", "tenant-a")
    identity = StaticIdentityProvider(principal)
    idempotency = InMemoryIdempotencyStore()
    reconciliation = InMemoryReconciliationLedger()
    limits = RuntimeLimits(max_in_flight=2)
    with (
        ThreadPoolExecutor(max_workers=1) as executor,
        ThreadPoolExecutor(max_workers=1) as idempotency_executor,
        ThreadPoolExecutor(max_workers=1) as reconciliation_executor,
        ThreadPoolExecutor(max_workers=1) as reconciliation_audit_executor,
    ):
        builder = RuntimeBuilder()
        assert builder.with_identity(identity) is builder
        assert builder.with_idempotency_store(idempotency) is builder
        assert builder.with_reconciliation_ledger(reconciliation) is builder
        assert builder.with_limits(limits) is builder
        assert builder.with_sync_executor(executor) is builder
        assert builder.with_idempotency_executor(idempotency_executor) is builder
        assert builder.with_reconciliation_executor(reconciliation_executor) is builder
        assert (
            builder.with_reconciliation_audit_executor(reconciliation_audit_executor)
            is builder
        )
        runtime = builder.build()
        assert runtime.identity_provider is identity
        assert runtime.require_verified_identity is True
        assert runtime.idempotency_store is idempotency
        assert runtime.reconciliation_ledger is reconciliation
        assert runtime.limits is limits
        assert runtime.sync_executor is executor
        assert runtime.idempotency_executor is idempotency_executor
        assert runtime.reconciliation_executor is reconciliation_executor
        assert runtime.reconciliation_audit_executor is reconciliation_audit_executor
        runtime.close()
        assert reconciliation_audit_executor.submit(lambda: True).result() is True


def test_runtime_builder_rejects_empty_registration_names() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        RuntimeBuilder().add_service("", object())


def test_plugin_module_factory_and_missing_exports() -> None:
    class Plugin:
        name = "factory-plugin"
        version = "1"

        def register(self, builder: RuntimeBuilder) -> None:
            builder.add_service("factory", object())

    factory_name = "test_boundary_factory_plugin"
    factory_module = ModuleType(factory_name)
    factory_module.create_plugin = lambda: Plugin()  # type: ignore[attr-defined]
    missing_name = "test_boundary_missing_plugin"
    missing_module = ModuleType(missing_name)
    sys.modules[factory_name] = factory_module
    sys.modules[missing_name] = missing_module
    try:
        record = PluginManager().load_module(factory_name)
        assert record.source == f"module:{factory_name}"
        with pytest.raises(TypeError, match="must export"):
            PluginManager().load_module(missing_name)
    finally:
        sys.modules.pop(factory_name, None)
        sys.modules.pop(missing_name, None)


@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://opa.example.com",
        "http://opa.example.com",
        "https://user@opa.example.com",
        "https://opa.example.com?query=yes",
        "https://opa.example.com#fragment",
    ],
)
def test_opa_client_rejects_unsafe_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError, match="OPA endpoint"):
        OPAClient(endpoint, "agent/allow")


@pytest.mark.parametrize("path", ["", "../admin", "agent/allow?"])
def test_opa_client_rejects_unsafe_policy_paths(path: str) -> None:
    with pytest.raises(ValueError, match="policy path"):
        OPAClient("https://opa.example.com", path)


def test_opa_client_rejects_invalid_limits_and_headers() -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        OPAClient("https://opa.example.com", "agent/allow", timeout_seconds=0)
    with pytest.raises(ValueError, match="byte limits"):
        OPAClient("https://opa.example.com", "agent/allow", max_request_bytes=0)
    with pytest.raises(ValueError, match="header name"):
        OPAClient(
            "https://opa.example.com", "agent/allow", headers={"Bad:Name": "value"}
        )


def test_opa_redirect_handler_refuses_all_redirects() -> None:
    handler = opa_module._RejectRedirects()
    assert handler.redirect_request(None, None, 307, "redirect", {}, "https://other") is None
    with pytest.raises(ValueError, match="header value"):
        OPAClient(
            "https://opa.example.com", "agent/allow", headers={"X-Token": "bad\nvalue"}
        )


def test_opa_client_parses_boolean_and_structured_decisions() -> None:
    context = _context()
    boolean = OPAClient(
        "https://opa.example.com", "agent/allow", transport=lambda payload: {"result": True}
    )
    assert boolean.evaluate(context).allow is True
    structured = OPAClient(
        "https://opa.example.com",
        "agent/allow",
        transport=lambda payload: {"result": {"allow": False, "reason": "blocked"}},
    )
    assert structured.evaluate(context).reason == "blocked"
    invalid = OPAClient(
        "https://opa.example.com", "agent/allow", transport=lambda payload: {"result": {}}
    )
    with pytest.raises(ValueError, match="result.allow"):
        invalid.evaluate(context)
    too_small = OPAClient(
        "https://opa.example.com",
        "agent/allow",
        transport=lambda payload: {"result": True},
        max_request_bytes=1,
    )
    with pytest.raises(ValueError, match="request exceeded"):
        too_small.evaluate(context)


@pytest.mark.asyncio
async def test_opa_middleware_covers_allow_deny_and_failure_policies() -> None:
    allowed = OPAClient(
        "https://opa.example.com", "agent/allow", transport=lambda payload: {"result": True}
    )
    allowed_context = await OPAMiddleware(allowed).process(_context())
    assert allowed_context.history[-1].outcome == "allow"

    denied = OPAClient(
        "https://opa.example.com",
        "agent/allow",
        transport=lambda payload: {"result": {"allow": False, "reason": "policy"}},
    )
    denied_context = await OPAMiddleware(denied).process(_context())
    assert denied_context.decision.outcome is DecisionOutcome.DENY

    failed = OPAClient(
        "https://opa.example.com",
        "agent/allow",
        transport=lambda payload: (_ for _ in ()).throw(OSError("unavailable")),
    )
    with pytest.raises(OSError, match="unavailable"):
        await OPAMiddleware(failed).process(_context())
    fail_open = await OPAMiddleware(failed, fail_closed=False).process(_context())
    assert fail_open.history[-1].outcome == "error"


def test_opa_and_prometheus_plugins_register_services() -> None:
    builder = RuntimeBuilder()
    client = OPAClient(
        "https://opa.example.com", "agent/allow", transport=lambda payload: {"result": True}
    )
    OPAPlugin(client).register(builder)
    registry = CollectorRegistry()
    PrometheusPlugin(registry=registry, prefix="boundary_plugin").register(builder)
    assert builder.services["opa"] is client
    assert "prometheus" in builder.services
    assert builder.build().pipeline.names == ("opa", "prometheus")


@pytest.mark.asyncio
async def test_prometheus_middleware_records_failures_once_and_skips_non_terminal() -> None:
    registry = CollectorRegistry()
    middleware = PrometheusMiddleware(registry=registry, prefix="boundary")
    pending = _context()
    assert await middleware.process(pending) is pending

    failed = pending.append_history(
        HistoryEntry(
            "opa",
            "error",
            "dependency failed",
            data={"reason": "connection reset"},
        )
    ).evolve(
        status=ExecutionStatus.FAILED,
        metadata={"duration_ms": 125},
    )
    recorded = await middleware.process(failed)
    assert recorded.history[-1].middleware == "prometheus"
    assert await middleware.process(recorded) is recorded
    middleware.record_external_failure("slack", reason="timeout")
    metrics = generate_latest(registry).decode("utf-8")
    assert (
        'component="opa",outcome="error",reason="observer_failure"'
        in metrics
    )
    assert 'component="slack"' in metrics

    critical = ExecutionContext.create(ToolCall("critical")).append_history(
        HistoryEntry("audit", "critical_error", "critical observer failure")
    ).evolve(status=ExecutionStatus.UNKNOWN)
    await middleware.process(critical)
    metrics = generate_latest(registry).decode("utf-8")
    assert (
        'component="audit",outcome="critical_error",reason="observer_failure"'
        in metrics
    )
