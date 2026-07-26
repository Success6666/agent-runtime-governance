from __future__ import annotations

import asyncio
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from agent_runtime_governance import (
    GovernanceDenied,
    InvocationOptions,
    RiskTier,
    Runtime,
)
from agent_runtime_governance.approval_store import (
    ApprovalStatus,
    InMemoryApprovalStore,
    SQLiteApprovalStore,
)
from agent_runtime_governance.context import ExecutionContext, ToolCall
from agent_runtime_governance.decisions import (
    ApprovalRequest,
    DecisionOutcome,
    DecisionRecord,
    HumanDecisionProvider,
)
from agent_runtime_governance.identity import (
    HMACClaimsIdentityProvider,
    SQLiteIdentityReplayStore,
    StaticIdentityProvider,
    VerifiedPrincipal,
)
from agent_runtime_governance.middleware.decision import DecisionMiddleware

HMAC_KEY = "test-identity-key-32-bytes-long!!"
WRONG_HMAC_KEY = "wrong-identity-key-32-bytes-long!"


def make_request(**changes: object) -> ApprovalRequest:
    values = {
        "trace_id": "trace",
        "request_id": "request-1",
        "tool_name": "delete_file",
        "arguments": {"args": ["a.txt"], "kwargs": {"force": True}},
        "risk_tier": "HIGH",
        "reason": "needs approval",
        "policy_version": "policy-v1",
    }
    values.update(changes)
    return ApprovalRequest(**values)  # type: ignore[arg-type]


def identity_claims(**changes: object) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    values: dict[str, object] = {
        "issuer": "gateway",
        "audience": "agent-runtime",
        "subject": "alice",
        "tenant": "tenant-a",
        "permissions": ["admin"],
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + timedelta(minutes=2)).timestamp(),
        "jti": uuid4().hex,
    }
    values.update(changes)
    return values


def test_hmac_identity_claims_reject_tampering() -> None:
    claims = identity_claims(permissions=["admin", "ops"])
    envelope = HMACClaimsIdentityProvider.sign_claims(claims, HMAC_KEY)
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY, expected_issuer="gateway", expected_audience="agent-runtime"
    )

    principal = provider.verify(envelope)
    assert principal.subject == "alice"
    assert principal.permissions == frozenset({"admin", "ops"})

    tampered = {
        "kid": envelope["kid"],
        "claims": {**claims, "subject": "mallory"},
        "signature": envelope["signature"],
    }
    with pytest.raises(ValueError, match="signature"):
        provider.verify(tampered)


def test_decision_binding_rejects_wrong_request_or_arguments() -> None:
    request = make_request()
    decision = DecisionRecord(DecisionOutcome.ALLOW, "ok", "human").bind_to(request)
    assert decision.request_id == request.request_id
    assert decision.arguments_digest == request.arguments_digest

    with pytest.raises(ValueError, match="request_id mismatch"):
        DecisionRecord(
            DecisionOutcome.ALLOW,
            "wrong request",
            "human",
            request_id="other",
        ).bind_to(request)


def test_memory_store_consumes_once_and_rejects_tampered_arguments() -> None:
    store = InMemoryApprovalStore()
    request = make_request()
    store.pending(request)
    store.decide(request.request_id, DecisionRecord(DecisionOutcome.ALLOW, "ok", "human"))

    tampered = make_request(arguments={"args": ["b.txt"], "kwargs": {"force": True}})
    tampered_result = store.consume(tampered)
    assert tampered_result.outcome is DecisionOutcome.DENY
    assert "arguments mismatch" in tampered_result.reason

    first = store.consume(request)
    second = store.consume(request)
    assert first.outcome is DecisionOutcome.ALLOW
    assert second.outcome is DecisionOutcome.DENY
    assert "already consumed" in second.reason


def test_store_expired_request_defaults_to_deny() -> None:
    store = InMemoryApprovalStore()
    now = datetime.now(timezone.utc)
    request = make_request(
        issued_at=(now - timedelta(seconds=2)).isoformat(),
        expires_at=(now - timedelta(seconds=1)).isoformat(),
    )
    store.pending(request)
    with pytest.raises(ValueError, match="expired"):
        store.decide(
            request.request_id,
            DecisionRecord(DecisionOutcome.ALLOW, "ok", "human"),
        )

    decision = store.consume(request)
    assert decision.outcome is DecisionOutcome.DENY
    assert "expired" in decision.reason


def test_sqlite_store_recovers_pending_decision_after_restart(tmp_path) -> None:
    path = tmp_path / "approvals.db"
    request = make_request()
    store = SQLiteApprovalStore(path)
    store.pending(request)
    store.decide(request.request_id, DecisionRecord(DecisionOutcome.ALLOW, "ok", "human"))
    store.close()

    restored = SQLiteApprovalStore(path)
    assert restored.get(request.request_id).status is ApprovalStatus.DECIDED
    decision = restored.consume(request)
    assert decision.outcome is DecisionOutcome.ALLOW
    assert restored.get(request.request_id).status is ApprovalStatus.CONSUMED
    restored.close()


def test_decision_middleware_keeps_legacy_callback_compatible() -> None:
    runtime = Runtime(
        [DecisionMiddleware(HumanDecisionProvider(lambda context, request: True))]
    )

    @runtime.tool(risk=RiskTier.HIGH, requires_approval=True)
    def operate() -> str:
        return "ok"

    assert operate() == "ok"


def test_decision_middleware_denies_tampered_provider_record() -> None:
    runtime = Runtime(
        [
            DecisionMiddleware(
                HumanDecisionProvider(
                    lambda context, request: DecisionRecord(
                        DecisionOutcome.ALLOW,
                        "ok",
                        "human",
                        request_id="other-request",
                    )
                )
            )
        ]
    )

    @runtime.tool(risk=RiskTier.HIGH, requires_approval=True)
    def operate() -> str:
        return "ok"

    with pytest.raises(GovernanceDenied) as caught:
        operate()
    assert (
        caught.value.context.decision.reason
        == "decision provider returned an invalid decision"
    )


def test_decision_middleware_denies_provider_timeout() -> None:
    class SlowProvider:
        async def decide(self, context, request):
            await asyncio.sleep(0.05)
            return DecisionRecord(DecisionOutcome.ALLOW, "late", "human")

    runtime = Runtime([DecisionMiddleware(SlowProvider(), provider_timeout_seconds=0.01)])

    @runtime.tool(risk=RiskTier.HIGH, requires_approval=True)
    def operate() -> str:
        return "ok"

    with pytest.raises(GovernanceDenied) as caught:
        operate()
    assert "timed out" in caught.value.context.decision.reason


def test_runtime_validates_identity_once_before_decision_middleware() -> None:
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY, expected_issuer="gateway", expected_audience="agent-runtime"
    )
    runtime = Runtime(
        [DecisionMiddleware(HumanDecisionProvider(lambda context, request: True))],
        identity_provider=provider,
        require_verified_identity=True,
    )

    @runtime.tool(risk=RiskTier.HIGH, requires_approval=True)
    def operate() -> str:
        return "ok"

    assert (
        operate(
            _governance=InvocationOptions(
                identity_claims=HMACClaimsIdentityProvider.sign_claims(
                    identity_claims(), HMAC_KEY
                ),
            )
        )
        == "ok"
    )

    with pytest.raises(GovernanceDenied) as caught:
        operate(
            _governance=InvocationOptions(
                identity_claims=HMACClaimsIdentityProvider.sign_claims(
                    identity_claims(subject="mallory"), WRONG_HMAC_KEY
                ),
            )
        )
    assert caught.value.context.decision.reason == "identity verification failed"


def test_decision_middleware_can_consume_preapproved_sqlite_decision(tmp_path) -> None:
    store = SQLiteApprovalStore(tmp_path / "approvals.db")
    middleware = DecisionMiddleware(store=store)
    context = ExecutionContext.create(
        ToolCall("operate", ("x",), {}),
        risk_tier=RiskTier.HIGH,
        requires_approval=True,
    )
    request = make_request(
        trace_id=context.trace_id,
        request_id=context.request_id,
        tool_name="operate",
        arguments={"args": ["x"], "kwargs": {}},
        risk_tier=context.risk_tier.name,
        policy_version=None,
    )
    store.pending(request)
    store.decide(
        request.request_id,
        DecisionRecord(DecisionOutcome.ALLOW, "ok", "human", approver="operator"),
    )

    approved = asyncio.run(middleware.process(context))
    assert approved.metadata["approval_granted"] is True
    assert approved.decision.outcome is DecisionOutcome.ALLOW
    store.close()


def test_static_identity_provider_is_trusted_boundary_only() -> None:
    principal = VerifiedPrincipal(
        issuer="gateway",
        subject="alice",
        tenant="tenant-a",
        permissions=frozenset({"admin"}),
    )
    provider = StaticIdentityProvider(principal)
    assert provider.verify({"subject": "mallory"}) is principal


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"exp": 0}, "expired"),
        ({"nbf_offset_seconds": 60}, "not active"),
        ({"audience": "different-runtime"}, "audience"),
        ({"exp_offset_seconds": 600}, "lifetime"),
    ],
)
def test_hmac_identity_rejects_invalid_time_and_audience(
    changes: dict[str, object], message: str
) -> None:
    changes = dict(changes)
    now = datetime.now(timezone.utc)
    if "nbf_offset_seconds" in changes:
        changes["nbf"] = (
            now + timedelta(seconds=int(changes.pop("nbf_offset_seconds")))
        ).timestamp()
    if "exp_offset_seconds" in changes:
        changes["exp"] = (
            now + timedelta(seconds=int(changes.pop("exp_offset_seconds")))
        ).timestamp()
    claims = identity_claims(**changes)
    envelope = HMACClaimsIdentityProvider.sign_claims(claims, HMAC_KEY)
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY,
        expected_issuer="gateway",
        expected_audience="agent-runtime",
    )
    with pytest.raises(ValueError, match=message):
        provider.verify(envelope)


def test_hmac_identity_rejects_replay_and_supports_key_rotation(tmp_path) -> None:
    old_key = "old-identity-signing-key-32-bytes!!"
    new_key = "new-identity-signing-key-32-bytes!!"
    replay_path = tmp_path / "identity-replay.db"
    claims = identity_claims()
    envelope = HMACClaimsIdentityProvider.sign_claims(claims, old_key, kid="old")
    first = HMACClaimsIdentityProvider(
        {"old": old_key, "new": new_key},
        expected_issuer="gateway",
        expected_audience="agent-runtime",
        replay_store=SQLiteIdentityReplayStore(replay_path),
    )
    assert first.verify(envelope).subject == "alice"

    restarted = HMACClaimsIdentityProvider(
        {"old": old_key, "new": new_key},
        expected_issuer="gateway",
        expected_audience="agent-runtime",
        replay_store=SQLiteIdentityReplayStore(replay_path),
    )
    with pytest.raises(ValueError, match="already used"):
        restarted.verify(envelope)

    rotated = HMACClaimsIdentityProvider.sign_claims(
        identity_claims(), new_key, kid="new"
    )
    assert restarted.verify(rotated).subject == "alice"


def test_identity_replay_claim_survives_clock_skew_acceptance_window(
    tmp_path,
) -> None:
    now = datetime.now(timezone.utc)
    claims = identity_claims(
        iat=(now - timedelta(seconds=30)).timestamp(),
        nbf=(now - timedelta(seconds=30)).timestamp(),
        exp=(now - timedelta(seconds=1)).timestamp(),
    )
    envelope = HMACClaimsIdentityProvider.sign_claims(claims, HMAC_KEY)
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY,
        expected_issuer="gateway",
        expected_audience="agent-runtime",
        clock_skew_seconds=30.0,
        replay_store=SQLiteIdentityReplayStore(tmp_path / "clock-skew-replay.db"),
    )

    assert provider.verify(envelope).subject == "alice"
    with pytest.raises(ValueError, match="already used"):
        provider.verify(envelope)


def test_hmac_identity_enforces_key_and_claim_size_limits() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        HMACClaimsIdentityProvider(
            "weak",
            expected_issuer="gateway",
            expected_audience="agent-runtime",
        )

    envelope = HMACClaimsIdentityProvider.sign_claims(
        identity_claims(extra="x" * 2048), HMAC_KEY
    )
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY,
        expected_issuer="gateway",
        expected_audience="agent-runtime",
        max_claims_bytes=512,
    )
    with pytest.raises(ValueError, match="byte limit"):
        provider.verify(envelope)


def test_approval_decision_is_immutable_and_tenant_bound() -> None:
    store = InMemoryApprovalStore()
    request = make_request(
        subject="alice",
        tenant="tenant-a",
        identity_issuer="gateway",
    )
    store.pending(request)
    first = store.decide(
        request.request_id,
        DecisionRecord(DecisionOutcome.DENY, "no", "human", approver="operator"),
    )
    assert store.decide(request.request_id, first) == first
    with pytest.raises(ValueError, match="already has a decision"):
        store.decide(
            request.request_id,
            DecisionRecord(
                DecisionOutcome.ALLOW,
                "changed",
                "human",
                approver="operator",
            ),
        )

    cross_tenant = make_request(
        subject="alice",
        tenant="tenant-b",
        identity_issuer="gateway",
    )
    denied = store.consume(cross_tenant)
    assert denied.outcome is DecisionOutcome.DENY
    assert "tenant mismatch" in denied.reason


def test_approval_request_rejects_forged_arguments_digest() -> None:
    with pytest.raises(ValueError, match="does not match"):
        make_request(arguments_digest="a" * 64)


def test_sqlite_approval_redacts_secrets_and_detects_tampering(tmp_path) -> None:
    path = tmp_path / "approvals.db"
    signing_key = "approval-integrity-key-32-bytes!!"
    store = SQLiteApprovalStore(path, sign_key=signing_key)
    request = make_request(
        arguments={"args": [], "kwargs": {"token": "top-secret"}}
    )
    store.pending(request)
    assert b"top-secret" not in path.read_bytes()
    restored = store.get(request.request_id)
    assert restored is not None
    assert restored.request.arguments == {}
    assert restored.request.arguments_redacted is True

    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "UPDATE approvals SET status = 'consumed' WHERE request_id = ?",
                (request.request_id,),
            )
    with pytest.raises(ValueError, match="integrity"):
        store.get(request.request_id)


def test_persistent_approval_resumes_after_runtime_restart(tmp_path) -> None:
    path = tmp_path / "approvals.db"
    principal = VerifiedPrincipal(
        issuer="gateway",
        subject="alice",
        tenant="tenant-a",
        permissions=frozenset({"operate"}),
    )
    options = InvocationOptions(request_id="stable-approval-request")
    first_store = SQLiteApprovalStore(
        path,
        sign_key="approval-integrity-key-32-bytes!!",
    )
    first = Runtime(
        [DecisionMiddleware(store=first_store)],
        identity_provider=StaticIdentityProvider(principal),
        require_verified_identity=True,
    )

    @first.tool(name="operate", risk=RiskTier.HIGH, requires_approval=True)
    def first_operate() -> str:
        raise AssertionError("pending approval must not execute")

    with pytest.raises(GovernanceDenied):
        first_operate(_governance=options)
    first_store.decide(
        "stable-approval-request",
        DecisionRecord(
            DecisionOutcome.ALLOW,
            "approved",
            "human",
            approver="operator",
        ),
    )
    first.close()

    second_store = SQLiteApprovalStore(
        path,
        sign_key="approval-integrity-key-32-bytes!!",
    )
    restarted = Runtime(
        [DecisionMiddleware(store=second_store)],
        identity_provider=StaticIdentityProvider(principal),
        require_verified_identity=True,
    )

    @restarted.tool(name="operate", risk=RiskTier.HIGH, requires_approval=True)
    def restarted_operate() -> str:
        return "executed"

    assert restarted_operate(_governance=options) == "executed"
    assert (
        second_store.get("stable-approval-request").status
        is ApprovalStatus.CONSUMED
    )
    restarted.close()


def test_approval_is_not_consumed_when_pre_execute_hook_denies(tmp_path) -> None:
    path = tmp_path / "approvals.db"
    request_id = "approval-pre-execute-denial"
    options = InvocationOptions(request_id=request_id)
    store = SQLiteApprovalStore(path, sign_key=HMAC_KEY)

    first = Runtime([DecisionMiddleware(store=store)])

    @first.tool(name="operate", risk=RiskTier.HIGH, requires_approval=True)
    def pending_operate() -> None:
        raise AssertionError("pending approval must not execute")

    with pytest.raises(GovernanceDenied):
        pending_operate(_governance=options)
    store.decide(
        request_id,
        DecisionRecord(
            DecisionOutcome.ALLOW,
            "approved",
            "human",
            approver="operator",
        ),
    )

    guarded = Runtime([DecisionMiddleware(store=store)])

    @guarded.before_tool(critical=True)
    def maintenance_window(context):
        raise RuntimeError("maintenance window")

    @guarded.tool(name="operate", risk=RiskTier.HIGH, requires_approval=True)
    def guarded_operate() -> None:
        raise AssertionError("denied hook must prevent execution")

    with pytest.raises(GovernanceDenied, match="maintenance window"):
        guarded_operate(_governance=options)
    assert store.get(request_id).status is ApprovalStatus.DECIDED

    resumed = Runtime([DecisionMiddleware(store=store)])

    @resumed.tool(name="operate", risk=RiskTier.HIGH, requires_approval=True)
    def resumed_operate() -> str:
        return "executed"

    assert resumed_operate(_governance=options) == "executed"
    assert store.get(request_id).status is ApprovalStatus.CONSUMED


def test_sqlite_approval_lock_contention_fails_closed(tmp_path) -> None:
    path = tmp_path / "approval-lock.db"
    store = SQLiteApprovalStore(path, timeout_seconds=0.01)
    blocker: sqlite3.Connection | None = None
    calls: list[str] = []
    runtime = Runtime([DecisionMiddleware(store=store)])

    @runtime.tool(risk=RiskTier.HIGH, requires_approval=True)
    def operate() -> None:
        calls.append("executed")

    try:
        blocker = sqlite3.connect(path, timeout=0.01, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(GovernanceDenied, match="failed closed"):
            operate(_governance=InvocationOptions(request_id="locked-approval"))
    finally:
        if blocker is not None:
            blocker.rollback()
            blocker.close()
        runtime.close()
        store.close()
    assert calls == []


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_approval_reservation_commit_and_release_lifecycle(
    tmp_path, store_kind: str
) -> None:
    store = (
        InMemoryApprovalStore()
        if store_kind == "memory"
        else SQLiteApprovalStore(tmp_path / "reservation-lifecycle.db")
    )
    request = make_request(request_id=f"reservation-{store_kind}")
    store.pending(request)
    approved = store.decide(
        request.request_id,
        DecisionRecord(
            DecisionOutcome.ALLOW,
            "approved",
            "human",
            approver="operator",
        ),
    )

    first = store.reserve(request, lease_seconds=1)
    assert first.decision == approved
    assert first.token is not None
    blocked = store.reserve(request, lease_seconds=1)
    assert blocked.token is None
    assert blocked.decision.outcome is DecisionOutcome.DENY
    assert store.release(request.request_id, "wrong-token") is False
    assert store.release(request.request_id, first.token) is True

    second = store.reserve(request, lease_seconds=1)
    assert second.token is not None
    mismatch = store.commit(request, "wrong-token")
    assert mismatch.outcome is DecisionOutcome.DENY
    assert store.commit(request, second.token) == approved
    assert store.get(request.request_id).status is ApprovalStatus.CONSUMED


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_expired_approval_reservation_can_be_reclaimed(
    tmp_path, store_kind: str
) -> None:
    store = (
        InMemoryApprovalStore()
        if store_kind == "memory"
        else SQLiteApprovalStore(tmp_path / "reservation-expiry.db")
    )
    request = make_request(request_id=f"reservation-expiry-{store_kind}")
    store.pending(request)
    store.decide(
        request.request_id,
        DecisionRecord(
            DecisionOutcome.ALLOW,
            "approved",
            "human",
            approver="operator",
        ),
    )

    first = store.reserve(request, lease_seconds=0.001)
    assert first.token is not None
    time.sleep(0.01)
    second = store.reserve(request, lease_seconds=1)
    assert second.token is not None
    assert second.token != first.token
    assert store.commit(request, first.token).outcome is DecisionOutcome.DENY
    assert store.commit(request, second.token).outcome is DecisionOutcome.ALLOW
