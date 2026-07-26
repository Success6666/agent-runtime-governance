from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from agent_runtime_governance.context import RiskTier
from agent_runtime_governance.errors import GovernanceDenied
from agent_runtime_governance.identity import (
    HMACClaimsIdentityProvider,
    StaticIdentityProvider,
    VerifiedPrincipal,
)
from agent_runtime_governance.runtime import InvocationOptions, Runtime

HMAC_KEY = "test-identity-key-32-bytes-long!!"
WRONG_HMAC_KEY = "wrong-identity-key-32-bytes-long!"


@pytest.fixture(autouse=True)
def close_created_runtimes(monkeypatch):
    runtime_type = Runtime
    created: list[Runtime] = []

    def factory(*args, **kwargs):
        runtime = runtime_type(*args, **kwargs)
        created.append(runtime)
        return runtime

    monkeypatch.setitem(globals(), "Runtime", factory)
    yield
    for runtime in reversed(created):
        runtime.close()


def register_tool(runtime: Runtime, calls: list[str]):
    @runtime.tool(risk=RiskTier.HIGH)
    def operate() -> str:
        calls.append("executed")
        return "ok"

    return operate


def signed_claims(**changes):
    now = datetime.now(timezone.utc)
    claims = {
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
    claims.update(changes)
    return HMACClaimsIdentityProvider.sign_claims(claims, HMAC_KEY)


@pytest.mark.asyncio
async def test_verified_principal_overrides_untrusted_invocation_identity() -> None:
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY, expected_issuer="gateway", expected_audience="agent-runtime"
    )
    runtime = Runtime(identity_provider=provider, require_verified_identity=True)
    calls: list[str] = []
    register_tool(runtime, calls)

    result = await runtime.arun(
        "operate",
        _governance=InvocationOptions(
            user="mallory",
            tenant="tenant-b",
            permissions=frozenset({"admin"}),
            identity_claims=signed_claims(),
        ),
    )

    assert result.value == "ok"
    assert calls == ["executed"]
    assert result.context.user == "alice"
    assert result.context.tenant == "tenant-a"
    assert result.context.permissions == frozenset({"file:write"})
    assert result.context.metadata["identity_verified"] is True
    assert result.context.metadata["identity_source"] == "hmac"


def test_strict_mode_without_identity_fails_closed_before_execution() -> None:
    runtime = Runtime(require_verified_identity=True)
    calls: list[str] = []
    operate = register_tool(runtime, calls)

    with pytest.raises(GovernanceDenied) as caught:
        operate(
            _governance=InvocationOptions(
                user="mallory",
                tenant="tenant-b",
                permissions=frozenset({"admin"}),
            )
        )

    context = caught.value.context
    assert calls == []
    assert context.user is None
    assert context.tenant is None
    assert context.permissions == frozenset()
    assert context.decision.source == "identity"
    assert context.metadata["identity_verified"] is False
    assert context.history[0].middleware == "identity"
    assert context.history[0].outcome == "deny"


def test_invalid_supplied_claims_fail_closed_even_in_compatibility_mode() -> None:
    provider = HMACClaimsIdentityProvider(
        HMAC_KEY, expected_issuer="gateway", expected_audience="agent-runtime"
    )
    runtime = Runtime(identity_provider=provider)
    calls: list[str] = []
    operate = register_tool(runtime, calls)
    now = datetime.now(timezone.utc)
    envelope = HMACClaimsIdentityProvider.sign_claims(
        {
            "issuer": "gateway", "audience": "agent-runtime",
            "subject": "alice", "tenant": "tenant-a", "permissions": ["read"],
            "iat": now.timestamp(), "nbf": now.timestamp(),
            "exp": (now + timedelta(minutes=2)).timestamp(), "jti": uuid4().hex,
        }, WRONG_HMAC_KEY
    )

    with pytest.raises(GovernanceDenied) as caught:
        operate(_governance=InvocationOptions(identity_claims=envelope))

    assert calls == []
    assert caught.value.context.decision.reason == "identity verification failed"


@pytest.mark.asyncio
async def test_static_provider_supplies_identity_without_claims() -> None:
    principal = VerifiedPrincipal(
        issuer="trusted-gateway",
        subject="service-account",
        tenant="tenant-a",
        permissions=frozenset({"operate"}),
        source="static",
    )
    runtime = Runtime(
        identity_provider=StaticIdentityProvider(principal),
        require_verified_identity=True,
    )
    calls: list[str] = []
    register_tool(runtime, calls)

    result = await runtime.arun("operate")

    assert result.context.user == "service-account"
    assert result.context.tenant == "tenant-a"
    assert result.context.permissions == frozenset({"operate"})


@pytest.mark.asyncio
async def test_legacy_identity_remains_available_without_strict_mode() -> None:
    runtime = Runtime()
    calls: list[str] = []
    register_tool(runtime, calls)

    result = await runtime.arun(
        "operate",
        _governance=InvocationOptions(
            user="legacy-user",
            tenant="legacy-tenant",
            permissions=frozenset({"legacy"}),
        ),
    )

    assert result.context.user == "legacy-user"
    assert result.context.tenant == "legacy-tenant"
    assert result.context.permissions == frozenset({"legacy"})
    assert "identity_verified" not in result.context.metadata


@pytest.mark.asyncio
async def test_untrusted_metadata_cannot_forge_verified_identity_fields() -> None:
    runtime = Runtime()
    calls: list[str] = []
    register_tool(runtime, calls)

    result = await runtime.arun(
        "operate",
        _governance=InvocationOptions(
            metadata={
                "identity_verified": True,
                "identity_issuer": "forged",
                "identity_source": "forged",
                "safe": "kept",
            }
        ),
    )

    assert "identity_verified" not in result.context.metadata
    assert "identity_issuer" not in result.context.metadata
    assert "identity_source" not in result.context.metadata
    assert result.context.metadata["safe"] == "kept"


def test_invalid_provider_result_fails_closed() -> None:
    class InvalidProvider:
        def verify(self, claims):
            return {"subject": "forged"}

    runtime = Runtime(identity_provider=InvalidProvider())
    calls: list[str] = []
    operate = register_tool(runtime, calls)

    with pytest.raises(GovernanceDenied) as caught:
        operate(_governance=InvocationOptions(identity_claims={"token": "value"}))

    assert calls == []
    assert "invalid principal" in caught.value.context.decision.reason


def test_identity_replay_store_failure_fails_closed() -> None:
    class FailingReplayStore:
        def claim(self, issuer, jti, expires_at):
            raise OSError("identity replay database unavailable")

    provider = HMACClaimsIdentityProvider(
        HMAC_KEY,
        expected_issuer="gateway",
        expected_audience="agent-runtime",
        replay_store=FailingReplayStore(),
    )
    runtime = Runtime(identity_provider=provider, require_verified_identity=True)
    calls: list[str] = []
    operate = register_tool(runtime, calls)

    with pytest.raises(GovernanceDenied, match="identity verification failed"):
        operate(_governance=InvocationOptions(identity_claims=signed_claims()))
    assert calls == []


def test_provider_failure_without_claims_cannot_fall_back_to_caller_identity() -> None:
    class FailingProvider:
        def verify(self, claims):
            raise OSError("identity service unavailable")

    runtime = Runtime(identity_provider=FailingProvider())
    calls: list[str] = []
    operate = register_tool(runtime, calls)

    with pytest.raises(GovernanceDenied, match="identity verification failed") as caught:
        operate(
            _governance=InvocationOptions(
                user="caller-asserted",
                tenant="untrusted",
                permissions=frozenset({"admin"}),
            )
        )

    assert calls == []
    assert caught.value.context.user is None
    assert caught.value.context.permissions == frozenset()
    assert caught.value.context.metadata["identity_verified"] is False
