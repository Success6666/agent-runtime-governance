from __future__ import annotations

import pytest

from agent_runtime_governance import (
    GovernanceDenied,
    InvocationOptions,
    PolicyValidationError,
    RiskTier,
    Runtime,
    YAMLPolicyLoader,
)


VALID_POLICY = """
version: "1"
policies:
  - tool: restart
    effect: allow
    approval: required
    admin_only: true
    required_permissions: [service:write]
    risk: high
  - tool: wipe
    effect: deny
    risk: critical
"""


def test_yaml_policy_loads_valid_document() -> None:
    document = YAMLPolicyLoader.loads(VALID_POLICY)
    assert document.version == "1"
    assert len(document.digest) == 64
    assert document.policy.risk_overrides["restart"] is RiskTier.HIGH
    assert "wipe" in document.policy.denied_tools


def test_policy_digest_is_independent_of_entry_order() -> None:
    first = YAMLPolicyLoader.loads(VALID_POLICY)
    reversed_entries = """
version: "1"
policies:
  - tool: wipe
    effect: deny
    risk: critical
  - tool: restart
    admin_only: true
    required_permissions: [service:write]
    risk: high
    approval: required
"""
    assert YAMLPolicyLoader.loads(reversed_entries).digest == first.digest


def test_duplicate_tool_policy_is_rejected() -> None:
    with pytest.raises(PolicyValidationError, match="duplicate"):
        YAMLPolicyLoader.loads(
            "version: 1\npolicies:\n  - tool: x\n  - tool: x\n"
        )


def test_unknown_policy_key_is_rejected() -> None:
    with pytest.raises(PolicyValidationError, match="unknown"):
        YAMLPolicyLoader.loads(
            "version: 1\npolicies:\n  - tool: x\n    working_hours: always\n"
        )


def test_unsafe_yaml_tag_is_rejected() -> None:
    with pytest.raises(PolicyValidationError, match="invalid YAML"):
        YAMLPolicyLoader.loads(
            "!!python/object/apply:os.system ['echo unsafe']"
        )


def test_invalid_risk_is_rejected() -> None:
    with pytest.raises(PolicyValidationError, match="invalid risk"):
        YAMLPolicyLoader.loads(
            "version: 1\npolicies:\n  - tool: x\n    risk: extreme\n"
        )


def test_denied_policy_retains_risk_override() -> None:
    document = YAMLPolicyLoader.loads(
        "version: 1\npolicies:\n  - tool: wipe\n    effect: deny\n    risk: critical\n"
    )
    runtime = Runtime([document.middleware()])

    @runtime.tool()
    def wipe() -> None:
        return None

    with pytest.raises(GovernanceDenied) as caught:
        wipe()
    assert caught.value.context.risk_tier is RiskTier.CRITICAL


@pytest.mark.asyncio
async def test_versioned_policy_is_attached_to_context() -> None:
    document = YAMLPolicyLoader.loads(
        "version: 7\npolicies:\n  - tool: read\n    risk: medium\n"
    )
    runtime = Runtime([document.middleware()])

    @runtime.tool()
    def read() -> bool:
        return True

    context = await runtime.apreview("read")
    assert context.metadata["policy_version"] == "7"
    assert context.metadata["policy_digest"] == document.digest


def test_yaml_approval_fails_closed_without_provider() -> None:
    document = YAMLPolicyLoader.loads(
        "version: 1\npolicies:\n  - tool: restart\n    approval: required\n"
    )
    runtime = Runtime([document.middleware()])

    @runtime.tool()
    def restart() -> bool:
        return True

    with pytest.raises(GovernanceDenied, match="not granted"):
        restart()


def test_yaml_permissions_are_enforced() -> None:
    document = YAMLPolicyLoader.loads(
        "version: 1\npolicies:\n  - tool: read\n    required_permissions: [file:read]\n"
    )
    runtime = Runtime([document.middleware()])

    @runtime.tool()
    def read() -> bool:
        return True

    with pytest.raises(GovernanceDenied):
        read()
    assert runtime.invoke(
        "read",
        _governance=InvocationOptions(permissions=frozenset({"file:read"})),
    ) is True
