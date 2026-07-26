from __future__ import annotations

import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .context import ExecutionContext, HistoryEntry, RiskTier
from .decisions import DecisionOutcome, DecisionRecord
from .middleware.base import GatingMiddleware


@dataclass(frozen=True, slots=True)
class SimplePolicy:
    """Small Python policy model; deliberately not a policy language."""

    denied_tools: frozenset[str] = frozenset()
    approval_tools: frozenset[str] = frozenset()
    admin_only: frozenset[str] = frozenset()
    required_permissions: Mapping[str, frozenset[str]] = field(default_factory=dict)
    risk_overrides: Mapping[str, RiskTier] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "denied_tools", frozenset(self.denied_tools))
        object.__setattr__(self, "approval_tools", frozenset(self.approval_tools))
        object.__setattr__(self, "admin_only", frozenset(self.admin_only))
        object.__setattr__(
            self,
            "required_permissions",
            MappingProxyType(
                {name: frozenset(values) for name, values in self.required_permissions.items()}
            ),
        )
        object.__setattr__(
            self, "risk_overrides", MappingProxyType(dict(self.risk_overrides))
        )


class PolicyMiddleware(GatingMiddleware):
    name = "policy"
    priority = 20
    requires_action_policy_identity = True

    def __init__(
        self,
        policy: SimplePolicy,
        *,
        version: str | None = None,
        digest: str | None = None,
    ) -> None:
        if (version is None) != (digest is None):
            raise ValueError("policy version and digest must be provided together")
        if version is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}", version
        ):
            raise ValueError("policy version is invalid")
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("policy digest must be a SHA-256 hex digest")
        self.policy = policy
        self.version = version
        self.digest = digest

    def action_policy_identity(self) -> tuple[str, str] | None:
        if self.version is None or self.digest is None:
            return None
        return self.version, self.digest

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        tool = context.tool_call.name
        policy_metadata = {
            key: value
            for key, value in {
                "policy_version": self.version,
                "policy_digest": self.digest,
            }.items()
            if value is not None
        }
        if policy_metadata:
            context = context.evolve(
                metadata={**context.metadata, **policy_metadata}
            )
        changes: dict[str, object] = {}
        if tool in self.policy.approval_tools:
            changes["requires_approval"] = True
        if tool in self.policy.risk_overrides:
            changes["risk_tier"] = self.policy.risk_overrides[tool]
        updated = context.evolve(**changes) if changes else context
        if tool in self.policy.denied_tools:
            return self._deny(updated, "tool denied by policy")
        if tool in self.policy.admin_only and "admin" not in updated.permissions:
            return self._deny(updated, "admin permission required")
        required = self.policy.required_permissions.get(tool, frozenset())
        missing = required.difference(updated.permissions)
        if missing:
            return self._deny(
                updated, f"missing permissions: {', '.join(sorted(missing))}"
            )
        return updated.append_history(
            HistoryEntry(
                self.name,
                "allow",
                "python policy allowed",
                data=policy_metadata,
            )
        )

    def _deny(self, context: ExecutionContext, reason: str) -> ExecutionContext:
        return context.with_decision(
            DecisionRecord(DecisionOutcome.DENY, reason, self.name)
        ).append_history(
            HistoryEntry(
                self.name,
                "deny",
                reason,
                data={
                    key: value
                    for key, value in {
                        "policy_version": self.version,
                        "policy_digest": self.digest,
                    }.items()
                    if value is not None
                },
            )
        )
