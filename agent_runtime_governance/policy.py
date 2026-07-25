from __future__ import annotations

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

    def __init__(self, policy: SimplePolicy) -> None:
        self.policy = policy

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        tool = context.tool_call.name
        if tool in self.policy.denied_tools:
            return self._deny(context, "tool denied by policy")
        if tool in self.policy.admin_only and "admin" not in context.permissions:
            return self._deny(context, "admin permission required")
        required = self.policy.required_permissions.get(tool, frozenset())
        missing = required.difference(context.permissions)
        if missing:
            return self._deny(
                context, f"missing permissions: {', '.join(sorted(missing))}"
            )
        changes: dict[str, object] = {}
        if tool in self.policy.approval_tools:
            changes["requires_approval"] = True
        if tool in self.policy.risk_overrides:
            changes["risk_tier"] = self.policy.risk_overrides[tool]
        updated = context.evolve(**changes) if changes else context
        return updated.append_history(
            HistoryEntry(self.name, "allow", "python policy allowed")
        )

    def _deny(self, context: ExecutionContext, reason: str) -> ExecutionContext:
        return context.with_decision(
            DecisionRecord(DecisionOutcome.DENY, reason, self.name)
        ).append_history(HistoryEntry(self.name, "deny", reason))
