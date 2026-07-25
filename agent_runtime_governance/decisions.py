from __future__ import annotations

import inspect
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Protocol, TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from .context import ExecutionContext


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_HUMAN = "require_human"


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    outcome: DecisionOutcome
    reason: str
    source: str


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    trace_id: str
    tool_name: str
    arguments: dict[str, object]
    risk_tier: str
    reason: str


class DecisionProvider(Protocol):
    async def decide(
        self, context: "ExecutionContext", request: ApprovalRequest
    ) -> DecisionRecord: ...


DecisionCallbackResult: TypeAlias = DecisionRecord | DecisionOutcome | bool
DecisionCallback: TypeAlias = Callable[
    ["ExecutionContext", ApprovalRequest],
    DecisionCallbackResult | Awaitable[DecisionCallbackResult],
]


class HumanDecisionProvider:
    """Delegates a decision to a user-supplied CLI, chat, or HTTP callback."""

    def __init__(self, callback: DecisionCallback) -> None:
        self._callback = callback

    async def decide(
        self, context: "ExecutionContext", request: ApprovalRequest
    ) -> DecisionRecord:
        value = self._callback(context, request)
        if inspect.isawaitable(value):
            value = await value
        if isinstance(value, DecisionRecord):
            return value
        if isinstance(value, bool):
            outcome = DecisionOutcome.ALLOW if value else DecisionOutcome.DENY
        elif isinstance(value, DecisionOutcome):
            outcome = value
        else:
            raise TypeError("decision callback must return bool, DecisionOutcome, or DecisionRecord")
        return DecisionRecord(
            outcome=outcome,
            reason="human decision",
            source="human",
        )

