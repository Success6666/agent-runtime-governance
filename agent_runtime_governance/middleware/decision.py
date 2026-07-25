from __future__ import annotations

from ..context import ExecutionContext, HistoryEntry
from ..decisions import ApprovalRequest, DecisionOutcome, DecisionProvider
from .base import GatingMiddleware


class DecisionMiddleware(GatingMiddleware):
    name = "decision"

    def __init__(self, provider: DecisionProvider) -> None:
        self._provider = provider

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if not context.requires_approval:
            return context.append_history(
                HistoryEntry(self.name, "skip", "human decision not required")
            )
        request = ApprovalRequest(
            trace_id=context.trace_id,
            tool_name=context.tool_call.name,
            arguments={
                "args": list(context.tool_call.args),
                "kwargs": dict(context.tool_call.kwargs),
            },
            risk_tier=context.risk_tier.name,
            reason="tool requires human decision",
        )
        decision = await self._provider.decide(context, request)
        if decision.outcome is DecisionOutcome.REQUIRE_HUMAN:
            raise ValueError("human decision provider must return allow or deny")
        return context.with_decision(decision).append_history(
            HistoryEntry(self.name, decision.outcome.value, decision.reason)
        )


ApprovalMiddleware = DecisionMiddleware

