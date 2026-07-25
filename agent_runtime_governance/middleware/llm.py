from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Awaitable, Callable, TypeAlias

from ..context import ExecutionContext, HistoryEntry
from ..decisions import DecisionOutcome, DecisionRecord
from .base import GatingMiddleware


@dataclass(frozen=True, slots=True)
class SemanticReview:
    outcome: DecisionOutcome
    reason: str
    risk_score: float | None = None


ReviewerResult: TypeAlias = SemanticReview | DecisionOutcome | bool
Reviewer: TypeAlias = Callable[
    [ExecutionContext], ReviewerResult | Awaitable[ReviewerResult]
]


class LLMMiddleware(GatingMiddleware):
    """Model-agnostic semantic review delegated to an application callback."""

    name = "llm"
    replayable = False

    def __init__(self, reviewer: Reviewer) -> None:
        self._reviewer = reviewer

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        value = self._reviewer(context)
        if inspect.isawaitable(value):
            value = await value
        if isinstance(value, SemanticReview):
            review = value
        elif isinstance(value, bool):
            review = SemanticReview(
                DecisionOutcome.ALLOW if value else DecisionOutcome.DENY,
                "semantic reviewer result",
            )
        elif isinstance(value, DecisionOutcome):
            review = SemanticReview(value, "semantic reviewer result")
        else:
            raise TypeError("reviewer must return bool, DecisionOutcome, or SemanticReview")

        updated = context
        if review.risk_score is not None:
            updated = updated.evolve(risk_score=review.risk_score)
        if review.outcome is DecisionOutcome.DENY:
            updated = updated.with_decision(
                DecisionRecord(review.outcome, review.reason, self.name)
            )
        elif review.outcome is DecisionOutcome.REQUIRE_HUMAN:
            updated = updated.evolve(requires_approval=True)
        return updated.append_history(
            HistoryEntry(self.name, review.outcome.value, review.reason)
        )
