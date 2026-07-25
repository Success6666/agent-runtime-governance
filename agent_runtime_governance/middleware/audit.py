from __future__ import annotations

import asyncio

from ..audit import AuditSink, context_event
from ..context import ExecutionContext, ExecutionStatus, HistoryEntry, RiskTier
from .base import ObservingMiddleware


class AuditMiddleware(ObservingMiddleware):
    name = "audit"
    replayable = False

    def __init__(
        self,
        sink: AuditSink,
        *,
        critical: bool = False,
        fail_closed: bool | None = None,
        critical_tiers: frozenset[RiskTier] = frozenset({RiskTier.CRITICAL}),
    ) -> None:
        self.sink = sink
        self.critical = critical or bool(fail_closed)
        self.fail_closed = self.critical if fail_closed is None else fail_closed
        self.critical_tiers = frozenset(critical_tiers)

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        stage = (
            "completed"
            if context.status in {
                ExecutionStatus.SUCCEEDED,
                ExecutionStatus.FAILED,
                ExecutionStatus.DENIED,
                ExecutionStatus.UNKNOWN,
            }
            else "decision"
        )
        if any(
            entry.middleware == self.name
            and entry.outcome == "record"
            and entry.data.get("stage") == stage
            for entry in context.history
        ):
            return context
        updated = context.append_history(
            HistoryEntry(
                self.name,
                "record",
                f"recorded {stage} snapshot",
                data={
                    "stage": stage,
                    "critical": self.is_critical(context),
                },
            )
        )
        try:
            await asyncio.to_thread(
                self.sink.write, context_event(updated, stage=stage)
            )
        except Exception:
            if self.fail_closed or self.is_critical(context):
                raise
            return context.append_history(
                HistoryEntry(
                    self.name,
                    "error",
                    f"non-critical audit write failed for {stage}",
                    data={"stage": stage},
                )
            )
        return updated

    def is_critical(self, context: ExecutionContext) -> bool:
        return self.critical or context.risk_tier in self.critical_tiers
