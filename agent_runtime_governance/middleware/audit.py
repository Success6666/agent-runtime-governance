from __future__ import annotations

from ..audit import AuditSink, context_event
from ..context import ExecutionContext, HistoryEntry
from .base import ObservingMiddleware


class AuditMiddleware(ObservingMiddleware):
    name = "audit"

    def __init__(self, sink: AuditSink) -> None:
        self.sink = sink

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        stage = "completed" if context.status.value in {"succeeded", "failed"} else "decision"
        if any(
            entry.middleware == self.name and entry.data.get("stage") == stage
            for entry in context.history
        ):
            return context
        updated = context.append_history(
            HistoryEntry(
                self.name,
                "record",
                f"recorded {stage} snapshot",
                data={"stage": stage},
            )
        )
        self.sink.write(context_event(updated, stage=stage))
        return updated
