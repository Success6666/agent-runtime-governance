from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass
from typing import Mapping

from ..context import ExecutionContext, HistoryEntry
from .base import ObservingMiddleware


@dataclass(frozen=True, slots=True)
class MetricsSnapshot:
    counters: Mapping[str, int]
    total_duration_ms: float


class InMemoryMetrics:
    def __init__(self) -> None:
        self._counters: Counter[str] = Counter()
        self._total_duration_ms = 0.0
        self._lock = threading.Lock()

    def record(self, context: ExecutionContext) -> None:
        with self._lock:
            self._counters[f"status.{context.status.value}"] += 1
            self._counters[f"tool.{context.tool_call.name}.{context.status.value}"] += 1
            if context.denied and context.decision:
                self._counters[f"denied.{context.decision.source}"] += 1
            duration = context.metadata.get("duration_ms")
            if isinstance(duration, int | float):
                self._total_duration_ms += float(duration)

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            return MetricsSnapshot(dict(self._counters), self._total_duration_ms)


class MetricsMiddleware(ObservingMiddleware):
    name = "metrics"
    priority = 900

    def __init__(self, collector: InMemoryMetrics | None = None) -> None:
        self.collector = collector or InMemoryMetrics()

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if any(
            entry.middleware == self.name and entry.outcome == context.status.value
            for entry in context.history
        ):
            return context
        self.collector.record(context)
        return context.append_history(
            HistoryEntry(self.name, context.status.value, "metrics recorded")
        )
