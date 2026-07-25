from __future__ import annotations

from typing import Any

from ..context import ExecutionContext, ExecutionStatus, HistoryEntry
from ..middleware.base import ObservingMiddleware
from .core import RuntimeBuilder


class PrometheusMiddleware(ObservingMiddleware):
    name = "prometheus"
    priority = 960
    replayable = False

    def __init__(self, *, registry: Any = None, prefix: str = "arg") -> None:
        try:
            from prometheus_client import REGISTRY, Counter, Histogram
        except ImportError as exc:
            raise RuntimeError(
                "install agent-runtime-governance[prometheus] to enable metrics"
            ) from exc
        target_registry = registry or REGISTRY
        self.calls = Counter(
            f"{prefix}_tool_calls_total",
            "Governed tool calls by terminal status.",
            ("tool", "status", "risk_tier"),
            registry=target_registry,
        )
        self.duration = Histogram(
            f"{prefix}_tool_duration_seconds",
            "Governed tool execution duration.",
            ("tool", "status"),
            registry=target_registry,
        )

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if context.status not in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.DENIED,
        }:
            return context
        if any(entry.middleware == self.name for entry in context.history):
            return context
        labels = (
            context.tool_call.name,
            context.status.value,
            context.risk_tier.name,
        )
        self.calls.labels(*labels).inc()
        duration_ms = context.metadata.get("duration_ms")
        if isinstance(duration_ms, int | float):
            self.duration.labels(
                context.tool_call.name, context.status.value
            ).observe(float(duration_ms) / 1000)
        return context.append_history(
            HistoryEntry(self.name, "record", "prometheus metrics recorded")
        )


class PrometheusPlugin:
    name = "prometheus"
    version = "1"

    def __init__(self, *, registry: Any = None, prefix: str = "arg") -> None:
        self.registry = registry
        self.prefix = prefix

    def register(self, builder: RuntimeBuilder) -> None:
        middleware = PrometheusMiddleware(
            registry=self.registry, prefix=self.prefix
        )
        builder.add_middleware(middleware)
        builder.add_service("prometheus", middleware)

