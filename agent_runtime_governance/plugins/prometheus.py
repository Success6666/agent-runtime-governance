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
        self.decisions = Counter(
            f"{prefix}_governance_decisions_total",
            "Runtime governance decisions with low-cardinality labels.",
            ("status", "risk_tier", "source"),
            registry=target_registry,
        )
        self.external_failures = Counter(
            f"{prefix}_external_failures_total",
            "External governance integration failures.",
            ("component", "outcome", "reason"),
            registry=target_registry,
        )

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if context.status not in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.DENIED,
            ExecutionStatus.UNKNOWN,
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
        source = context.decision.source if context.decision else "runtime"
        self.decisions.labels(
            context.status.value, context.risk_tier.name, _safe_label(source)
        ).inc()
        self._record_external_failures(context)
        duration_ms = context.metadata.get("duration_ms")
        if isinstance(duration_ms, int | float):
            self.duration.labels(
                context.tool_call.name, context.status.value
            ).observe(float(duration_ms) / 1000)
        return context.append_history(
            HistoryEntry(self.name, "record", "prometheus metrics recorded")
        )

    def record_external_failure(
        self, component: str, *, outcome: str = "error", reason: str = "unknown"
    ) -> None:
        self.external_failures.labels(
            _safe_label(component), _safe_label(outcome), _safe_label(reason)
        ).inc()

    def _record_external_failures(self, context: ExecutionContext) -> None:
        for entry in context.history:
            if entry.outcome not in {"error", "critical_error"}:
                continue
            component = _safe_label(entry.middleware)
            self.external_failures.labels(
                component,
                _safe_label(entry.outcome),
                "observer_failure",
            ).inc()


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


def _safe_label(value: str) -> str:
    cleaned = "_".join(str(value).strip().lower().split())[:64]
    return cleaned or "unknown"
