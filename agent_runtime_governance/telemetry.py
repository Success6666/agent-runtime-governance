from __future__ import annotations

import threading
from typing import Any, Protocol

from .context import ExecutionContext, ExecutionStatus, HistoryEntry
from .middleware.base import ObservingMiddleware


class Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None: ...
    def end(self) -> None: ...


class Tracer(Protocol):
    def start_span(self, name: str, *, attributes: dict[str, Any]) -> Span: ...


class OpenTelemetryMiddleware(ObservingMiddleware):
    """Exports runtime lifecycle data through an injected or global OTel tracer."""

    name = "opentelemetry"
    priority = 950
    replayable = False

    def __init__(self, tracer: Tracer | None = None) -> None:
        if tracer is None:
            try:
                from opentelemetry import trace
            except ImportError as exc:
                raise RuntimeError(
                    "install agent-runtime-governance[otel] to enable OpenTelemetry"
                ) from exc
            tracer = trace.get_tracer("agent_runtime_governance")
        self._tracer = tracer
        self._spans: dict[str, Span] = {}
        self._lock = threading.Lock()

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if any(
            entry.middleware == self.name and entry.outcome == context.status.value
            for entry in context.history
        ):
            return context
        with self._lock:
            span = self._spans.get(context.trace_id)
            if span is None:
                span = self._tracer.start_span(
                    f"tool.{context.tool_call.name}",
                    attributes={
                        "arg.trace_id": context.trace_id,
                        "arg.span_id": context.span_id,
                        "arg.request_id": context.request_id,
                        "arg.tool.name": context.tool_call.name,
                        "arg.risk.tier": context.risk_tier.name,
                    },
                )
                self._spans[context.trace_id] = span
            span.set_attribute("arg.status", context.status.value)
            span.set_attribute("arg.risk.score", context.risk_score)
            if context.decision:
                span.set_attribute("arg.decision", context.decision.outcome.value)
            if context.error:
                span.set_attribute("arg.error", context.error)
            if context.status in {
                ExecutionStatus.SUCCEEDED,
                ExecutionStatus.FAILED,
                ExecutionStatus.DENIED,
            }:
                span.end()
                self._spans.pop(context.trace_id, None)
        return context.append_history(
            HistoryEntry(self.name, context.status.value, "telemetry exported")
        )
