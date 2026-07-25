from __future__ import annotations

import threading
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from typing import Any, Protocol

from .context import ExecutionContext, ExecutionStatus, HistoryEntry
from .middleware.base import ObservingMiddleware


class Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None: ...
    def end(self) -> None: ...


class Tracer(Protocol):
    def start_span(self, name: str, *, attributes: dict[str, Any]) -> Span: ...


@dataclass(slots=True)
class _SpanHandle:
    span: Span
    manager: Any = None
    ended: bool = False

    def finish(self, context: ExecutionContext) -> None:
        if self.ended:
            return
        _set_span_terminal_state(self.span, context)
        if self.manager is not None:
            self.manager.__exit__(None, None, None)
        else:
            self.span.end()
        self.ended = True

    def abort(self, description: str) -> None:
        if self.ended:
            return
        _record_exception(self.span, RuntimeError(description))
        _set_status(self.span, "ERROR", description)
        if self.manager is not None:
            self.manager.__exit__(None, None, None)
        else:
            self.span.end()
        self.ended = True


class OpenTelemetryMiddleware(ObservingMiddleware):
    """Exports runtime lifecycle data through an injected or global OTel tracer."""

    name = "opentelemetry"
    priority = 950
    replayable = False

    def __init__(self, tracer: Tracer | None = None, *, parent_context: Any = None) -> None:
        self._status_cls = None
        self._status_code_cls = None
        if tracer is None:
            try:
                from opentelemetry import trace
                from opentelemetry.trace import Status, StatusCode
            except ImportError as exc:
                raise RuntimeError(
                    "install agent-runtime-governance[otel] to enable OpenTelemetry"
                ) from exc
            tracer = trace.get_tracer("agent_runtime_governance")
            self._status_cls = Status
            self._status_code_cls = StatusCode
        else:
            try:
                from opentelemetry.trace import Status, StatusCode
            except ImportError:
                Status = StatusCode = None  # type: ignore[assignment]
            self._status_cls = Status
            self._status_code_cls = StatusCode
        self._tracer = tracer
        self._parent_context = parent_context
        self._spans: dict[str, _SpanHandle] = {}
        self._lock = threading.Lock()

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if any(
            entry.middleware == self.name and entry.outcome == context.status.value
            for entry in context.history
        ):
            return context
        with self._lock:
            handle = self._spans.get(context.trace_id)
            if handle is None:
                handle = self._start_span(context)
                self._spans[context.trace_id] = handle
        _set_span_attribute(handle.span, "arg.status", context.status.value)
        _set_span_attribute(handle.span, "arg.risk.score", context.risk_score)
        if context.decision:
            _set_span_attribute(
                handle.span, "arg.decision", context.decision.outcome.value
            )
            _set_span_attribute(
                handle.span, "arg.decision.source", context.decision.source
            )
        if context.status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.DENIED,
            ExecutionStatus.UNKNOWN,
        }:
            self.finish(context)
        return context.append_history(
            HistoryEntry(self.name, context.status.value, "telemetry exported")
        )

    def finish(self, context: ExecutionContext) -> bool:
        """Finish and forget the active span for a terminal context."""

        with self._lock:
            handle = self._spans.pop(context.trace_id, None)
        if handle is None:
            return False
        handle.finish(context)
        return True

    def abort(
        self,
        trace_id: str,
        *,
        description: str = "runtime pipeline cancelled",
    ) -> bool:
        """Abort an active span when execution cannot produce a terminal context."""

        with self._lock:
            handle = self._spans.pop(trace_id, None)
        if handle is None:
            return False
        handle.abort(description)
        return True

    @property
    def active_span_count(self) -> int:
        with self._lock:
            return len(self._spans)

    @contextmanager
    def execution_scope(self, trace_id: str):
        """Make the runtime span current only while the governed tool executes."""

        with self._lock:
            handle = self._spans.get(trace_id)
        if handle is None:
            with nullcontext():
                yield
            return
        try:
            from opentelemetry.trace import use_span
        except ImportError:
            with nullcontext():
                yield
            return
        with use_span(handle.span, end_on_exit=False):
            yield

    def _start_span(self, context: ExecutionContext) -> _SpanHandle:
        attributes = {
            "arg.trace_id": context.trace_id,
            "arg.span_id": context.span_id,
            "arg.parent_span_id": context.parent_span_id,
            "arg.request_id": context.request_id,
            "arg.tool.name": context.tool_call.name,
            "arg.risk.tier": context.risk_tier.name,
        }
        attributes = {key: value for key, value in attributes.items() if value is not None}
        start_span = getattr(self._tracer, "start_span", None)
        if callable(start_span):
            kwargs: dict[str, Any] = {"attributes": attributes}
            if self._parent_context is not None:
                kwargs["context"] = self._parent_context
            try:
                span = start_span(f"tool.{context.tool_call.name}", **kwargs)
            except TypeError:
                span = start_span(
                    f"tool.{context.tool_call.name}", attributes=attributes
                )
            return _SpanHandle(span=span)
        start_as_current = getattr(self._tracer, "start_as_current_span", None)
        if callable(start_as_current):
            kwargs: dict[str, Any] = {"attributes": attributes}
            if self._parent_context is not None:
                kwargs["context"] = self._parent_context
            manager = start_as_current(f"tool.{context.tool_call.name}", **kwargs)
            span = manager.__enter__()
            return _SpanHandle(span=span, manager=manager)
        raise TypeError("tracer must provide start_span or start_as_current_span")


def _set_span_terminal_state(span: Span, context: ExecutionContext) -> None:
    if context.status is ExecutionStatus.SUCCEEDED:
        _set_status(span, "OK", "succeeded")
        return
    if context.status in {
        ExecutionStatus.FAILED,
        ExecutionStatus.DENIED,
        ExecutionStatus.UNKNOWN,
    }:
        description = context.status.value
        if context.status in {ExecutionStatus.FAILED, ExecutionStatus.UNKNOWN}:
            _record_exception(
                span,
                RuntimeError(f"tool execution ended with status {description}"),
            )
        _set_status(span, "ERROR", description)


def _set_status(span: Span, code_name: str, description: str) -> None:
    setter = getattr(span, "set_status", None)
    if not callable(setter):
        return
    try:
        from opentelemetry.trace import Status, StatusCode
    except ImportError:
        return
    code = StatusCode.OK if code_name == "OK" else StatusCode.ERROR
    setter(Status(code) if code is StatusCode.OK else Status(code, description=description))


def _record_exception(span: Span, exc: BaseException) -> None:
    recorder = getattr(span, "record_exception", None)
    if callable(recorder):
        recorder(exc)


def _set_span_attribute(span: Span, key: str, value: Any) -> None:
    if value is not None:
        span.set_attribute(key, value)
