from __future__ import annotations

from typing import Any

from .._extensions import ExtensionDispatchSnapshot, _ExtensionDispatcher
from ..context import ExecutionContext, ExecutionStatus, HistoryEntry
from ..middleware.base import ObservingMiddleware
from .core import RuntimeBuilder


class PrometheusMiddleware(ObservingMiddleware):
    name = "prometheus"
    priority = 960
    replayable = False

    def __init__(self, *, registry: Any = None, prefix: str = "arg") -> None:
        try:
            from prometheus_client import REGISTRY, Counter, Gauge, Histogram
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
        self.extension_dispatch_queue_wait = Histogram(
            f"{prefix}_extension_dispatch_queue_wait_seconds",
            "Time an extension waited before synchronous worker execution.",
            ("mode",),
            registry=target_registry,
        )
        self.extension_dispatch_execution = Histogram(
            f"{prefix}_extension_dispatch_execution_seconds",
            "Execution time for third-party extension callbacks.",
            ("mode",),
            registry=target_registry,
        )
        self.extension_dispatch_saturation = Counter(
            f"{prefix}_extension_dispatch_saturation_total",
            "Synchronous extension dispatch saturation events.",
            ("mode",),
            registry=target_registry,
        )
        self.extension_dispatch_detached_work = Gauge(
            f"{prefix}_extension_dispatch_detached_work",
            "Synchronous extension calls still running after caller cancellation.",
            registry=target_registry,
        )
        self.extension_dispatch_workers = Gauge(
            f"{prefix}_extension_dispatch_workers",
            "Runtime-owned extension worker capacity and activity.",
            ("state",),
            registry=target_registry,
        )
        self.extension_dispatch_queue_depth = Gauge(
            f"{prefix}_extension_dispatch_queue_depth",
            "Extension dispatch queue and admission depth.",
            ("state",),
            registry=target_registry,
        )
        self._extension_dispatcher: _ExtensionDispatcher | None = None
        self.extension_dispatch_workers.labels("capacity").set_function(
            lambda: float(self._extension_snapshot().worker_capacity)
        )
        self.extension_dispatch_workers.labels("active").set_function(
            lambda: float(self._extension_snapshot().active_workers)
        )
        self.extension_dispatch_queue_depth.labels("executor").set_function(
            lambda: float(self._extension_snapshot().executor_queued)
        )
        self.extension_dispatch_queue_depth.labels("admission").set_function(
            lambda: float(self._extension_snapshot().admission_waiters)
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

    def _bind_extension_dispatcher(self, dispatcher: _ExtensionDispatcher) -> None:
        """Receive the Runtime-owned dispatcher without exposing an injection API."""

        self._extension_dispatcher = dispatcher
        dispatcher.add_observer(self)

    def record_queue_wait(self, *, mode: str, seconds: float) -> None:
        self.extension_dispatch_queue_wait.labels(mode).observe(seconds)

    def record_execution(self, *, mode: str, seconds: float) -> None:
        self.extension_dispatch_execution.labels(mode).observe(seconds)

    def record_saturation(self, *, mode: str) -> None:
        self.extension_dispatch_saturation.labels(mode).inc()

    def record_detached_work(self, *, count: int) -> None:
        self.extension_dispatch_detached_work.set(count)

    def _extension_snapshot(self) -> ExtensionDispatchSnapshot:
        if self._extension_dispatcher is None:
            return ExtensionDispatchSnapshot(
                worker_capacity=0,
                in_flight_capacity=0,
                active_workers=0,
                in_flight=0,
                executor_queued=0,
                admission_waiters=0,
                detached_sync_work=0,
                saturated=False,
            )
        return self._extension_dispatcher.snapshot()

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
