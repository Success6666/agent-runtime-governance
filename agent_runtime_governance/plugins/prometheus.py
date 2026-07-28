from __future__ import annotations

import weakref
from collections.abc import Callable, Iterator
from typing import Any

from .._internal.runtime.extensions import ExtensionDispatchSnapshot
from ..context import ExecutionContext, ExecutionStatus, HistoryEntry
from ..middleware.base import ObservingMiddleware
from .core import RuntimeBuilder

_EMPTY_EXTENSION_SNAPSHOT = ExtensionDispatchSnapshot(
    worker_capacity=0,
    in_flight_capacity=0,
    active_workers=0,
    in_flight=0,
    executor_queued=0,
    admission_waiters=0,
    detached_sync_work=0,
    saturated=False,
)


class _ExtensionDispatchSnapshotCollector:
    """Expose one coherent capacity snapshot for each Prometheus scrape."""

    def __init__(self, *, middleware: "PrometheusMiddleware", prefix: str) -> None:
        self._middleware = weakref.ref(middleware)
        self._prefix = prefix

    def collect(self) -> Iterator[Any]:
        from prometheus_client.core import GaugeMetricFamily

        middleware = self._middleware()
        snapshot = (
            middleware._extension_snapshot()
            if middleware is not None
            else _EMPTY_EXTENSION_SNAPSHOT
        )
        workers = GaugeMetricFamily(
            f"{self._prefix}_extension_dispatch_workers",
            "Runtime-owned extension worker capacity and activity.",
            labels=("state",),
        )
        workers.add_metric(["capacity"], float(snapshot.worker_capacity))
        workers.add_metric(["active"], float(snapshot.active_workers))
        yield workers

        queue_depth = GaugeMetricFamily(
            f"{self._prefix}_extension_dispatch_queue_depth",
            "Extension dispatch queue and admission depth.",
            labels=("state",),
        )
        queue_depth.add_metric(["executor"], float(snapshot.executor_queued))
        queue_depth.add_metric(["admission"], float(snapshot.admission_waiters))
        yield queue_depth

    def describe(self) -> Iterator[Any]:
        return iter(())


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
        self._extension_snapshot_provider: weakref.WeakMethod[Any] | None = None
        self._extension_dispatch_collector = _ExtensionDispatchSnapshotCollector(
            middleware=self,
            prefix=prefix,
        )
        target_registry.register(self._extension_dispatch_collector)

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

    def _bind_extension_dispatch_snapshot(
        self,
        snapshot_provider: Callable[[], ExtensionDispatchSnapshot],
    ) -> None:
        """Receive only a weak, observation-only view of dispatcher capacity."""

        self._extension_snapshot_provider = weakref.WeakMethod(snapshot_provider)

    def record_queue_wait(self, *, mode: str, seconds: float) -> None:
        self.extension_dispatch_queue_wait.labels(mode).observe(seconds)

    def record_execution(self, *, mode: str, seconds: float) -> None:
        self.extension_dispatch_execution.labels(mode).observe(seconds)

    def record_saturation(self, *, mode: str) -> None:
        self.extension_dispatch_saturation.labels(mode).inc()

    def record_detached_work(self, *, count: int) -> None:
        self.extension_dispatch_detached_work.set(count)

    def _extension_snapshot(self) -> ExtensionDispatchSnapshot:
        provider = (
            None
            if self._extension_snapshot_provider is None
            else self._extension_snapshot_provider()
        )
        return _EMPTY_EXTENSION_SNAPSHOT if provider is None else provider()

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
