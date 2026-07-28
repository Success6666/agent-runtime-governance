from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import sys
import threading
import tracemalloc
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter, sleep
from typing import Any, Iterable

from agent_runtime_governance._internal.runtime.blocking import invoke_extension
from agent_runtime_governance.action_contracts import ActionContract
from agent_runtime_governance.audit import AuditSink
from agent_runtime_governance.context import ExecutionMode
from agent_runtime_governance.identity import StaticIdentityProvider, VerifiedPrincipal
from agent_runtime_governance.middleware import (
    AuditMiddleware,
    GatingMiddleware,
    Rule,
    RuleMiddleware,
)
from agent_runtime_governance.plugins.opa import OPAClient, OPAMiddleware
from agent_runtime_governance.policy import PolicyMiddleware, SimplePolicy
from agent_runtime_governance.production import ProductionProfile
from agent_runtime_governance.resilience import RuntimeBulkhead, RuntimeLimits
from agent_runtime_governance.runtime import Runtime
from agent_runtime_governance.telemetry import OpenTelemetryMiddleware


@dataclass(frozen=True, slots=True)
class Measurement:
    scenario: str
    requests: int
    concurrency: int
    throughput_per_second: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    peak_memory_kib: float


@dataclass(frozen=True, slots=True)
class AdmissionContentionMeasurement:
    waiters: int
    permit_hold_ms: float
    mean_wait_ms: float
    p50_wait_ms: float
    p95_wait_ms: float
    p99_wait_ms: float


@dataclass(frozen=True, slots=True)
class ExtensionDispatchMeasurement:
    """One same-host measurement of an extension dispatch mode."""

    mode: str
    io_latency_ms: float
    requests: int
    concurrency: int
    worker_capacity: int
    throughput_per_second: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    event_loop_lag_p50_ms: float
    event_loop_lag_p95_ms: float
    event_loop_lag_p99_ms: float
    queue_wait_mean_ms: float
    queue_wait_p50_ms: float
    queue_wait_p95_ms: float
    queue_wait_p99_ms: float
    thread_count_start: int
    thread_count_peak: int
    extension_worker_thread_peak: int
    active_workers_peak: int
    executor_queued_peak: int
    admission_waiters_peak: int
    peak_memory_kib: float


_PAIRED_SCENARIOS = ("strict_baseline", "strict_bound_action")
_DISPATCH_MODES = ("native_async", "legacy_sync")
_DEFAULT_DISPATCH_LATENCIES_MS = (5.0, 20.0, 50.0)
_DEFAULT_DISPATCH_CONCURRENCIES = (1, 16, 100, 500)
_DISPATCH_SAMPLE_INTERVAL_SECONDS = 0.002


class NullAuditSink(AuditSink):
    production_durable = True
    production_integrity_protected = True

    def write(self, event) -> None:
        return None


class BenchmarkKeyProvider:
    def get_key(self, *, tenant: str, version: str) -> bytes:
        return b"benchmark-identity-digest-key".ljust(32, b"0")


class NoopSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def set_status(self, status: Any) -> None:
        return None

    def record_exception(self, exc: BaseException) -> None:
        return None

    def end(self) -> None:
        return None


class NoopTracer:
    def start_span(self, name: str, **kwargs: Any) -> NoopSpan:
        return NoopSpan()


class PassGate(GatingMiddleware):
    def __init__(self, name: str) -> None:
        self.name = name

    async def process(self, context):
        return context


class ExtensionDispatchGate(GatingMiddleware):
    """Exercise the Runtime-owned third-party extension dispatch boundary."""

    name = "benchmark_extension_dispatch"

    def __init__(self, callback) -> None:
        self._callback = callback

    async def process(self, context):
        queued_at = perf_counter()
        await invoke_extension(self._callback, queued_at)
        return context


class _DispatchRecorder:
    """Collect callback-start timing without adding work to the benchmark path."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue_waits_ms: list[float] = []

    def record_callback_start(self, queued_at: float) -> None:
        with self._lock:
            self._queue_waits_ms.append(
                max(0.0, (perf_counter() - queued_at) * 1000)
            )

    def reset(self) -> None:
        with self._lock:
            self._queue_waits_ms.clear()

    def queue_waits_ms(self) -> list[float]:
        with self._lock:
            return list(self._queue_waits_ms)


class _ExtensionDispatchMonitor:
    """Sample loop responsiveness and dispatcher occupancy during one run."""

    def __init__(self, runtime: Runtime) -> None:
        self._runtime = runtime
        self.event_loop_lags_ms: list[float] = []
        self.thread_count_start = len(threading.enumerate())
        self.thread_count_peak = self.thread_count_start
        self.extension_worker_thread_peak = 0
        self.active_workers_peak = 0
        self.executor_queued_peak = 0
        self.admission_waiters_peak = 0

    def observe(self) -> None:
        snapshot = self._runtime.extension_dispatch_snapshot
        threads = threading.enumerate()
        self.thread_count_peak = max(self.thread_count_peak, len(threads))
        self.extension_worker_thread_peak = max(
            self.extension_worker_thread_peak,
            sum(thread.name.startswith("arg-extension") for thread in threads),
        )
        self.active_workers_peak = max(
            self.active_workers_peak, snapshot.active_workers
        )
        self.executor_queued_peak = max(
            self.executor_queued_peak, snapshot.executor_queued
        )
        self.admission_waiters_peak = max(
            self.admission_waiters_peak, snapshot.admission_waiters
        )

    async def sample(self, stop: asyncio.Event) -> None:
        expected = perf_counter() + _DISPATCH_SAMPLE_INTERVAL_SECONDS
        while not stop.is_set():
            await asyncio.sleep(
                max(0.0, expected - perf_counter())
            )
            observed = perf_counter()
            self.event_loop_lags_ms.append(
                max(0.0, (observed - expected) * 1000)
            )
            self.observe()
            expected = observed + _DISPATCH_SAMPLE_INTERVAL_SECONDS


def build_scenarios(concurrency: int) -> dict[str, Runtime]:
    def rule() -> RuleMiddleware:
        return RuleMiddleware(
            [Rule("never", r"(?!)", "benchmark non-matching rule")]
        )

    def opa() -> OPAMiddleware:
        return OPAMiddleware(
            OPAClient(
                "http://localhost:8181",
                "benchmark/allow",
                transport=lambda payload: {"result": True},
            )
        )

    def audit() -> AuditMiddleware:
        return AuditMiddleware(NullAuditSink())

    def otel() -> OpenTelemetryMiddleware:
        return OpenTelemetryMiddleware(NoopTracer())

    limits = RuntimeLimits(max_in_flight=max(128, concurrency))
    definitions: dict[str, list[Any]] = {
        "baseline": [],
        "rule": [rule()],
        "rule_opa": [rule(), opa()],
        "rule_opa_audit": [rule(), opa(), audit()],
        "rule_opa_audit_otel": [rule(), opa(), audit(), otel()],
        "ten_gates": [PassGate(f"gate_{index}") for index in range(10)],
    }
    scenarios = {
        name: Runtime(middleware, limits=limits)
        for name, middleware in definitions.items()
    }
    profile = ProductionProfile(
        identity_digest_key_provider=BenchmarkKeyProvider(),
        identity_digest_key_version="benchmark-v1",
        policy_version="benchmark-policy-v1",
        policy_digest="a" * 64,
    )
    principal = VerifiedPrincipal(
        issuer="benchmark",
        subject="benchmark-runner",
        tenant="benchmark-tenant",
        source="static",
    )
    for name in ("strict_baseline", "strict_bound_action"):
        scenarios[name] = Runtime(
            [
                PolicyMiddleware(
                    SimplePolicy(),
                    version="benchmark-policy-v1",
                    digest="a" * 64,
                ),
                AuditMiddleware(NullAuditSink(), fail_closed=True),
            ],
            identity_provider=StaticIdentityProvider(principal),
            require_verified_identity=True,
            production_profile=profile,
            limits=limits,
        )

    contract = ActionContract(
        contract_id="benchmark.echo",
        contract_version=1,
        tool_name="benchmark_echo",
        execution_mode=ExecutionMode.READ_ONLY,
        parameters_schema={
            "type": "object",
            "properties": {"value": {"type": "integer"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        effect_class="benchmark.read",
    )
    for name, runtime in scenarios.items():
        _register_echo(
            runtime,
            action_contract=(
                contract if name == "strict_bound_action" else None
            ),
        )
        if name.startswith("strict_"):
            runtime.seal_production()
    return scenarios


def _register_echo(
    runtime: Runtime,
    *,
    action_contract: ActionContract | None,
) -> None:
    @runtime.tool(
        name="benchmark_echo",
        execution_mode=ExecutionMode.READ_ONLY,
        action_contract=action_contract,
    )
    async def echo(value: int) -> int:
        return value


async def measure(
    runtime: Runtime,
    *,
    scenario: str,
    requests: int,
    concurrency: int,
) -> Measurement:
    for index in range(min(50, requests)):
        await runtime.arun("benchmark_echo", index)

    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []

    async def invoke(index: int) -> None:
        async with semaphore:
            started = perf_counter()
            result = await runtime.arun("benchmark_echo", index)
            elapsed = (perf_counter() - started) * 1000
            if result.value != index:
                raise AssertionError("benchmark returned an invalid result")
            latencies.append(elapsed)

    tracemalloc.start()
    started = perf_counter()
    await asyncio.gather(*(invoke(index) for index in range(requests)))
    duration = perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    ordered = sorted(latencies)
    return Measurement(
        scenario=scenario,
        requests=requests,
        concurrency=concurrency,
        throughput_per_second=requests / duration,
        mean_ms=statistics.fmean(latencies),
        p50_ms=_percentile(ordered, 0.50),
        p95_ms=_percentile(ordered, 0.95),
        p99_ms=_percentile(ordered, 0.99),
        peak_memory_kib=peak / 1024,
    )


def _percentile(ordered: list[float], quantile: float) -> float:
    position = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * quantile)))
    return ordered[position]


def _median_measurement(samples: list[Measurement]) -> Measurement:
    if not samples:
        raise ValueError("at least one benchmark sample is required")
    first = samples[0]
    if any(
        (item.scenario, item.requests, item.concurrency)
        != (first.scenario, first.requests, first.concurrency)
        for item in samples[1:]
    ):
        raise ValueError("benchmark samples must describe the same scenario")
    return Measurement(
        scenario=first.scenario,
        requests=first.requests,
        concurrency=first.concurrency,
        throughput_per_second=statistics.median(
            item.throughput_per_second for item in samples
        ),
        mean_ms=statistics.median(item.mean_ms for item in samples),
        p50_ms=statistics.median(item.p50_ms for item in samples),
        p95_ms=statistics.median(item.p95_ms for item in samples),
        p99_ms=statistics.median(item.p99_ms for item in samples),
        peak_memory_kib=statistics.median(item.peak_memory_kib for item in samples),
    )


def _median_extension_dispatch_measurement(
    samples: list[ExtensionDispatchMeasurement],
) -> ExtensionDispatchMeasurement:
    if not samples:
        raise ValueError("at least one dispatch benchmark sample is required")
    first = samples[0]
    identity = (
        first.mode,
        first.io_latency_ms,
        first.requests,
        first.concurrency,
        first.worker_capacity,
    )
    if any(
        (
            item.mode,
            item.io_latency_ms,
            item.requests,
            item.concurrency,
            item.worker_capacity,
        )
        != identity
        for item in samples[1:]
    ):
        raise ValueError("dispatch benchmark samples must describe the same cell")

    def median_float(name: str) -> float:
        return statistics.median(float(getattr(item, name)) for item in samples)

    def median_int(name: str) -> int:
        return round(statistics.median(int(getattr(item, name)) for item in samples))

    return ExtensionDispatchMeasurement(
        mode=first.mode,
        io_latency_ms=first.io_latency_ms,
        requests=first.requests,
        concurrency=first.concurrency,
        worker_capacity=first.worker_capacity,
        throughput_per_second=median_float("throughput_per_second"),
        mean_ms=median_float("mean_ms"),
        p50_ms=median_float("p50_ms"),
        p95_ms=median_float("p95_ms"),
        p99_ms=median_float("p99_ms"),
        event_loop_lag_p50_ms=median_float("event_loop_lag_p50_ms"),
        event_loop_lag_p95_ms=median_float("event_loop_lag_p95_ms"),
        event_loop_lag_p99_ms=median_float("event_loop_lag_p99_ms"),
        queue_wait_mean_ms=median_float("queue_wait_mean_ms"),
        queue_wait_p50_ms=median_float("queue_wait_p50_ms"),
        queue_wait_p95_ms=median_float("queue_wait_p95_ms"),
        queue_wait_p99_ms=median_float("queue_wait_p99_ms"),
        thread_count_start=median_int("thread_count_start"),
        thread_count_peak=median_int("thread_count_peak"),
        extension_worker_thread_peak=median_int(
            "extension_worker_thread_peak"
        ),
        active_workers_peak=median_int("active_workers_peak"),
        executor_queued_peak=median_int("executor_queued_peak"),
        admission_waiters_peak=median_int("admission_waiters_peak"),
        peak_memory_kib=median_float("peak_memory_kib"),
    )


def _validate_dispatch_inputs(
    *,
    mode: str,
    io_latency_ms: float,
    requests: int,
    concurrency: int,
    worker_capacity: int,
) -> None:
    if mode not in _DISPATCH_MODES:
        raise ValueError(f"unsupported dispatch mode: {mode}")
    if io_latency_ms <= 0:
        raise ValueError("io_latency_ms must be positive")
    if requests < 1:
        raise ValueError("requests must be positive")
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    if worker_capacity < 1:
        raise ValueError("worker_capacity must be positive")


async def measure_extension_dispatch(
    *,
    mode: str,
    io_latency_ms: float,
    requests: int,
    concurrency: int,
    worker_capacity: int = 4,
) -> ExtensionDispatchMeasurement:
    """Measure synthetic native-async or legacy-sync extension I/O.

    Both modes use the same Runtime gate and a local sleep-only callback. This
    isolates the dispatch path from external services while preserving native
    coroutine execution and bounded legacy-worker execution.
    """

    _validate_dispatch_inputs(
        mode=mode,
        io_latency_ms=io_latency_ms,
        requests=requests,
        concurrency=concurrency,
        worker_capacity=worker_capacity,
    )
    recorder = _DispatchRecorder()
    delay_seconds = io_latency_ms / 1000

    if mode == "native_async":

        async def callback(queued_at: float) -> None:
            recorder.record_callback_start(queued_at)
            await asyncio.sleep(delay_seconds)

    else:

        def callback(queued_at: float) -> None:
            recorder.record_callback_start(queued_at)
            sleep(delay_seconds)

    limits = RuntimeLimits(
        admission_timeout_seconds=30.0,
        execution_timeout_seconds=30.0,
        max_in_flight=max(500, concurrency),
        max_blocking_extension_in_flight=max(500, concurrency),
        max_blocking_extension_workers=worker_capacity,
    )
    runtime = Runtime([ExtensionDispatchGate(callback)], limits=limits)

    @runtime.tool(name="benchmark_extension_echo", execution_mode=ExecutionMode.READ_ONLY)
    async def echo(value: int) -> int:
        return value

    try:
        # Start the legacy executor before sampling so worker creation does not
        # dominate a short 5 ms cell. Native callbacks leave it unused.
        await runtime.arun("benchmark_extension_echo", -1)
        recorder.reset()
        monitor = _ExtensionDispatchMonitor(runtime)
        monitor.observe()
        stop_monitor = asyncio.Event()
        monitor_task: asyncio.Task[None] | None = None
        latencies_ms: list[float] = []
        tracing_was_active = tracemalloc.is_tracing()
        peak = 0

        async def invoke(index: int) -> None:
            async with semaphore:
                started = perf_counter()
                result = await runtime.arun("benchmark_extension_echo", index)
                latency_ms = (perf_counter() - started) * 1000
                if result.value != index:
                    raise AssertionError("extension benchmark returned an invalid result")
                latencies_ms.append(latency_ms)

        try:
            semaphore = asyncio.Semaphore(concurrency)
            if tracing_was_active:
                tracemalloc.reset_peak()
            else:
                tracemalloc.start()
            monitor_task = asyncio.create_task(
                monitor.sample(stop_monitor),
                name="benchmark-extension-monitor",
            )
            started = perf_counter()
            await asyncio.gather(*(invoke(index) for index in range(requests)))
            duration = perf_counter() - started
        finally:
            if tracemalloc.is_tracing():
                _, peak = tracemalloc.get_traced_memory()
            if not tracing_was_active and tracemalloc.is_tracing():
                tracemalloc.stop()
            stop_monitor.set()
            if monitor_task is not None:
                await monitor_task
            monitor.observe()

        ordered_latencies = sorted(latencies_ms)
        queue_waits_ms = sorted(recorder.queue_waits_ms())
        event_loop_lags_ms = sorted(monitor.event_loop_lags_ms) or [0.0]
        if len(queue_waits_ms) != requests:
            raise AssertionError("extension callback did not record every dispatch")
        return ExtensionDispatchMeasurement(
            mode=mode,
            io_latency_ms=io_latency_ms,
            requests=requests,
            concurrency=concurrency,
            worker_capacity=worker_capacity,
            throughput_per_second=requests / duration,
            mean_ms=statistics.fmean(latencies_ms),
            p50_ms=_percentile(ordered_latencies, 0.50),
            p95_ms=_percentile(ordered_latencies, 0.95),
            p99_ms=_percentile(ordered_latencies, 0.99),
            event_loop_lag_p50_ms=_percentile(event_loop_lags_ms, 0.50),
            event_loop_lag_p95_ms=_percentile(event_loop_lags_ms, 0.95),
            event_loop_lag_p99_ms=_percentile(event_loop_lags_ms, 0.99),
            queue_wait_mean_ms=statistics.fmean(queue_waits_ms),
            queue_wait_p50_ms=_percentile(queue_waits_ms, 0.50),
            queue_wait_p95_ms=_percentile(queue_waits_ms, 0.95),
            queue_wait_p99_ms=_percentile(queue_waits_ms, 0.99),
            thread_count_start=monitor.thread_count_start,
            thread_count_peak=monitor.thread_count_peak,
            extension_worker_thread_peak=monitor.extension_worker_thread_peak,
            active_workers_peak=monitor.active_workers_peak,
            executor_queued_peak=monitor.executor_queued_peak,
            admission_waiters_peak=monitor.admission_waiters_peak,
            peak_memory_kib=peak / 1024,
        )
    finally:
        await runtime.aclose()


async def run_extension_dispatch_matrix(
    *,
    io_latencies_ms: Iterable[float] = _DEFAULT_DISPATCH_LATENCIES_MS,
    concurrencies: Iterable[int] = _DEFAULT_DISPATCH_CONCURRENCIES,
    requests_per_cell: int = 20,
    worker_capacity: int = 4,
    paired_repetitions: int = 3,
) -> list[ExtensionDispatchMeasurement]:
    """Run alternating native/sync pairs for every synthetic I/O cell."""

    if paired_repetitions < 1 or paired_repetitions % 2 == 0:
        raise ValueError("paired_repetitions must be a positive odd integer")
    if requests_per_cell < 1:
        raise ValueError("requests_per_cell must be positive")
    if worker_capacity < 1:
        raise ValueError("worker_capacity must be positive")
    latencies = tuple(float(value) for value in io_latencies_ms)
    concurrency_levels = tuple(int(value) for value in concurrencies)
    if not latencies or any(value <= 0 for value in latencies):
        raise ValueError("io_latencies_ms must contain positive values")
    if not concurrency_levels or any(value < 1 for value in concurrency_levels):
        raise ValueError("concurrencies must contain positive values")

    measurements: list[ExtensionDispatchMeasurement] = []
    for io_latency_ms in latencies:
        for concurrency in concurrency_levels:
            requests = max(requests_per_cell, concurrency)
            paired: dict[str, list[ExtensionDispatchMeasurement]] = {
                mode: [] for mode in _DISPATCH_MODES
            }
            for repetition in range(paired_repetitions):
                order = (
                    _DISPATCH_MODES
                    if repetition % 2 == 0
                    else tuple(reversed(_DISPATCH_MODES))
                )
                for mode in order:
                    paired[mode].append(
                        await measure_extension_dispatch(
                            mode=mode,
                            io_latency_ms=io_latency_ms,
                            requests=requests,
                            concurrency=concurrency,
                            worker_capacity=worker_capacity,
                        )
                    )
            measurements.extend(
                _median_extension_dispatch_measurement(paired[mode])
                for mode in _DISPATCH_MODES
            )
    return measurements


async def run_matrix(
    request_counts: Iterable[int],
    concurrency: int,
    *,
    paired_repetitions: int = 3,
) -> list[Measurement]:
    if paired_repetitions < 1 or paired_repetitions % 2 == 0:
        raise ValueError("paired_repetitions must be a positive odd integer")
    measurements: list[Measurement] = []
    scenarios = build_scenarios(concurrency)
    try:
        for requests in request_counts:
            for scenario, runtime in scenarios.items():
                if scenario in _PAIRED_SCENARIOS:
                    continue
                measurements.append(
                    await measure(
                        runtime,
                        scenario=scenario,
                        requests=requests,
                        concurrency=min(concurrency, requests),
                    )
                )
            paired: dict[str, list[Measurement]] = {
                scenario: [] for scenario in _PAIRED_SCENARIOS
            }
            for repetition in range(paired_repetitions):
                order = (
                    _PAIRED_SCENARIOS
                    if repetition % 2 == 0
                    else tuple(reversed(_PAIRED_SCENARIOS))
                )
                for scenario in order:
                    paired[scenario].append(
                        await measure(
                            scenarios[scenario],
                            scenario=scenario,
                            requests=requests,
                            concurrency=min(concurrency, requests),
                        )
                    )
            measurements.extend(
                _median_measurement(paired[scenario])
                for scenario in _PAIRED_SCENARIOS
            )
    finally:
        await asyncio.gather(*(runtime.aclose() for runtime in scenarios.values()))
    return measurements


async def measure_admission_contention(
    *, waiters: int, permit_hold_seconds: float = 0.0
) -> AdmissionContentionMeasurement:
    if waiters < 1:
        raise ValueError("waiters must be at least 1")
    bulkhead = RuntimeBulkhead(1)
    initial = await bulkhead.acquire(1)
    latencies: list[float] = []
    started_waiters = 0
    all_waiters_started = asyncio.Event()

    async def contend() -> None:
        nonlocal started_waiters
        started = perf_counter()
        started_waiters += 1
        if started_waiters == waiters:
            all_waiters_started.set()
        lease = await bulkhead.acquire(max(5.0, waiters * permit_hold_seconds * 2))
        latencies.append((perf_counter() - started) * 1000)
        try:
            await asyncio.sleep(max(0.0, permit_hold_seconds))
        finally:
            lease.release()

    tasks = [asyncio.create_task(contend()) for _ in range(waiters)]
    await all_waiters_started.wait()
    initial.release()
    await asyncio.gather(*tasks)
    ordered = sorted(latencies)
    return AdmissionContentionMeasurement(
        waiters=waiters,
        permit_hold_ms=permit_hold_seconds * 1000,
        mean_wait_ms=statistics.fmean(latencies),
        p50_wait_ms=_percentile(ordered, 0.50),
        p95_wait_ms=_percentile(ordered, 0.95),
        p99_wait_ms=_percentile(ordered, 0.99),
    )


async def run_benchmarks(
    request_counts: Iterable[int],
    concurrency: int,
    *,
    paired_repetitions: int = 3,
) -> tuple[list[Measurement], AdmissionContentionMeasurement]:
    measurements = await run_matrix(
        request_counts,
        concurrency,
        paired_repetitions=paired_repetitions,
    )
    admission = await measure_admission_contention(waiters=max(10, concurrency))
    return measurements, admission


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure governance layer latency, throughput, and peak allocations."
    )
    parser.add_argument(
        "--requests",
        default="1000",
        help="comma-separated request counts, for example 100,500,1000,5000",
    )
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument(
        "--paired-repetitions",
        type=int,
        default=3,
        help="odd number of alternating strict-pair samples aggregated by median",
    )
    parser.add_argument(
        "--dispatch-matrix",
        action="store_true",
        help=(
            "also measure native async and legacy sync extension dispatch "
            "across the synthetic I/O matrix"
        ),
    )
    parser.add_argument(
        "--skip-runtime-matrix",
        action="store_true",
        help="skip the existing governance-layer matrix",
    )
    parser.add_argument(
        "--dispatch-latencies-ms",
        default="5,20,50",
        help="comma-separated synthetic I/O delays for dispatch measurements",
    )
    parser.add_argument(
        "--dispatch-concurrencies",
        default="1,16,100,500",
        help="comma-separated dispatch concurrency levels",
    )
    parser.add_argument(
        "--dispatch-requests-per-cell",
        type=int,
        default=20,
        help="minimum requests in each dispatch matrix cell",
    )
    parser.add_argument(
        "--dispatch-workers",
        type=int,
        default=4,
        help="legacy sync extension worker capacity",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        counts = [int(item) for item in args.requests.split(",")]
        dispatch_latencies_ms = [
            float(item) for item in args.dispatch_latencies_ms.split(",")
        ]
        dispatch_concurrencies = [
            int(item) for item in args.dispatch_concurrencies.split(",")
        ]
    except ValueError:
        parser.error("benchmark matrix values must be numeric")
    if not counts or any(item < 1 for item in counts):
        parser.error("request counts must be positive")
    if args.concurrency < 1:
        parser.error("concurrency must be positive")
    if args.paired_repetitions < 1 or args.paired_repetitions % 2 == 0:
        parser.error("paired repetitions must be a positive odd integer")
    if args.skip_runtime_matrix and not args.dispatch_matrix:
        parser.error("--skip-runtime-matrix requires --dispatch-matrix")
    if args.dispatch_matrix and (
        not dispatch_latencies_ms
        or any(item <= 0 for item in dispatch_latencies_ms)
        or not dispatch_concurrencies
        or any(item < 1 for item in dispatch_concurrencies)
        or args.dispatch_requests_per_cell < 1
        or args.dispatch_workers < 1
    ):
        parser.error("dispatch matrix values must be positive")

    measurements: list[Measurement] = []
    admission: AdmissionContentionMeasurement | None = None
    if not args.skip_runtime_matrix:
        measurements, admission = asyncio.run(
            run_benchmarks(
                counts,
                args.concurrency,
                paired_repetitions=args.paired_repetitions,
            )
        )
    dispatch_measurements: list[ExtensionDispatchMeasurement] = []
    if args.dispatch_matrix:
        dispatch_measurements = asyncio.run(
            run_extension_dispatch_matrix(
                io_latencies_ms=dispatch_latencies_ms,
                concurrencies=dispatch_concurrencies,
                requests_per_cell=args.dispatch_requests_per_cell,
                worker_capacity=args.dispatch_workers,
                paired_repetitions=args.paired_repetitions,
            )
        )
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
        "paired_repetitions": args.paired_repetitions,
        "measurements": [asdict(item) for item in measurements],
        "admission_contention": (
            None if admission is None else asdict(admission)
        ),
    }
    if args.dispatch_matrix:
        payload["extension_dispatch"] = {
            "paired_repetitions": args.paired_repetitions,
            "io_latencies_ms": dispatch_latencies_ms,
            "concurrencies": dispatch_concurrencies,
            "minimum_requests_per_cell": args.dispatch_requests_per_cell,
            "worker_capacity": args.dispatch_workers,
            "measurements": [asdict(item) for item in dispatch_measurements],
        }
    encoded = json.dumps(payload, indent=2, ensure_ascii=True)
    print(encoded)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
