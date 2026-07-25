from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import sys
import tracemalloc
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable

from agent_runtime_governance.audit import AuditSink
from agent_runtime_governance.context import ExecutionMode
from agent_runtime_governance.middleware import (
    AuditMiddleware,
    GatingMiddleware,
    Rule,
    RuleMiddleware,
)
from agent_runtime_governance.plugins.opa import OPAClient, OPAMiddleware
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


class NullAuditSink(AuditSink):
    def write(self, event) -> None:
        return None


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
    definitions = {
        "baseline": [],
        "rule": [rule()],
        "rule_opa": [rule(), opa()],
        "rule_opa_audit": [rule(), opa(), audit()],
        "rule_opa_audit_otel": [rule(), opa(), audit(), otel()],
        "ten_gates": [PassGate(f"gate_{index}") for index in range(10)],
    }
    return {
        name: Runtime(middleware, limits=limits)
        for name, middleware in definitions.items()
    }


async def measure(
    runtime: Runtime,
    *,
    scenario: str,
    requests: int,
    concurrency: int,
) -> Measurement:
    @runtime.tool(name="benchmark_echo", execution_mode=ExecutionMode.READ_ONLY)
    async def echo(value: int) -> int:
        return value

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


async def run_matrix(
    request_counts: Iterable[int], concurrency: int
) -> list[Measurement]:
    measurements: list[Measurement] = []
    for requests in request_counts:
        for scenario, runtime in build_scenarios(concurrency).items():
            measurements.append(
                await measure(
                    runtime,
                    scenario=scenario,
                    requests=requests,
                    concurrency=min(concurrency, requests),
                )
            )
    return measurements


async def measure_admission_contention(
    *, waiters: int, permit_hold_seconds: float = 0.0
) -> AdmissionContentionMeasurement:
    bulkhead = RuntimeBulkhead(1)
    initial = await bulkhead.acquire(1)
    latencies: list[float] = []

    async def contend() -> None:
        started = perf_counter()
        lease = await bulkhead.acquire(max(5.0, waiters * permit_hold_seconds * 2))
        latencies.append((perf_counter() - started) * 1000)
        try:
            await asyncio.sleep(max(0.0, permit_hold_seconds))
        finally:
            lease.release()

    tasks = [asyncio.create_task(contend()) for _ in range(waiters)]
    await asyncio.sleep(0)
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
    request_counts: Iterable[int], concurrency: int
) -> tuple[list[Measurement], AdmissionContentionMeasurement]:
    measurements = await run_matrix(request_counts, concurrency)
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
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    counts = [int(item) for item in args.requests.split(",")]
    if not counts or any(item < 1 for item in counts):
        parser.error("request counts must be positive")
    if args.concurrency < 1:
        parser.error("concurrency must be positive")

    measurements, admission = asyncio.run(run_benchmarks(counts, args.concurrency))
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
        "measurements": [asdict(item) for item in measurements],
        "admission_contention": asdict(admission),
    }
    encoded = json.dumps(payload, indent=2, ensure_ascii=True)
    print(encoded)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
