"""Measure detached decision-explanation projection and offline verification."""

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

from agent_runtime_governance import (
    ActionContract,
    DecisionExplanationAttachment,
    ExecutionContext,
    ExecutionMode,
    PolicyMiddleware,
    RiskTier,
    SimplePolicy,
    ToolCall,
    verify_decision_explanation_document,
)


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


def _context() -> ExecutionContext:
    action = ActionContract(
        contract_id="benchmark.decision-explanation",
        contract_version=1,
        tool_name="benchmark_decision_explanation",
        execution_mode=ExecutionMode.READ_ONLY,
        parameters_schema={
            "type": "object",
            "properties": {"value": {"type": "integer"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        effect_class="benchmark.read",
    ).bind(
        {"value": 1},
        identity_issuer="benchmark",
        principal="benchmark-principal",
        tenant="benchmark-tenant",
        identity_digest_key=b"benchmark-identity-digest-key".ljust(32, b"0"),
        identity_digest_key_version="benchmark-v1",
        policy_version="benchmark-policy-v1",
        policy_digest="a" * 64,
    )
    context = ExecutionContext.create(
        ToolCall(name="benchmark_decision_explanation"),
        risk_tier=RiskTier.HIGH,
    ).bind_action(action)
    return asyncio.run(
        PolicyMiddleware(
            SimplePolicy(),
            version="benchmark-policy-v1",
            digest="a" * 64,
        ).process(context)
    )


def _percentile(ordered: list[float], quantile: float) -> float:
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * quantile)))
    return ordered[index]


def _measure(context: ExecutionContext, *, verify: bool, requests: int) -> Measurement:
    for _ in range(min(100, requests)):
        attachment = DecisionExplanationAttachment.from_context(context)
        if verify:
            verify_decision_explanation_document(
                attachment.to_dict(),
                expected_attachment_digest=attachment.attachment_digest,
                expected_action_digest=attachment.action_digest,
                expected_policy_version=attachment.policy_version,
                expected_policy_digest=attachment.policy_digest,
            )

    latencies: list[float] = []
    tracemalloc.start()
    started = perf_counter()
    for _ in range(requests):
        request_started = perf_counter()
        attachment = DecisionExplanationAttachment.from_context(context)
        if verify:
            report = verify_decision_explanation_document(
                attachment.to_dict(),
                expected_attachment_digest=attachment.attachment_digest,
                expected_action_digest=attachment.action_digest,
                expected_policy_version=attachment.policy_version,
                expected_policy_digest=attachment.policy_digest,
            )
            if not report["integrity"]["ok"] or not report["binding"]["ok"]:
                raise AssertionError("decision explanation verification failed")
        latencies.append((perf_counter() - request_started) * 1000)
    duration = perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    ordered = sorted(latencies)
    return Measurement(
        scenario=(
            "attachment_projection_and_verification"
            if verify
            else "attachment_projection"
        ),
        requests=requests,
        concurrency=1,
        throughput_per_second=requests / duration,
        mean_ms=statistics.fmean(latencies),
        p50_ms=_percentile(ordered, 0.50),
        p95_ms=_percentile(ordered, 0.95),
        p99_ms=_percentile(ordered, 0.99),
        peak_memory_kib=peak / 1024,
    )


def _median(samples: list[Measurement]) -> Measurement:
    first = samples[0]
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure detached decision-explanation verification overhead."
    )
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--paired-repetitions", type=int, default=3)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.requests < 1:
        parser.error("requests must be positive")
    if arguments.paired_repetitions < 1 or arguments.paired_repetitions % 2 == 0:
        parser.error("paired-repetitions must be a positive odd integer")

    context = _context()
    projection: list[Measurement] = []
    verification: list[Measurement] = []
    for index in range(arguments.paired_repetitions):
        order = (False, True) if index % 2 == 0 else (True, False)
        for verify in order:
            measurement = _measure(context, verify=verify, requests=arguments.requests)
            (verification if verify else projection).append(measurement)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
        "paired_repetitions": arguments.paired_repetitions,
        "measurements": [asdict(_median(projection)), asdict(_median(verification))],
    }
    encoded = json.dumps(payload, indent=2, ensure_ascii=True)
    print(encoded)
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
