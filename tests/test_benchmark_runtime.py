from __future__ import annotations

import pytest

from benchmarks.benchmark_runtime import (
    Measurement,
    _median_measurement,
    build_scenarios,
    run_matrix,
)


def _measurement(mean_ms: float, *, scenario: str = "strict") -> Measurement:
    return Measurement(
        scenario=scenario,
        requests=1000,
        concurrency=100,
        throughput_per_second=1000.0 / mean_ms,
        mean_ms=mean_ms,
        p50_ms=mean_ms + 1,
        p95_ms=mean_ms + 2,
        p99_ms=mean_ms + 3,
        peak_memory_kib=mean_ms + 4,
    )


def test_paired_benchmark_uses_per_metric_median() -> None:
    result = _median_measurement(
        [_measurement(9.0), _measurement(1.0), _measurement(5.0)]
    )

    assert result.mean_ms == 5.0
    assert result.p95_ms == 7.0
    assert result.peak_memory_kib == 9.0


def test_paired_benchmark_rejects_mixed_scenarios() -> None:
    with pytest.raises(ValueError, match="same scenario"):
        _median_measurement(
            [_measurement(1.0), _measurement(2.0, scenario="other")]
        )


@pytest.mark.parametrize("repetitions", [0, -1, 2, 4])
@pytest.mark.asyncio
async def test_paired_benchmark_rejects_invalid_repetitions(repetitions: int) -> None:
    with pytest.raises(ValueError, match="positive odd integer"):
        await run_matrix([1], 1, paired_repetitions=repetitions)


def test_strict_benchmark_pair_uses_identical_policy_identity() -> None:
    scenarios = build_scenarios(concurrency=1)
    try:
        identities = []
        for name in ("strict_baseline", "strict_bound_action"):
            policy = scenarios[name].pipeline.middlewares[0]
            identities.append(policy.action_policy_identity())
        assert identities == [
            ("benchmark-policy-v1", "a" * 64),
            ("benchmark-policy-v1", "a" * 64),
        ]
    finally:
        for runtime in scenarios.values():
            runtime.close()
