from __future__ import annotations

import pytest

from benchmarks.benchmark_runtime import Measurement, _median_measurement


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
