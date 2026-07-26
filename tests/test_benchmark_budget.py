from __future__ import annotations

from scripts.check_benchmark_budget import evaluate


def _result(candidate_mean: float = 2.0) -> dict:
    common = {
        "requests": 1000,
        "concurrency": 100,
        "throughput_per_second": 1000.0,
        "p50_ms": 1.0,
        "p95_ms": 1.0,
        "p99_ms": 1.0,
        "peak_memory_kib": 100.0,
    }
    return {
        "measurements": [
            {**common, "scenario": "strict_baseline", "mean_ms": 1.0},
            {
                **common,
                "scenario": "strict_bound_action",
                "mean_ms": candidate_mean,
            },
        ]
    }


def _budget() -> dict:
    return {
        "comparison": {
            "baseline": "strict_baseline",
            "candidate": "strict_bound_action",
        },
        "limits": {
            "mean_ms_ratio": 3.0,
            "p95_ms_ratio": 3.0,
            "p99_ms_ratio": 3.0,
            "peak_memory_kib_ratio": 2.0,
        },
        "minimum_requests": 1000,
    }


def test_paired_benchmark_within_budget_passes() -> None:
    assert evaluate(_result(), _budget()) == []


def test_paired_benchmark_regression_reports_metric_and_scale() -> None:
    failures = evaluate(_result(candidate_mean=4.0), _budget())
    assert failures == ["mean_ms ratio 4.000 exceeds 3.000 at 1000 requests"]


def test_benchmark_requires_minimum_scale() -> None:
    result = _result()
    for measurement in result["measurements"]:
        measurement["requests"] = 100
    assert evaluate(result, _budget()) == [
        "no strict_bound_action measurement has at least 1000 requests"
    ]
