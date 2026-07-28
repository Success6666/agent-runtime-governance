from __future__ import annotations

import math

import pytest

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


def _dispatch_result() -> dict:
    common = {
        "io_latency_ms": 5.0,
        "requests": 20,
        "concurrency": 1,
        "worker_capacity": 4,
        "throughput_per_second": 100.0,
        "mean_ms": 1.0,
        "p50_ms": 1.0,
        "p95_ms": 1.0,
        "p99_ms": 1.0,
        "event_loop_lag_p50_ms": 0.1,
        "event_loop_lag_p95_ms": 0.2,
        "event_loop_lag_p99_ms": 0.3,
        "queue_wait_mean_ms": 0.1,
        "queue_wait_p50_ms": 0.1,
        "queue_wait_p95_ms": 0.2,
        "queue_wait_p99_ms": 0.3,
        "thread_count_start": 1,
        "thread_count_peak": 2,
        "extension_worker_thread_peak": 1,
        "active_workers_peak": 1,
        "executor_queued_peak": 0,
        "admission_waiters_peak": 0,
        "peak_memory_kib": 100.0,
    }
    return {
        "extension_dispatch": {
            "measurements": [
                {**common, "mode": "native_async"},
                {
                    **common,
                    "mode": "legacy_sync",
                    "throughput_per_second": 50.0,
                    "mean_ms": 2.0,
                    "p50_ms": 2.0,
                    "p95_ms": 2.0,
                    "p99_ms": 2.0,
                    "peak_memory_kib": 150.0,
                },
            ]
        }
    }


def _dispatch_budget() -> dict:
    return {
        "measurement_set": "extension_dispatch",
        "comparison": {
            "baseline": "native_async",
            "candidate": "legacy_sync",
        },
        "latencies_ms": [5],
        "concurrencies": [1],
        "minimum_requests_per_cell": 20,
        "limits_by_concurrency": {
            "1": {
                "maximum_ratios": {
                    "mean_ms": 3.0,
                    "p99_ms": 3.0,
                    "peak_memory_kib": 2.0,
                },
                "minimum_ratios": {
                    "throughput_per_second": 0.2,
                },
            }
        },
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


def test_benchmark_requires_paired_measurements() -> None:
    result = _result()
    result["measurements"] = [result["measurements"][1]]
    assert evaluate(result, _budget()) == [
        "missing paired measurement for 1000 requests"
    ]


@pytest.mark.parametrize("value", [0.0, -1.0, math.nan, math.inf])
def test_benchmark_rejects_invalid_baseline(value: float) -> None:
    result = _result()
    result["measurements"][0]["mean_ms"] = value
    assert evaluate(result, _budget()) == [
        "baseline mean_ms must be finite and positive"
    ]


@pytest.mark.parametrize("value", [-1.0, math.nan, math.inf])
def test_benchmark_rejects_invalid_candidate(value: float) -> None:
    result = _result()
    result["measurements"][1]["mean_ms"] = value
    assert evaluate(result, _budget()) == [
        "candidate mean_ms must be finite and non-negative"
    ]


@pytest.mark.parametrize("value", [-1.0, math.nan, math.inf])
def test_benchmark_rejects_invalid_limit(value: float) -> None:
    budget = _budget()
    budget["limits"] = {"mean_ms_ratio": value}
    assert evaluate(_result(), budget) == [
        "budget limit for mean_ms must be finite and non-negative"
    ]


@pytest.mark.parametrize(
    ("metric", "source", "value", "limit"),
    [
        ("p95_ms_ratio", "p95_ms", 4.0, 3.0),
        ("p99_ms_ratio", "p99_ms", 4.0, 3.0),
        ("peak_memory_kib_ratio", "peak_memory_kib", 300.0, 2.0),
    ],
)
def test_benchmark_reports_each_release_budget_violation(
    metric: str, source: str, value: float, limit: float
) -> None:
    result = _result()
    result["measurements"][1][source] = value
    budget = _budget()
    budget["limits"] = {metric: limit}

    expected_ratio = value / float(result["measurements"][0][source])
    assert evaluate(result, budget) == [
        f"{source} ratio {expected_ratio:.3f} exceeds {limit:.3f} at 1000 requests"
    ]


def test_extension_dispatch_budget_uses_same_host_mode_ratios() -> None:
    assert evaluate(_dispatch_result(), _dispatch_budget()) == []


def test_extension_dispatch_budget_reports_per_cell_tail_regression() -> None:
    result = _dispatch_result()
    result["extension_dispatch"]["measurements"][1]["p99_ms"] = 4.0

    assert evaluate(result, _dispatch_budget()) == [
        "dispatch p99_ms ratio 4.000 exceeds 3.000 at 5 ms / 1 concurrency"
    ]


def test_extension_dispatch_budget_requires_both_modes_for_every_cell() -> None:
    result = _dispatch_result()
    result["extension_dispatch"]["measurements"].pop()

    assert evaluate(result, _dispatch_budget()) == [
        "missing dispatch pair at 5 ms / 1 concurrency"
    ]


def test_extension_dispatch_budget_reports_minimum_throughput_ratio() -> None:
    result = _dispatch_result()
    result["extension_dispatch"]["measurements"][1][
        "throughput_per_second"
    ] = 10.0

    assert evaluate(result, _dispatch_budget()) == [
        "dispatch throughput_per_second ratio 0.100 is below 0.200 at "
        "5 ms / 1 concurrency"
    ]


def test_extension_dispatch_budget_requires_the_configured_worker_capacity() -> None:
    result = _dispatch_result()
    budget = _dispatch_budget()
    budget["worker_capacity"] = 4
    result["extension_dispatch"]["measurements"][1]["worker_capacity"] = 2

    assert evaluate(result, budget) == [
        "legacy_sync dispatch worker_capacity 2 does not match 4 at "
        "5 ms / 1 concurrency"
    ]
