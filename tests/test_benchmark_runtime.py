from __future__ import annotations

import pytest

from benchmarks.benchmark_runtime import (
    _DEFAULT_DISPATCH_CONCURRENCIES,
    _DEFAULT_DISPATCH_LATENCIES_MS,
    ExtensionDispatchMeasurement,
    Measurement,
    _median_extension_dispatch_measurement,
    _median_measurement,
    build_scenarios,
    measure_extension_dispatch,
    run_extension_dispatch_matrix,
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


def _dispatch_measurement(
    mean_ms: float,
    *,
    mode: str = "native_async",
) -> ExtensionDispatchMeasurement:
    return ExtensionDispatchMeasurement(
        mode=mode,
        io_latency_ms=5.0,
        requests=20,
        concurrency=1,
        worker_capacity=4,
        throughput_per_second=1000.0 / mean_ms,
        mean_ms=mean_ms,
        p50_ms=mean_ms + 1,
        p95_ms=mean_ms + 2,
        p99_ms=mean_ms + 3,
        event_loop_lag_p50_ms=mean_ms + 4,
        event_loop_lag_p95_ms=mean_ms + 5,
        event_loop_lag_p99_ms=mean_ms + 6,
        queue_wait_mean_ms=mean_ms + 7,
        queue_wait_p50_ms=mean_ms + 8,
        queue_wait_p95_ms=mean_ms + 9,
        queue_wait_p99_ms=mean_ms + 10,
        thread_count_start=3,
        thread_count_peak=4,
        extension_worker_thread_peak=1,
        active_workers_peak=1,
        executor_queued_peak=2,
        admission_waiters_peak=3,
        peak_memory_kib=mean_ms + 11,
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


def test_extension_dispatch_defaults_cover_the_required_matrix() -> None:
    assert _DEFAULT_DISPATCH_LATENCIES_MS == (5.0, 20.0, 50.0)
    assert _DEFAULT_DISPATCH_CONCURRENCIES == (1, 16, 100, 500)


def test_extension_dispatch_pair_uses_per_metric_median() -> None:
    result = _median_extension_dispatch_measurement(
        [
            _dispatch_measurement(9.0),
            _dispatch_measurement(1.0),
            _dispatch_measurement(5.0),
        ]
    )

    assert result.mean_ms == 5.0
    assert result.queue_wait_p99_ms == 15.0
    assert result.peak_memory_kib == 16.0


@pytest.mark.asyncio
async def test_extension_dispatch_matrix_records_runtime_owned_worker_metrics() -> None:
    measurements = await run_extension_dispatch_matrix(
        io_latencies_ms=[1],
        concurrencies=[1, 2],
        requests_per_cell=2,
        worker_capacity=1,
        paired_repetitions=1,
    )

    assert len(measurements) == 4
    modes = {measurement.mode for measurement in measurements}
    assert modes == {"native_async", "legacy_sync"}
    assert {
        (measurement.io_latency_ms, measurement.concurrency)
        for measurement in measurements
    } == {(1.0, 1), (1.0, 2)}
    legacy = next(
        measurement
        for measurement in measurements
        if measurement.mode == "legacy_sync" and measurement.concurrency == 2
    )
    assert legacy.requests == 2
    assert legacy.worker_capacity == 1
    assert legacy.extension_worker_thread_peak >= 1
    assert legacy.queue_wait_p99_ms >= legacy.queue_wait_p50_ms >= 0
    assert legacy.thread_count_peak >= legacy.thread_count_start


@pytest.mark.asyncio
async def test_extension_dispatch_rejects_invalid_mode() -> None:
    with pytest.raises(ValueError, match="unsupported dispatch mode"):
        await measure_extension_dispatch(
            mode="unknown",
            io_latency_ms=1,
            requests=1,
            concurrency=1,
        )
