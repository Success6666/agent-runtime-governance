from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def evaluate(result: dict[str, Any], budget: dict[str, Any]) -> list[str]:
    if budget.get("measurement_set") == "extension_dispatch":
        return _evaluate_extension_dispatch(result, budget)
    return _evaluate_runtime_pair(result, budget)


def _evaluate_runtime_pair(result: dict[str, Any], budget: dict[str, Any]) -> list[str]:
    comparison = budget["comparison"]
    minimum = int(budget["minimum_requests"])
    grouped: dict[tuple[str, int], dict[str, Any]] = {
        (str(item["scenario"]), int(item["requests"])): item
        for item in result["measurements"]
    }
    failures: list[str] = []
    request_counts = sorted(
        requests
        for scenario, requests in grouped
        if scenario == comparison["candidate"] and requests >= minimum
    )
    if not request_counts:
        return [
            f"no {comparison['candidate']} measurement has at least {minimum} requests"
        ]
    for requests in request_counts:
        baseline = grouped.get((comparison["baseline"], requests))
        candidate = grouped.get((comparison["candidate"], requests))
        if baseline is None or candidate is None:
            failures.append(f"missing paired measurement for {requests} requests")
            continue
        for metric, maximum in budget["limits"].items():
            source = metric.removesuffix("_ratio")
            try:
                denominator = float(baseline[source])
            except (KeyError, TypeError, ValueError):
                failures.append(f"baseline {source} must be finite and positive")
                continue
            try:
                numerator = float(candidate[source])
            except (KeyError, TypeError, ValueError):
                failures.append(
                    f"candidate {source} must be finite and non-negative"
                )
                continue
            try:
                limit = float(maximum)
            except (TypeError, ValueError):
                failures.append(
                    f"budget limit for {source} must be finite and non-negative"
                )
                continue
            if not math.isfinite(denominator) or denominator <= 0:
                failures.append(f"baseline {source} must be finite and positive")
                continue
            if not math.isfinite(numerator) or numerator < 0:
                failures.append(
                    f"candidate {source} must be finite and non-negative"
                )
                continue
            if not math.isfinite(limit) or limit < 0:
                failures.append(
                    f"budget limit for {source} must be finite and non-negative"
                )
                continue
            ratio = numerator / denominator
            if ratio > limit:
                failures.append(
                    f"{source} ratio {ratio:.3f} exceeds {limit:.3f} "
                    f"at {requests} requests"
                )
    return failures


def _evaluate_extension_dispatch(
    result: dict[str, Any],
    budget: dict[str, Any],
) -> list[str]:
    dispatch = result.get("extension_dispatch")
    if not isinstance(dispatch, dict):
        return ["missing extension_dispatch benchmark result"]
    measurements = dispatch.get("measurements")
    if not isinstance(measurements, list):
        return ["extension_dispatch measurements must be a list"]

    comparison = budget["comparison"]
    baseline_mode = str(comparison["baseline"])
    candidate_mode = str(comparison["candidate"])
    grouped: dict[tuple[str, float, int], dict[str, Any]] = {}
    failures: list[str] = []
    for item in measurements:
        try:
            key = (
                str(item["mode"]),
                float(item["io_latency_ms"]),
                int(item["concurrency"]),
            )
        except (KeyError, TypeError, ValueError):
            failures.append("dispatch measurement has an invalid cell identity")
            continue
        if key in grouped:
            failures.append(
                "duplicate dispatch measurement for "
                f"{key[0]} at {key[1]:g} ms / {key[2]} concurrency"
            )
            continue
        grouped[key] = item

    try:
        latencies_ms = tuple(float(value) for value in budget["latencies_ms"])
        concurrencies = tuple(int(value) for value in budget["concurrencies"])
        minimum_requests = int(budget["minimum_requests_per_cell"])
        limits_by_concurrency = budget["limits_by_concurrency"]
    except (KeyError, TypeError, ValueError):
        return failures + ["extension dispatch budget is invalid"]
    if minimum_requests < 1:
        return failures + ["extension dispatch minimum_requests_per_cell must be positive"]
    configured_worker_capacity = budget.get("worker_capacity")
    if configured_worker_capacity is not None:
        try:
            configured_worker_capacity = int(configured_worker_capacity)
        except (TypeError, ValueError):
            return failures + ["extension dispatch worker_capacity must be positive"]
        if configured_worker_capacity < 1:
            return failures + ["extension dispatch worker_capacity must be positive"]

    for io_latency_ms in latencies_ms:
        for concurrency in concurrencies:
            label = f"{io_latency_ms:g} ms / {concurrency} concurrency"
            baseline = grouped.get((baseline_mode, io_latency_ms, concurrency))
            candidate = grouped.get((candidate_mode, io_latency_ms, concurrency))
            if baseline is None or candidate is None:
                failures.append(f"missing dispatch pair at {label}")
                continue
            for mode, measurement in (
                (baseline_mode, baseline),
                (candidate_mode, candidate),
            ):
                try:
                    requests = int(measurement["requests"])
                except (KeyError, TypeError, ValueError):
                    failures.append(
                        f"{mode} dispatch requests must be a positive integer at {label}"
                    )
                    continue
                if requests < minimum_requests:
                    failures.append(
                        f"{mode} dispatch requests {requests} are below "
                        f"{minimum_requests} at {label}"
                    )
                if configured_worker_capacity is not None:
                    try:
                        worker_capacity = int(measurement["worker_capacity"])
                    except (KeyError, TypeError, ValueError):
                        failures.append(
                            f"{mode} dispatch worker_capacity must be a positive "
                            f"integer at {label}"
                        )
                        continue
                    if worker_capacity != configured_worker_capacity:
                        failures.append(
                            f"{mode} dispatch worker_capacity {worker_capacity} "
                            f"does not match {configured_worker_capacity} at {label}"
                        )
            cell_limits = limits_by_concurrency.get(str(concurrency))
            if not isinstance(cell_limits, dict):
                failures.append(f"missing dispatch budget for {concurrency} concurrency")
                continue
            failures.extend(
                _evaluate_dispatch_ratios(
                    baseline,
                    candidate,
                    maximum_ratios=cell_limits.get("maximum_ratios", {}),
                    minimum_ratios=cell_limits.get("minimum_ratios", {}),
                    label=label,
                )
            )
    return failures


def _evaluate_dispatch_ratios(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    *,
    maximum_ratios: Any,
    minimum_ratios: Any,
    label: str,
) -> list[str]:
    if not isinstance(maximum_ratios, dict) or not isinstance(minimum_ratios, dict):
        return [f"dispatch ratio limits must be objects at {label}"]
    failures: list[str] = []
    for metric, maximum in maximum_ratios.items():
        ratio, error = _dispatch_ratio(
            baseline,
            candidate,
            metric=str(metric),
            label=label,
        )
        if error is not None:
            failures.append(error)
            continue
        try:
            limit = float(maximum)
        except (TypeError, ValueError):
            failures.append(
                f"dispatch maximum ratio for {metric} must be finite and non-negative"
            )
            continue
        if not math.isfinite(limit) or limit < 0:
            failures.append(
                f"dispatch maximum ratio for {metric} must be finite and non-negative"
            )
            continue
        assert ratio is not None
        if ratio > limit:
            failures.append(
                f"dispatch {metric} ratio {ratio:.3f} exceeds {limit:.3f} at {label}"
            )
    for metric, minimum in minimum_ratios.items():
        ratio, error = _dispatch_ratio(
            baseline,
            candidate,
            metric=str(metric),
            label=label,
        )
        if error is not None:
            failures.append(error)
            continue
        try:
            limit = float(minimum)
        except (TypeError, ValueError):
            failures.append(
                f"dispatch minimum ratio for {metric} must be finite and non-negative"
            )
            continue
        if not math.isfinite(limit) or limit < 0:
            failures.append(
                f"dispatch minimum ratio for {metric} must be finite and non-negative"
            )
            continue
        assert ratio is not None
        if ratio < limit:
            failures.append(
                f"dispatch {metric} ratio {ratio:.3f} is below {limit:.3f} at {label}"
            )
    return failures


def _dispatch_ratio(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    *,
    metric: str,
    label: str,
) -> tuple[float | None, str | None]:
    try:
        denominator = float(baseline[metric])
    except (KeyError, TypeError, ValueError):
        return None, f"dispatch baseline {metric} must be finite and positive at {label}"
    try:
        numerator = float(candidate[metric])
    except (KeyError, TypeError, ValueError):
        return (
            None,
            f"dispatch candidate {metric} must be finite and non-negative at {label}",
        )
    if not math.isfinite(denominator) or denominator <= 0:
        return None, f"dispatch baseline {metric} must be finite and positive at {label}"
    if not math.isfinite(numerator) or numerator < 0:
        return (
            None,
            f"dispatch candidate {metric} must be finite and non-negative at {label}",
        )
    return numerator / denominator, None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check paired runtime benchmark measurements against a budget."
    )
    parser.add_argument("result", type=Path)
    parser.add_argument(
        "--budget",
        type=Path,
        default=Path("benchmarks/budgets/v0.6.0.json"),
    )
    args = parser.parse_args()
    result = json.loads(args.result.read_text(encoding="utf-8"))
    budget = json.loads(args.budget.read_text(encoding="utf-8"))
    failures = evaluate(result, budget)
    if failures:
        for failure in failures:
            print(f"benchmark budget failed: {failure}")
        return 1
    print("benchmark budget passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
