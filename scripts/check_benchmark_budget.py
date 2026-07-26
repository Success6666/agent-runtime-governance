from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def evaluate(result: dict[str, Any], budget: dict[str, Any]) -> list[str]:
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
