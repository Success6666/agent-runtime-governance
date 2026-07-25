from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .context import ExecutionContext, RiskTier
from .decisions import DecisionOutcome
from .runtime import InvocationOptions, Runtime


@dataclass(frozen=True, slots=True)
class RegressionCase:
    name: str
    tool_name: str
    expected: DecisionOutcome
    args: tuple[Any, ...] = ()
    kwargs: Mapping[str, Any] | None = None
    options: InvocationOptions = InvocationOptions()
    expected_risk_tier: RiskTier | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(
            self, "kwargs", MappingProxyType(dict(self.kwargs or {}))
        )


@dataclass(frozen=True, slots=True)
class RegressionResult:
    case: str
    passed: bool
    expected: DecisionOutcome
    actual: DecisionOutcome
    expected_risk_tier: RiskTier | None
    actual_risk_tier: RiskTier
    reason: str


@dataclass(frozen=True, slots=True)
class RegressionReport:
    results: tuple[RegressionResult, ...]

    @property
    def passed(self) -> int:
        return sum(result.passed for result in self.results)

    @property
    def failed(self) -> int:
        return len(self.results) - self.passed

    @property
    def success_rate(self) -> float:
        return self.passed / len(self.results) if self.results else 1.0


class EvaluationSuite:
    def __init__(self, cases: Iterable[RegressionCase]) -> None:
        self.cases = tuple(cases)
        names = [case.name for case in self.cases]
        if len(names) != len(set(names)):
            raise ValueError("regression case names must be unique")

    async def arun(
        self, runtime: Runtime, *, replayable_only: bool = True
    ) -> RegressionReport:
        results: list[RegressionResult] = []
        for case in self.cases:
            context = await runtime.apreview(
                case.tool_name,
                *case.args,
                _governance=case.options,
                replayable_only=replayable_only,
                **dict(case.kwargs or {}),
            )
            actual = _outcome(context)
            risk_matches = (
                case.expected_risk_tier is None
                or context.risk_tier is case.expected_risk_tier
            )
            results.append(
                RegressionResult(
                    case=case.name,
                    passed=actual is case.expected and risk_matches,
                    expected=case.expected,
                    actual=actual,
                    expected_risk_tier=case.expected_risk_tier,
                    actual_risk_tier=context.risk_tier,
                    reason=context.decision.reason if context.decision else "allowed",
                )
            )
        return RegressionReport(tuple(results))

    def run(
        self, runtime: Runtime, *, replayable_only: bool = True
    ) -> RegressionReport:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.arun(runtime, replayable_only=replayable_only))
        raise RuntimeError("run() cannot execute inside an event loop; use arun()")


@dataclass(frozen=True, slots=True)
class DriftRecord:
    trace_id: str
    baseline: DecisionOutcome
    candidate: DecisionOutcome
    baseline_risk_tier: RiskTier
    candidate_risk_tier: RiskTier
    baseline_requires_approval: bool
    candidate_requires_approval: bool
    baseline_policy_version: str | None
    candidate_policy_version: str | None


@dataclass(frozen=True, slots=True)
class PolicyDriftReport:
    records: tuple[DriftRecord, ...]

    @property
    def drift_detected(self) -> bool:
        return bool(self.records)


class PolicyDriftDetector:
    @staticmethod
    async def compare(
        contexts: Iterable[ExecutionContext],
        baseline: Runtime,
        candidate: Runtime,
    ) -> PolicyDriftReport:
        records: list[DriftRecord] = []
        for context in contexts:
            old = await baseline.areplay(context)
            new = await candidate.areplay(context)
            old_outcome = _outcome(old)
            new_outcome = _outcome(new)
            if (
                old_outcome is not new_outcome
                or old.risk_tier is not new.risk_tier
                or old.requires_approval != new.requires_approval
            ):
                records.append(
                    DriftRecord(
                        trace_id=context.trace_id,
                        baseline=old_outcome,
                        candidate=new_outcome,
                        baseline_risk_tier=old.risk_tier,
                        candidate_risk_tier=new.risk_tier,
                        baseline_requires_approval=old.requires_approval,
                        candidate_requires_approval=new.requires_approval,
                        baseline_policy_version=old.metadata.get("policy_version"),
                        candidate_policy_version=new.metadata.get("policy_version"),
                    )
                )
        return PolicyDriftReport(tuple(records))


def _outcome(context: ExecutionContext) -> DecisionOutcome:
    if context.denied:
        return DecisionOutcome.DENY
    return DecisionOutcome.ALLOW
