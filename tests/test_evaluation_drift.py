from __future__ import annotations

import pytest

from agent_runtime_governance import (
    DecisionOutcome,
    EvaluationSuite,
    ExecutionContext,
    GovernanceDenied,
    InvocationOptions,
    LLMMiddleware,
    PolicyDriftDetector,
    PolicyMiddleware,
    RegressionCase,
    RiskTier,
    Rule,
    RuleMiddleware,
    Runtime,
    SimplePolicy,
    ToolCall,
)


def runtime_with_policy(policy: SimplePolicy) -> Runtime:
    runtime = Runtime([PolicyMiddleware(policy)])

    @runtime.tool()
    def operate() -> bool:
        return True

    return runtime


def test_evaluation_suite_reports_success_rate() -> None:
    runtime = Runtime([RuleMiddleware([Rule("block", r"\bblock\b", "blocked")])])

    @runtime.tool()
    def work() -> bool:
        return True

    suite = EvaluationSuite(
        [
            RegressionCase("allow", "work", DecisionOutcome.ALLOW),
            RegressionCase(
                "deny",
                "work",
                DecisionOutcome.DENY,
                options=InvocationOptions(input_text="block this"),
            ),
        ]
    )
    report = suite.run(runtime)
    assert report.passed == 2
    assert report.failed == 0
    assert report.success_rate == 1.0


def test_evaluation_reports_mismatch() -> None:
    runtime = runtime_with_policy(SimplePolicy())
    report = EvaluationSuite(
        [RegressionCase("wrong", "operate", DecisionOutcome.DENY)]
    ).run(runtime)
    assert report.failed == 1
    assert report.results[0].actual is DecisionOutcome.ALLOW


def test_evaluation_validates_expected_risk() -> None:
    runtime = runtime_with_policy(
        SimplePolicy(risk_overrides={"operate": RiskTier.HIGH})
    )
    report = EvaluationSuite(
        [
            RegressionCase(
                "risk", "operate", DecisionOutcome.ALLOW, expected_risk_tier=RiskTier.HIGH
            )
        ]
    ).run(runtime)
    assert report.passed == 1


def test_duplicate_regression_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="unique"):
        EvaluationSuite(
            [
                RegressionCase("same", "x", DecisionOutcome.ALLOW),
                RegressionCase("same", "x", DecisionOutcome.DENY),
            ]
        )


@pytest.mark.asyncio
async def test_policy_drift_detects_allow_to_deny() -> None:
    baseline = runtime_with_policy(SimplePolicy())
    candidate = runtime_with_policy(SimplePolicy(denied_tools={"operate"}))
    context = ExecutionContext.create(ToolCall("operate"))
    report = await PolicyDriftDetector.compare([context], baseline, candidate)
    assert report.drift_detected
    assert report.records[0].baseline is DecisionOutcome.ALLOW
    assert report.records[0].candidate is DecisionOutcome.DENY


@pytest.mark.asyncio
async def test_policy_drift_detects_risk_change() -> None:
    baseline = runtime_with_policy(SimplePolicy())
    candidate = runtime_with_policy(
        SimplePolicy(risk_overrides={"operate": RiskTier.CRITICAL})
    )
    context = ExecutionContext.create(ToolCall("operate"))
    report = await PolicyDriftDetector.compare([context], baseline, candidate)
    assert report.records[0].candidate_risk_tier is RiskTier.CRITICAL


@pytest.mark.asyncio
async def test_policy_drift_reports_approval_change() -> None:
    baseline = runtime_with_policy(SimplePolicy())
    candidate = runtime_with_policy(SimplePolicy(approval_tools={"operate"}))
    context = ExecutionContext.create(ToolCall("operate"))
    report = await PolicyDriftDetector.compare([context], baseline, candidate)
    assert not report.records[0].baseline_requires_approval
    assert report.records[0].candidate_requires_approval


@pytest.mark.asyncio
async def test_policy_drift_ignores_identical_policy() -> None:
    baseline = runtime_with_policy(SimplePolicy())
    candidate = runtime_with_policy(SimplePolicy())
    context = ExecutionContext.create(ToolCall("operate"))
    report = await PolicyDriftDetector.compare([context], baseline, candidate)
    assert not report.drift_detected


@pytest.mark.asyncio
async def test_replay_preserves_recorded_trace_identity() -> None:
    runtime = runtime_with_policy(SimplePolicy())
    context = ExecutionContext.create(ToolCall("operate"))
    replayed = await runtime.areplay(context)
    assert replayed.trace_id == context.trace_id
    assert replayed.request_id == context.request_id


@pytest.mark.asyncio
async def test_replay_skips_non_replayable_llm() -> None:
    called = False

    def review(context):
        nonlocal called
        called = True
        return False

    runtime = Runtime([LLMMiddleware(review)])

    @runtime.tool()
    def operate() -> bool:
        return True

    context = ExecutionContext.create(ToolCall("operate"))
    replayed = await runtime.areplay(context)
    assert not called
    assert not replayed.denied


def test_declared_approval_without_middleware_fails_closed() -> None:
    runtime = Runtime()

    @runtime.tool(requires_approval=True)
    def operate() -> bool:
        return True

    with pytest.raises(GovernanceDenied, match="not granted"):
        operate()
