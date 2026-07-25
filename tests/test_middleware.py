from __future__ import annotations

import pytest

from agent_runtime_governance import (
    ApprovalMiddleware,
    DecisionOutcome,
    GovernanceDenied,
    HumanDecisionProvider,
    InvocationOptions,
    LLMMiddleware,
    RiskTier,
    Rule,
    RuleMiddleware,
    Runtime,
    SemanticReview,
)


def register_tool(runtime: Runtime, *, approval: bool = False):
    @runtime.tool(risk=RiskTier.HIGH, requires_approval=approval)
    def delete(path: str) -> str:
        return path

    return delete


def test_rule_uses_explicit_regex_not_substring_matching() -> None:
    runtime = Runtime([RuleMiddleware([Rule("delete", r"\bdelete\b", "blocked")])])
    tool = register_tool(runtime)
    assert tool("report") == "report"


def test_rule_blocks_unambiguous_match() -> None:
    runtime = Runtime([RuleMiddleware([Rule("delete", r"\bdelete\b", "blocked")])])
    register_tool(runtime)
    with pytest.raises(GovernanceDenied):
        runtime.invoke(
            "delete", "report", _governance=InvocationOptions(input_text="delete everything")
        )


def test_llm_boolean_allow() -> None:
    runtime = Runtime([LLMMiddleware(lambda context: True)])
    tool = register_tool(runtime)
    assert tool("ok") == "ok"


def test_llm_denial_carries_risk_score() -> None:
    runtime = Runtime(
        [LLMMiddleware(lambda context: SemanticReview(DecisionOutcome.DENY, "unsafe", 0.9))]
    )
    register_tool(runtime)
    with pytest.raises(GovernanceDenied) as caught:
        runtime.invoke("delete", "x")
    assert caught.value.context.risk_score == 0.9


def test_llm_can_escalate_to_human_decision() -> None:
    runtime = Runtime(
        [
            LLMMiddleware(lambda context: DecisionOutcome.REQUIRE_HUMAN),
            ApprovalMiddleware(HumanDecisionProvider(lambda context, request: True)),
        ]
    )
    tool = register_tool(runtime)
    assert tool("x") == "x"


def test_human_decision_allows_high_risk_tool() -> None:
    runtime = Runtime(
        [ApprovalMiddleware(HumanDecisionProvider(lambda context, request: True))]
    )
    tool = register_tool(runtime, approval=True)
    assert tool("x") == "x"


def test_human_decision_denies_high_risk_tool() -> None:
    runtime = Runtime(
        [ApprovalMiddleware(HumanDecisionProvider(lambda context, request: False))]
    )
    register_tool(runtime, approval=True)
    with pytest.raises(GovernanceDenied):
        runtime.invoke("delete", "x")


@pytest.mark.asyncio
async def test_async_human_decision_callback() -> None:
    async def approve(context, request):
        return DecisionOutcome.ALLOW

    runtime = Runtime([ApprovalMiddleware(HumanDecisionProvider(approve))])
    register_tool(runtime, approval=True)
    assert await runtime.ainvoke("delete", "x") == "x"


def test_invalid_human_decision_fails_closed() -> None:
    runtime = Runtime(
        [ApprovalMiddleware(HumanDecisionProvider(lambda context, request: "yes"))]
    )
    register_tool(runtime, approval=True)
    with pytest.raises(GovernanceDenied):
        runtime.invoke("delete", "x")

