from __future__ import annotations

import pytest

from agent_runtime_governance import (
    ContextMutationError,
    DecisionOutcome,
    DecisionRecord,
    ExecutionContext,
    ExecutionStatus,
    HistoryEntry,
    RiskTier,
    ToolCall,
)


def make_context(**changes: object) -> ExecutionContext:
    base = ExecutionContext.create(ToolCall("read_file", ("a.txt",), {"mode": "r"}))
    return base.evolve(**changes) if changes else base


def test_create_assigns_otel_style_identifiers() -> None:
    context = make_context()
    assert len(context.trace_id) == 32
    assert len(context.span_id) == 16
    assert len(context.request_id) == 32


def test_context_freezes_nested_metadata() -> None:
    context = ExecutionContext.create(
        ToolCall("x"), metadata={"nested": {"items": [1, 2]}}
    )
    with pytest.raises(TypeError):
        context.metadata["new"] = True  # type: ignore[index]
    with pytest.raises(TypeError):
        context.metadata["nested"]["items"] = ()  # type: ignore[index]


def test_context_freezes_tool_arguments() -> None:
    call = ToolCall("x", kwargs={"options": {"force": False}})
    with pytest.raises(TypeError):
        call.kwargs["options"]["force"] = True  # type: ignore[index]


@pytest.mark.parametrize("field", ["trace_id", "user", "tenant", "tool_call", "input_text"])
def test_evolve_rejects_identity_changes(field: str) -> None:
    with pytest.raises(ContextMutationError):
        make_context().evolve(**{field: "changed"})


def test_evolve_returns_new_context() -> None:
    original = make_context()
    updated = original.evolve(risk_score=0.4)
    assert original.risk_score == 0.0
    assert updated.risk_score == 0.4
    assert updated is not original


@pytest.mark.parametrize("value", [-0.1, 1.1])
def test_risk_score_range_is_validated(value: float) -> None:
    with pytest.raises(ValueError):
        make_context().evolve(risk_score=value)


def test_history_is_append_only() -> None:
    original = make_context()
    updated = original.append_history(HistoryEntry("rule", "allow"))
    assert original.history == ()
    assert updated.history[-1].middleware == "rule"


def test_history_cannot_be_replaced_through_evolve() -> None:
    with pytest.raises(ContextMutationError):
        make_context().evolve(history=())


def test_deny_decision_sets_terminal_status() -> None:
    context = make_context().with_decision(
        DecisionRecord(DecisionOutcome.DENY, "blocked", "test")
    )
    assert context.denied
    assert context.status is ExecutionStatus.DENIED


def test_denial_cannot_be_overridden() -> None:
    context = make_context().with_decision(
        DecisionRecord(DecisionOutcome.DENY, "blocked", "test")
    )
    with pytest.raises(ContextMutationError):
        context.evolve(
            status=ExecutionStatus.ALLOWED,
            decision=DecisionRecord(DecisionOutcome.ALLOW, "override", "test"),
        )


def test_context_round_trip_preserves_governance_state() -> None:
    context = make_context(
        risk_tier=RiskTier.HIGH,
        risk_score=0.8,
        status=ExecutionStatus.SUCCEEDED,
        result={"ok": True},
    ).append_history(HistoryEntry("rule", "allow", "safe"))
    restored = ExecutionContext.from_dict(context.to_dict())
    assert restored.to_dict() == context.to_dict()


def test_non_json_result_uses_safe_representation() -> None:
    context = make_context(result=object())
    assert isinstance(context.to_dict()["result"], str)
