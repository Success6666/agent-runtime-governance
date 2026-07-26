from __future__ import annotations

from datetime import datetime, timezone

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
from agent_runtime_governance._serialization import thaw


def make_context(**changes: object) -> ExecutionContext:
    base = ExecutionContext.create(ToolCall("read_file", ("a.txt",), {"mode": "r"}))
    return base.evolve(**changes) if changes else base


def test_create_assigns_otel_style_identifiers() -> None:
    context = make_context()
    assert len(context.trace_id) == 32
    assert len(context.span_id) == 16


def test_from_dict_accepts_rfc3339_utc_deadline() -> None:
    context = ExecutionContext.create(
        ToolCall("read_file"),
        deadline=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    payload = context.to_dict()
    payload["deadline"] = "2026-01-01T00:00:00Z"

    restored = ExecutionContext.from_dict(payload)

    assert restored.deadline == datetime(2026, 1, 1, tzinfo=timezone.utc)
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


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ToolCall("x", kwargs={1: "integer", "1": "string"}),
        lambda: ExecutionContext.create(ToolCall("x"), metadata={1: "invalid"}),
        lambda: HistoryEntry("test", "allow", data={1: "invalid"}),
    ],
)
def test_context_rejects_non_string_mapping_keys(factory) -> None:
    with pytest.raises(TypeError, match="mapping keys must be strings"):
        factory()


def test_thaw_rejects_non_string_mapping_keys() -> None:
    with pytest.raises(TypeError, match="mapping keys must be strings"):
        thaw({1: "invalid"})


def test_context_serializes_heterogeneous_sets_deterministically() -> None:
    context = ExecutionContext.create(
        ToolCall("x"),
        metadata={"mixed": {1, "x"}},
    )

    assert context.to_dict()["metadata"]["mixed"] == [1, "x"]
    assert context.to_dict() == context.to_dict()


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


def test_approval_requirement_is_monotonic() -> None:
    context = make_context(requires_approval=True)
    with pytest.raises(ContextMutationError, match="cannot be removed"):
        context.evolve(requires_approval=False)


@pytest.mark.parametrize("value", [-0.1, 1.1])
def test_risk_score_range_is_validated(value: float) -> None:
    with pytest.raises(ValueError):
        make_context().evolve(risk_score=value)


@pytest.mark.parametrize("value", ["", " ", "\t\n"])
def test_context_rejects_blank_idempotency_keys_on_all_restore_paths(
    value: str,
) -> None:
    with pytest.raises(ValueError, match="idempotency_key cannot be empty"):
        ExecutionContext.create(ToolCall("write"), idempotency_key=value)

    payload = make_context().to_dict()
    payload["idempotency_key"] = value
    with pytest.raises(ValueError, match="idempotency_key cannot be empty"):
        ExecutionContext.from_dict(payload)


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
    base = make_context(
        risk_tier=RiskTier.HIGH,
        risk_score=0.8,
        status=ExecutionStatus.SUCCEEDED,
        result={"ok": True},
    )
    decision = DecisionRecord(
        DecisionOutcome.ALLOW,
        "approved",
        "human",
        request_id=base.request_id,
        tool_name=base.tool_call.name,
    )
    context = base.evolve(
        decision=decision,
        approval_granted=True,
        approval_request_id=base.request_id,
        approval_decision_id=decision.decision_id,
    ).append_history(HistoryEntry("rule", "allow", "safe"))
    restored = ExecutionContext.from_dict(context.to_dict())
    assert restored.to_dict() == context.to_dict()


def test_context_rejects_partial_approval_state() -> None:
    with pytest.raises(ValueError, match="requires request and decision IDs"):
        make_context(approval_granted=True)

    with pytest.raises(ValueError, match="require a granted approval"):
        make_context(approval_request_id="request")

    decision = DecisionRecord(DecisionOutcome.ALLOW, "approved", "human")
    with pytest.raises(ValueError, match="must match an allow decision"):
        make_context(
            decision=decision,
            approval_granted=True,
            approval_request_id="different-request",
            approval_decision_id=decision.decision_id,
        )


def test_denial_clears_previously_granted_approval() -> None:
    base = make_context()
    allow = DecisionRecord(
        DecisionOutcome.ALLOW,
        "approved",
        "human",
        request_id=base.request_id,
        tool_name=base.tool_call.name,
    )
    approved = base.with_decision(allow).evolve(
        approval_granted=True,
        approval_request_id=base.request_id,
        approval_decision_id=allow.decision_id,
    )

    denied = approved.with_decision(
        DecisionRecord(DecisionOutcome.DENY, "revoked", "runtime")
    )

    assert denied.approval_granted is False
    assert denied.approval_request_id is None
    assert denied.approval_decision_id is None


def test_non_json_result_uses_safe_representation() -> None:
    context = make_context(result=object())
    assert isinstance(context.to_dict()["result"], str)
