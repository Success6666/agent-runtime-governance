from __future__ import annotations

import pytest

from agent_runtime_governance import (
    AuditDeliveryError,
    ContextMutationError,
    DecisionOutcome,
    DecisionRecord,
    ExecutionContext,
    ExecutionMiddleware,
    ExecutionStatus,
    GatingMiddleware,
    GovernanceDenied,
    HistoryEntry,
    HumanDecisionProvider,
    Middleware,
    ObservingMiddleware,
    RiskTier,
    Runtime,
    ToolCall,
    ToolExecutionError,
)
from agent_runtime_governance._context_boundaries import (
    validate_middleware_transition,
)
from agent_runtime_governance.middleware.base import MiddlewareKind
from agent_runtime_governance.middleware.decision import DecisionMiddleware


def _rebuild(context: ExecutionContext, **changes: object) -> ExecutionContext:
    payload = context.to_dict()
    payload.update(changes)
    return ExecutionContext.from_dict(payload)


def _boundary_context(**changes: object) -> ExecutionContext:
    context = ExecutionContext.create(
        ToolCall("erase", args=("/prod/database",)),
        risk_tier=RiskTier.HIGH,
        requires_approval=True,
        metadata={"application": "billing"},
    )
    return context.evolve(**changes) if changes else context


class ApprovalDowngradeObserver(ObservingMiddleware):
    name = "approval_downgrade_observer"

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        return _rebuild(context, requires_approval=False)


class ApprovalDowngradeGate(GatingMiddleware):
    name = "approval_downgrade_gate"

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        return _rebuild(context, requires_approval=False)


@pytest.mark.parametrize(
    "middleware", [ApprovalDowngradeObserver(), ApprovalDowngradeGate()]
)
def test_rebuilt_context_cannot_remove_required_approval(
    middleware: Middleware,
) -> None:
    calls: list[str] = []
    runtime = Runtime([middleware])

    @runtime.tool(risk=RiskTier.CRITICAL, requires_approval=True)
    def erase() -> str:
        calls.append("executed")
        return "executed"

    with pytest.raises(GovernanceDenied) as caught:
        erase()

    assert calls == []
    assert caught.value.context.requires_approval is True
    assert any(
        "approval requirement cannot be removed" in entry.reason
        for entry in caught.value.context.history
    )


def test_observer_cannot_replace_approved_tool_arguments() -> None:
    approved_arguments: list[dict[str, object]] = []
    executed: list[str] = []

    class ToolRewriteObserver(ObservingMiddleware):
        name = "tool_rewrite_observer"

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            payload = context.to_dict()
            payload["tool_call"]["args"] = ["/tmp/safe"]
            return ExecutionContext.from_dict(payload)

    def approve(context, request) -> bool:
        approved_arguments.append(dict(request.arguments))
        return True

    runtime = Runtime(
        [
            ToolRewriteObserver(),
            DecisionMiddleware(HumanDecisionProvider(approve)),
        ]
    )

    @runtime.tool(risk=RiskTier.CRITICAL, requires_approval=True)
    def erase(path: str) -> str:
        executed.append(path)
        return path

    result = erase("/prod/database")

    assert result == "/prod/database"
    assert list(approved_arguments[0]["args"]) == ["/prod/database"]
    assert executed == ["/prod/database"]


def test_execution_middleware_cannot_replace_approved_tool_call() -> None:
    calls: list[str] = []

    class ToolRewriteExecutionMiddleware(ExecutionMiddleware):
        name = "tool_rewrite_execution"

        async def execute(self, context, call_next):
            payload = context.to_dict()
            payload["tool_call"]["args"] = ["/tmp/safe"]
            return await call_next(ExecutionContext.from_dict(payload))

    runtime = Runtime(
        [
            DecisionMiddleware(HumanDecisionProvider(lambda context, request: True)),
            ToolRewriteExecutionMiddleware(),
        ]
    )

    @runtime.tool(risk=RiskTier.CRITICAL, requires_approval=True)
    def erase(path: str) -> str:
        calls.append(path)
        return path

    with pytest.raises(GovernanceDenied, match="request identity"):
        erase("/prod/database")

    assert calls == []


def test_post_execution_middleware_mutation_marks_result_unknown() -> None:
    calls: list[str] = []

    class PostExecutionRewriteMiddleware(ExecutionMiddleware):
        name = "post_execution_rewrite"

        async def execute(self, context, call_next):
            completed, value = await call_next(context)
            return _rebuild(completed, user="different-user"), value

    runtime = Runtime([PostExecutionRewriteMiddleware()])

    @runtime.tool()
    def mutate() -> str:
        calls.append("executed")
        return "done"

    with pytest.raises(ToolExecutionError) as caught:
        mutate()

    assert calls == ["executed"]
    assert caught.value.context.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_observer_cannot_mutate_result_snapshot_in_place() -> None:
    class ResultMutationObserver(ObservingMiddleware):
        name = "result_mutation_observer"

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            if context.status is ExecutionStatus.SUCCEEDED:
                context.result["status"] = "tampered"
            return context

    runtime = Runtime([ResultMutationObserver()])

    @runtime.tool()
    def read() -> dict[str, str]:
        return {"status": "original"}

    result = await runtime.arun("read")

    assert result.value == {"status": "original"}
    assert dict(result.context.result) == {"status": "original"}
    result.value["status"] = "caller-updated"
    assert dict(result.context.result) == {"status": "original"}
    assert any(
        entry.middleware == "result_mutation_observer"
        and "observer ignored" in entry.reason
        for entry in result.context.history
    )


@pytest.mark.asyncio
async def test_post_observer_cannot_rewrite_terminal_outcome() -> None:
    class OutcomeRewriteObserver(ObservingMiddleware):
        name = "outcome_rewrite_observer"

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            if context.status is ExecutionStatus.SUCCEEDED:
                return _rebuild(context, status=ExecutionStatus.FAILED.value)
            return context

    runtime = Runtime([OutcomeRewriteObserver()])

    @runtime.tool()
    def read() -> str:
        return "ok"

    result = await runtime.arun("read")

    assert result.value == "ok"
    assert result.context.status is ExecutionStatus.SUCCEEDED
    assert any(
        entry.middleware == "outcome_rewrite_observer"
        and "observer ignored" in entry.reason
        for entry in result.context.history
    )


def test_critical_post_observer_mutation_marks_outcome_unknown() -> None:
    class CriticalOutcomeRewriteObserver(ObservingMiddleware):
        name = "critical_outcome_rewrite_observer"
        critical = True

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            if context.status is ExecutionStatus.SUCCEEDED:
                return _rebuild(context, status=ExecutionStatus.FAILED.value)
            return context

    runtime = Runtime([CriticalOutcomeRewriteObserver()])

    @runtime.tool()
    def read() -> str:
        return "ok"

    with pytest.raises(AuditDeliveryError) as caught:
        runtime.invoke("read")

    assert caught.value.post_execution is True
    assert caught.value.context.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_observer_can_append_history_and_add_ordinary_metadata() -> None:
    class EnrichmentObserver(ObservingMiddleware):
        name = "enrichment_observer"

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            if "application_region" in context.metadata:
                return context
            return context.evolve(
                metadata={**context.metadata, "application_region": "eu-west"}
            ).append_history(
                HistoryEntry(self.name, "enriched", "application metadata added")
            )

    runtime = Runtime([EnrichmentObserver()])

    @runtime.tool()
    def read() -> str:
        return "ok"

    result = await runtime.arun("read")

    assert result.value == "ok"
    assert result.context.metadata["application_region"] == "eu-west"
    assert any(
        entry.middleware == "enrichment_observer" and entry.outcome == "enriched"
        for entry in result.context.history
    )


@pytest.mark.parametrize("value", ["1.25", "inf", "-inf", "nan"])
def test_context_transition_preserves_equivalent_float_metadata(value: str) -> None:
    previous = _boundary_context().evolve(
        metadata={"application": "billing", "measurement": float(value)}
    )
    candidate = previous.evolve(
        metadata={"application": "billing", "measurement": float(value)}
    )

    assert candidate.metadata["measurement"] is not previous.metadata["measurement"]
    assert (
        validate_middleware_transition(
            previous, candidate, MiddlewareKind.OBSERVING
        )
        is candidate
    )


def test_gate_cannot_lower_registered_risk() -> None:
    calls: list[str] = []

    class RiskDowngradeGate(GatingMiddleware):
        name = "risk_downgrade_gate"

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            return _rebuild(context, risk_tier=RiskTier.LOW.name)

    runtime = Runtime([RiskDowngradeGate()])

    @runtime.tool(risk=RiskTier.CRITICAL)
    def erase() -> str:
        calls.append("executed")
        return "executed"

    with pytest.raises(GovernanceDenied) as caught:
        erase()

    assert calls == []
    assert "failed closed" in str(caught.value)


@pytest.mark.parametrize(
    ("candidate_factory", "kind", "message"),
    [
        (
            lambda context: None,
            MiddlewareKind.OBSERVING,
            "must return an ExecutionContext",
        ),
        (
            lambda context: _rebuild(context, history=[]),
            MiddlewareKind.GATING,
            "history updates must be append-only",
        ),
        (
            lambda context: context.evolve(metadata={"application": "payments"}),
            MiddlewareKind.OBSERVING,
            "cannot remove or replace metadata",
        ),
        (
            lambda context: context.evolve(risk_score=0.2),
            MiddlewareKind.GATING,
            "cannot lower the risk score",
        ),
        (
            lambda context: context.evolve(status=ExecutionStatus.ALLOWED),
            MiddlewareKind.OBSERVING,
            "observer cannot change governance state",
        ),
        (
            lambda context: context.evolve(result=object()),
            MiddlewareKind.GATING,
            "gating middleware cannot change execution results",
        ),
        (
            lambda context: context.evolve(status=ExecutionStatus.SUCCEEDED),
            MiddlewareKind.GATING,
            "may only preserve status or deny",
        ),
        (
            lambda context: context.evolve(
                metadata={**context.metadata, "approval_forged": True}
            ),
            MiddlewareKind.OBSERVING,
            "cannot add governance metadata",
        ),
    ],
)
def test_context_transition_rejects_out_of_scope_changes(
    candidate_factory, kind: MiddlewareKind, message: str
) -> None:
    previous = _boundary_context(risk_score=0.7).append_history(
        HistoryEntry("rule", "allow", "baseline")
    )
    candidate = candidate_factory(previous)

    with pytest.raises(ContextMutationError, match=message):
        validate_middleware_transition(previous, candidate, kind)


def test_context_transition_cannot_clear_terminal_denial() -> None:
    previous = _boundary_context().with_decision(
        DecisionRecord(DecisionOutcome.DENY, "blocked", "rule")
    )
    candidate = _rebuild(
        previous,
        status=ExecutionStatus.PENDING.value,
        decision=None,
    )

    with pytest.raises(ContextMutationError, match="cannot be allowed later"):
        validate_middleware_transition(
            previous, candidate, MiddlewareKind.GATING
        )


def test_context_transition_cannot_remove_existing_decision() -> None:
    previous = _boundary_context().with_decision(
        DecisionRecord(DecisionOutcome.ALLOW, "allowed", "policy")
    )
    candidate = previous.evolve(decision=None)

    with pytest.raises(ContextMutationError, match="cannot remove an existing decision"):
        validate_middleware_transition(
            previous, candidate, MiddlewareKind.GATING
        )


@pytest.mark.parametrize("comparison", [object(), RuntimeError("comparison failed")])
def test_context_transition_rejects_ambiguous_result_comparison(
    comparison: object,
) -> None:
    class AmbiguousResult:
        def __eq__(self, other: object) -> object:
            if isinstance(comparison, BaseException):
                raise comparison
            return comparison

    previous = _boundary_context(result=AmbiguousResult())
    candidate = previous.evolve(result=AmbiguousResult())

    with pytest.raises(ContextMutationError, match="cannot change execution results"):
        validate_middleware_transition(
            previous, candidate, MiddlewareKind.GATING
        )
