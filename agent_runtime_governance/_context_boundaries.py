from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .context import ExecutionContext, ExecutionStatus
from .errors import ContextMutationError
from .middleware.base import MiddlewareKind

_GOVERNANCE_METADATA_PREFIXES = ("approval_", "identity_", "policy_")
_RUNTIME_METADATA_KEYS = frozenset({"duration_ms"})


def validate_middleware_transition(
    previous: ExecutionContext,
    candidate: ExecutionContext,
    kind: MiddlewareKind,
) -> ExecutionContext:
    """Validate a middleware-owned context transition before accepting it."""
    if not isinstance(candidate, ExecutionContext):
        raise ContextMutationError("middleware must return an ExecutionContext")
    if _request_state(candidate) != _request_state(previous):
        raise ContextMutationError(
            "middleware cannot change request identity or tool execution fields"
        )
    if not _history_is_append_only(previous, candidate):
        raise ContextMutationError("middleware history updates must be append-only")
    _validate_metadata(previous.metadata, candidate.metadata, kind)

    if previous.denied and not candidate.denied:
        raise ContextMutationError("a denied context cannot be allowed later")
    if previous.requires_approval and not candidate.requires_approval:
        raise ContextMutationError("an approval requirement cannot be removed")
    if candidate.risk_tier < previous.risk_tier:
        raise ContextMutationError("middleware cannot lower the risk tier")
    if candidate.risk_score < previous.risk_score:
        raise ContextMutationError("middleware cannot lower the risk score")

    if kind in {MiddlewareKind.OBSERVING, MiddlewareKind.EXECUTION}:
        if (
            _governance_state(candidate) != _governance_state(previous)
            or not _same_result(candidate.result, previous.result)
        ):
            label = (
                "observer"
                if kind is MiddlewareKind.OBSERVING
                else "execution middleware"
            )
            raise ContextMutationError(f"{label} cannot change governance state")
        return candidate

    if not _same_result(candidate.result, previous.result) or (
        candidate.error != previous.error
    ):
        raise ContextMutationError("gating middleware cannot change execution results")
    if candidate.status not in {previous.status, ExecutionStatus.DENIED}:
        raise ContextMutationError(
            "gating middleware may only preserve status or deny execution"
        )
    if previous.decision is not None and candidate.decision is None:
        raise ContextMutationError("middleware cannot remove an existing decision")
    return candidate


def _request_state(context: ExecutionContext) -> tuple[object, ...]:
    return (
        context.trace_id,
        context.span_id,
        context.parent_span_id,
        context.request_id,
        context.task_id,
        context.conversation_id,
        context.user,
        context.tenant,
        context.permissions,
        context.tool_call,
        context.input_text,
        context.execution_mode,
        context.idempotency_key,
        context.deadline,
    )


def _governance_state(context: ExecutionContext) -> tuple[object, ...]:
    return (
        context.risk_tier,
        context.risk_score,
        context.requires_approval,
        context.approval_granted,
        context.approval_request_id,
        context.approval_decision_id,
        context.status,
        context.decision,
        context.error,
    )


def _history_is_append_only(
    previous: ExecutionContext, candidate: ExecutionContext
) -> bool:
    prefix_length = len(previous.history)
    return (
        len(candidate.history) >= prefix_length
        and candidate.history[:prefix_length] == previous.history
    )


def _validate_metadata(
    previous: Mapping[str, Any],
    candidate: Mapping[str, Any],
    kind: MiddlewareKind,
) -> None:
    for key, value in previous.items():
        if key not in candidate or candidate[key] != value:
            raise ContextMutationError(
                f"middleware cannot remove or replace metadata key {key!r}"
            )
    for key in candidate.keys() - previous.keys():
        if _is_governance_metadata(key) and not (
            kind is MiddlewareKind.GATING and key.lower().startswith("policy_")
        ):
            raise ContextMutationError(
                f"{kind.value} middleware cannot add governance metadata key {key!r}"
            )


def _is_governance_metadata(key: str) -> bool:
    normalized = key.lower()
    return normalized in _RUNTIME_METADATA_KEYS or normalized.startswith(
        _GOVERNANCE_METADATA_PREFIXES
    )


def _same_result(left: object, right: object) -> bool:
    if left is right:
        return True
    try:
        comparison = left == right
        return comparison if isinstance(comparison, bool) else False
    except Exception:
        return False
