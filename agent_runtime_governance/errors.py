from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import ExecutionContext


class GovernanceError(Exception):
    """Base exception for runtime governance failures."""


class GovernanceDenied(GovernanceError):
    """Raised when a gating middleware denies a tool call."""

    def __init__(self, context: "ExecutionContext") -> None:
        self.context = context
        reason = context.decision.reason if context.decision else "denied"
        super().__init__(reason)


class GovernanceCancelledError(asyncio.CancelledError):
    """Cancellation carrier for the final governed context."""

    def __init__(self, context: "ExecutionContext") -> None:
        self.context = context
        super().__init__("governed execution cancelled")


def get_cancellation_context(
    error: BaseException,
) -> "ExecutionContext | None":
    """Recover governed cancellation state across supported Python versions.

    Python 3.10 re-materializes ``CancelledError`` when a cancelled task is
    awaited, so custom attributes survive only on the chained carrier.
    """
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, GovernanceCancelledError):
            return current.context
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return None


class MiddlewareExecutionError(GovernanceError):
    """Raised when a gating middleware fails closed."""


class ToolExecutionError(GovernanceError):
    """Raised when a governed tool fails."""

    def __init__(self, context: "ExecutionContext", cause: BaseException) -> None:
        self.context = context
        self.cause = cause
        execution_record_id = getattr(cause, "execution_record_id", None)
        if execution_record_id is None:
            execution_record_id = context.metadata.get("execution_record_id")
        self.execution_record_id = (
            execution_record_id if isinstance(execution_record_id, str) else None
        )
        super().__init__(f"tool {context.tool_call.name!r} failed: {cause}")


class ExecutionControlError(GovernanceError):
    """Internal carrier for execution middleware state and its root cause."""

    def __init__(self, context: "ExecutionContext", cause: Exception) -> None:
        self.context = context
        self.cause = cause
        super().__init__(str(cause))


class RegistryError(GovernanceError):
    """Raised for invalid or duplicate tool registration."""


class ContextMutationError(GovernanceError):
    """Raised when middleware attempts to alter immutable identity fields."""


class AuditIntegrityError(GovernanceError):
    """Raised when a signed audit event fails verification."""


class ContractValidationError(GovernanceError):
    """A tool parameter or result violated its declared JSON contract."""

    def __init__(self, label: str, reason: str) -> None:
        self.label = label
        self.reason = reason
        super().__init__(f"{label} contract violation: {reason}")


class AuditDeliveryError(GovernanceError):
    """A critical audit event could not be durably delivered."""

    def __init__(
        self,
        context: "ExecutionContext",
        cause: BaseException,
        *,
        post_execution: bool,
    ) -> None:
        self.context = context
        self.cause = cause
        self.post_execution = post_execution
        stage = "after execution" if post_execution else "before execution"
        super().__init__(f"critical audit delivery failed {stage}: {cause}")


class ReconciliationAuditDeliveryPendingError(GovernanceError):
    """A committed reconciliation event remains durably queued for audit delivery."""

    def __init__(
        self,
        execution_record_id: str,
        outbox_id: str,
        cause: BaseException,
    ) -> None:
        self.execution_record_id = execution_record_id
        self.outbox_id = outbox_id
        self.cause = cause
        super().__init__(
            "reconciliation audit delivery is pending for committed execution "
            f"{execution_record_id}"
        )
