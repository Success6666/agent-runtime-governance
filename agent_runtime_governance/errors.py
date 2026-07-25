from __future__ import annotations

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


class MiddlewareExecutionError(GovernanceError):
    """Raised when a gating middleware fails closed."""


class ToolExecutionError(GovernanceError):
    """Raised when a governed tool fails."""

    def __init__(self, context: "ExecutionContext", cause: BaseException) -> None:
        self.context = context
        self.cause = cause
        super().__init__(f"tool {context.tool_call.name!r} failed: {cause}")


class RegistryError(GovernanceError):
    """Raised for invalid or duplicate tool registration."""


class ContextMutationError(GovernanceError):
    """Raised when middleware attempts to alter immutable identity fields."""


class AuditIntegrityError(GovernanceError):
    """Raised when a signed audit event fails verification."""

