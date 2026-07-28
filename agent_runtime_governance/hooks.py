from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, TypeAlias

from ._blocking import invoke_extension
from .context import ExecutionContext, HistoryEntry


class HookPoint(str, Enum):
    BEFORE_PIPELINE = "before_pipeline"
    AFTER_PIPELINE = "after_pipeline"
    BEFORE_LLM = "before_llm"
    AFTER_LLM = "after_llm"
    BEFORE_DECISION = "before_decision"
    AFTER_DECISION = "after_decision"
    BEFORE_EXECUTE = "before_execute"
    AFTER_EXECUTE = "after_execute"
    BEFORE_AUDIT = "before_audit"
    AFTER_AUDIT = "after_audit"
    ON_ERROR = "on_error"


HookResult: TypeAlias = ExecutionContext | None
HookCallback: TypeAlias = Callable[
    [ExecutionContext], HookResult | Awaitable[HookResult]
]


@dataclass(frozen=True, slots=True)
class HookRegistration:
    callback: HookCallback
    critical: bool = False


class CriticalHookError(RuntimeError):
    pass


class HookRegistry:
    def __init__(self) -> None:
        self._hooks: dict[HookPoint, list[HookRegistration]] = {
            point: [] for point in HookPoint
        }

    def register(
        self, point: HookPoint, callback: HookCallback, *, critical: bool = False
    ) -> HookCallback:
        self._hooks[point].append(HookRegistration(callback, critical))
        return callback

    def decorator(
        self, point: HookPoint, *, critical: bool = False
    ) -> Callable[[HookCallback], HookCallback]:
        def add(callback: HookCallback) -> HookCallback:
            return self.register(point, callback, critical=critical)

        return add

    async def emit(
        self, point: HookPoint, context: ExecutionContext, *, allow_critical: bool
    ) -> ExecutionContext:
        current = context
        for registration in self._hooks[point]:
            try:
                value = await invoke_extension(registration.callback, current)
                if value is not None:
                    if not isinstance(value, ExecutionContext):
                        raise TypeError("hook must return ExecutionContext or None")
                    if _protected_state(value) != _protected_state(current):
                        raise TypeError("hooks cannot change protected execution state")
                    if _governance_metadata(value) != _governance_metadata(current):
                        raise TypeError("hooks cannot change governance metadata")
                    current = value
            except Exception as exc:
                if registration.critical and allow_critical:
                    raise CriticalHookError(f"critical {point.value} hook failed: {exc}") from exc
                current = current.append_history(
                    HistoryEntry(f"hook:{point.value}", "error", str(exc))
                )
        return current


def _protected_state(context: ExecutionContext) -> tuple[object, ...]:
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
        context.bound_action,
        context.risk_tier,
        context.risk_score,
        context.requires_approval,
        context.approval_granted,
        context.approval_request_id,
        context.approval_decision_id,
        context.status,
        context.decision,
        context.history,
        context.result,
        context.error,
    )


def _governance_metadata(context: ExecutionContext) -> dict[str, object]:
    return {
        key: value
        for key, value in context.metadata.items()
        if key.lower() == "duration_ms"
        or key.lower().startswith(("approval_", "identity_", "policy_"))
    }
