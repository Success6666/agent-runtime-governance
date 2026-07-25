from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, TypeAlias

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
                if inspect.iscoroutinefunction(registration.callback):
                    value = await registration.callback(current)
                else:
                    value = await asyncio.to_thread(registration.callback, current)
                if inspect.isawaitable(value):
                    value = await value
                if value is not None:
                    if not isinstance(value, ExecutionContext):
                        raise TypeError("hook must return ExecutionContext or None")
                    if value.status is not current.status or value.decision != current.decision:
                        raise TypeError("hooks cannot change execution status or decisions")
                    current = value
            except Exception as exc:
                if registration.critical and allow_critical:
                    raise CriticalHookError(f"critical {point.value} hook failed: {exc}") from exc
                current = current.append_history(
                    HistoryEntry(f"hook:{point.value}", "error", str(exc))
                )
        return current
