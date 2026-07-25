from __future__ import annotations

import asyncio

from ..context import ExecutionContext, ExecutionMode, HistoryEntry
from ..errors import ExecutionControlError
from .base import ExecutionCall, ExecutionMiddleware


class RetryMiddleware(ExecutionMiddleware):
    name = "retry"
    priority = 200
    replayable = False

    def __init__(
        self,
        max_attempts: int = 3,
        *,
        backoff_seconds: float = 0.0,
        retry_on: tuple[type[Exception], ...] = (TimeoutError, ConnectionError),
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if backoff_seconds < 0:
            raise ValueError("backoff_seconds cannot be negative")
        self.max_attempts = max_attempts
        self.backoff_seconds = backoff_seconds
        self.retry_on = retry_on

    async def execute(
        self, context: ExecutionContext, call_next: ExecutionCall
    ) -> tuple[ExecutionContext, object]:
        if not self._can_retry(context):
            try:
                return await call_next(context)
            except self.retry_on as exc:
                current = context.append_history(
                    HistoryEntry(self.name, "skipped", self._skip_reason(context))
                )
                raise ExecutionControlError(current, exc) from exc
        current = context
        for attempt in range(1, self.max_attempts + 1):
            try:
                result_context, value = await call_next(current)
                if attempt > 1:
                    result_context = result_context.append_history(
                        HistoryEntry(self.name, "recovered", f"succeeded on attempt {attempt}")
                    )
                return result_context, value
            except self.retry_on as exc:
                current = current.append_history(
                    HistoryEntry(
                        self.name,
                        "retry" if attempt < self.max_attempts else "exhausted",
                        f"attempt {attempt}: {exc}",
                    )
                )
                if attempt == self.max_attempts:
                    raise ExecutionControlError(current, exc) from exc
                if self.backoff_seconds:
                    await asyncio.sleep(self.backoff_seconds * attempt)
        raise AssertionError("retry loop exhausted unexpectedly")

    @staticmethod
    def _can_retry(context: ExecutionContext) -> bool:
        if context.execution_mode is ExecutionMode.READ_ONLY:
            return True
        return (
            context.execution_mode is ExecutionMode.IDEMPOTENT
            and context.idempotency_key is not None
        )

    @staticmethod
    def _skip_reason(context: ExecutionContext) -> str:
        if context.execution_mode is ExecutionMode.IDEMPOTENT:
            return "idempotent tool requires an idempotency_key before retry"
        return "mutating tool is not retried automatically"
