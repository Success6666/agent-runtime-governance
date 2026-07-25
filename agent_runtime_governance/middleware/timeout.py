from __future__ import annotations

import asyncio

from ..context import ExecutionContext
from .base import ExecutionCall, ExecutionMiddleware


class TimeoutMiddleware(ExecutionMiddleware):
    name = "timeout"
    priority = 300
    replayable = False

    def __init__(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError("timeout must be greater than zero")
        self.seconds = seconds

    async def execute(
        self, context: ExecutionContext, call_next: ExecutionCall
    ) -> tuple[ExecutionContext, object]:
        try:
            return await asyncio.wait_for(call_next(context), timeout=self.seconds)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(f"tool exceeded {self.seconds:.3f}s timeout") from exc
