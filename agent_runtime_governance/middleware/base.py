from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable

from ..context import ExecutionContext


class MiddlewareKind(str, Enum):
    GATING = "gating"
    OBSERVING = "observing"
    EXECUTION = "execution"


@dataclass(frozen=True, slots=True)
class MiddlewareMetadata:
    name: str
    kind: MiddlewareKind
    priority: int = 100
    replayable: bool = True
    version: str = "1"


class Middleware(ABC):
    name: str
    kind: MiddlewareKind
    priority = 100
    replayable = True

    @property
    def metadata(self) -> MiddlewareMetadata:
        return MiddlewareMetadata(
            name=self.name,
            kind=self.kind,
            priority=self.priority,
            replayable=self.replayable,
        )

    @abstractmethod
    async def process(self, context: ExecutionContext) -> ExecutionContext:
        raise NotImplementedError


class GatingMiddleware(Middleware):
    kind = MiddlewareKind.GATING


class ObservingMiddleware(Middleware):
    kind = MiddlewareKind.OBSERVING
    critical = False

    def is_critical(self, context: ExecutionContext) -> bool:
        return self.critical


ExecutionCall = Callable[[ExecutionContext], Awaitable[tuple[ExecutionContext, Any]]]


class ExecutionMiddleware(Middleware):
    kind = MiddlewareKind.EXECUTION

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        return context

    @abstractmethod
    async def execute(
        self, context: ExecutionContext, call_next: ExecutionCall
    ) -> tuple[ExecutionContext, Any]:
        raise NotImplementedError
