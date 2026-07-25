from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from ..context import ExecutionContext


class MiddlewareKind(str, Enum):
    GATING = "gating"
    OBSERVING = "observing"


class Middleware(ABC):
    name: str
    kind: MiddlewareKind

    @abstractmethod
    async def process(self, context: ExecutionContext) -> ExecutionContext:
        raise NotImplementedError


class GatingMiddleware(Middleware):
    kind = MiddlewareKind.GATING


class ObservingMiddleware(Middleware):
    kind = MiddlewareKind.OBSERVING

