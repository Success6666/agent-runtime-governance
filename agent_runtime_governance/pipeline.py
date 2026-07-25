from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator

from .middleware.base import Middleware


@dataclass(frozen=True, slots=True)
class Pipeline:
    """Immutable, explicitly ordered middleware composition."""

    middlewares: tuple[Middleware, ...] = ()

    def __init__(self, middlewares: Iterable[Middleware] = ()) -> None:
        items = tuple(middlewares)
        names = [item.name for item in items]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate middleware names: {', '.join(duplicates)}")
        object.__setattr__(self, "middlewares", items)

    def __iter__(self) -> Iterator[Middleware]:
        return iter(self.middlewares)

    def __len__(self) -> int:
        return len(self.middlewares)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.middlewares)

    def append(self, middleware: Middleware) -> "Pipeline":
        return Pipeline((*self.middlewares, middleware))

    def remove(self, name: str) -> "Pipeline":
        if name not in self.names:
            raise KeyError(name)
        return Pipeline(item for item in self.middlewares if item.name != name)

    def insert_before(self, target: str, middleware: Middleware) -> "Pipeline":
        return self._insert(target, middleware, after=False)

    def insert_after(self, target: str, middleware: Middleware) -> "Pipeline":
        return self._insert(target, middleware, after=True)

    def replace(self, target: str, middleware: Middleware) -> "Pipeline":
        if target not in self.names:
            raise KeyError(target)
        return Pipeline(middleware if item.name == target else item for item in self.middlewares)

    def _insert(self, target: str, middleware: Middleware, *, after: bool) -> "Pipeline":
        if target not in self.names:
            raise KeyError(target)
        items = list(self.middlewares)
        index = self.names.index(target) + int(after)
        items.insert(index, middleware)
        return Pipeline(items)

