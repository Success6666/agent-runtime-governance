"""Internal middleware registration and execution seams.

The public :class:`~agent_runtime_governance.pipeline.Pipeline` remains an
immutable, explicitly ordered value.  This module centralizes the metadata
validation and selection rules that Runtime services need, without introducing
a mutable runtime pipeline or a plugin-loading mechanism.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import TypeVar

from ...middleware.base import Middleware, MiddlewareKind, MiddlewareMetadata

ContextT = TypeVar("ContextT")
MiddlewareInvoker = Callable[[Middleware, ContextT], Awaitable[ContextT]]
MiddlewareSelector = Callable[[Middleware, ContextT], bool]


@dataclass(frozen=True, slots=True)
class MiddlewareRegistry:
    """Validate and index one immutable middleware registration set.

    Registration order remains the public ``Pipeline`` order.  The separate
    :attr:`priority_ordered` view gives internal services a deterministic
    priority order without silently changing existing Pipeline semantics.
    """

    middlewares: tuple[Middleware, ...]

    def __init__(self, middlewares: Iterable[Middleware] = ()) -> None:
        items = tuple(middlewares)
        names: set[str] = set()
        duplicates: set[str] = set()
        for middleware in items:
            metadata = _validate_metadata(middleware)
            if metadata.name in names:
                duplicates.add(metadata.name)
            names.add(metadata.name)
        if duplicates:
            raise ValueError(f"duplicate middleware names: {', '.join(sorted(duplicates))}")
        object.__setattr__(self, "middlewares", items)

    def __iter__(self):
        return iter(self.middlewares)

    def __len__(self) -> int:
        return len(self.middlewares)

    @property
    def names(self) -> tuple[str, ...]:
        """Return stable middleware names in Pipeline registration order."""

        return tuple(middleware.metadata.name for middleware in self.middlewares)

    @property
    def priority_ordered(self) -> tuple[Middleware, ...]:
        """Return middleware sorted by ascending priority and stable ties."""

        indexed = enumerate(self.middlewares)
        return tuple(
            middleware
            for _, middleware in sorted(
                indexed,
                key=lambda item: (item[1].metadata.priority, item[0]),
            )
        )

    def of_kind(self, kind: MiddlewareKind) -> tuple[Middleware, ...]:
        """Return registered middleware of one validated kind."""

        if not isinstance(kind, MiddlewareKind):
            raise TypeError("middleware kind must be a MiddlewareKind")
        return tuple(
            middleware
            for middleware in self.middlewares
            if middleware.metadata.kind is kind
        )


@dataclass(frozen=True, slots=True)
class PipelineRunner:
    """Run a selected immutable middleware sequence through Runtime callbacks.

    Runtime keeps ownership of hooks, deadlines, transition validation and
    fail-closed policy.  This runner owns only deterministic middleware
    selection and sequential composition, making the boundary independently
    testable and safe to reuse by replay paths.
    """

    registry: MiddlewareRegistry

    def __init__(self, middlewares: MiddlewareRegistry | Iterable[Middleware] = ()) -> None:
        registry = (
            middlewares
            if isinstance(middlewares, MiddlewareRegistry)
            else MiddlewareRegistry(middlewares)
        )
        object.__setattr__(self, "registry", registry)

    async def run(
        self,
        context: ContextT,
        *,
        invoke: MiddlewareInvoker[ContextT],
        include: MiddlewareSelector[ContextT] | None = None,
    ) -> ContextT:
        """Invoke selected middleware in immutable Pipeline registration order."""

        for middleware in self.registry:
            if include is not None and not include(middleware, context):
                continue
            context = await invoke(middleware, context)
        return context


def _validate_metadata(middleware: Middleware) -> MiddlewareMetadata:
    """Reject malformed metadata before it reaches Runtime orchestration."""

    if not isinstance(middleware, Middleware):
        raise TypeError("pipeline entries must be Middleware instances")
    name = getattr(middleware, "name", None)
    kind = getattr(middleware, "kind", None)
    priority = getattr(middleware, "priority", None)
    replayable = getattr(middleware, "replayable", None)
    _validate_fields("middleware", name, kind, priority, replayable)
    metadata = middleware.metadata
    if not isinstance(metadata, MiddlewareMetadata):
        raise TypeError("middleware metadata must be MiddlewareMetadata")
    _validate_fields(
        "middleware metadata",
        metadata.name,
        metadata.kind,
        metadata.priority,
        metadata.replayable,
    )
    if not isinstance(metadata.version, str) or not metadata.version.strip():
        raise ValueError("middleware metadata version must be a non-empty string")
    if metadata.name != name:
        raise ValueError("middleware metadata name must match middleware name")
    if metadata.kind is not kind:
        raise ValueError("middleware metadata kind must match middleware kind")
    if metadata.priority != priority:
        raise ValueError(
            "middleware metadata priority must match middleware priority"
        )
    if metadata.replayable is not replayable:
        raise ValueError(
            "middleware metadata replayable must match middleware replayable"
        )
    return metadata


def _validate_fields(
    label: str,
    name: object,
    kind: object,
    priority: object,
    replayable: object,
) -> None:
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{label} name must be a non-empty string")
    if not isinstance(kind, MiddlewareKind):
        raise TypeError(f"{label} kind must be a MiddlewareKind")
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise TypeError(f"{label} priority must be an integer")
    if not isinstance(replayable, bool):
        raise TypeError(f"{label} replayable must be a boolean")
