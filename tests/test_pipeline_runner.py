from __future__ import annotations

import pytest

from agent_runtime_governance._pipeline_runner import MiddlewareRegistry, PipelineRunner
from agent_runtime_governance.context import ExecutionContext, ToolCall
from agent_runtime_governance.middleware.base import (
    Middleware,
    MiddlewareKind,
    MiddlewareMetadata,
)
from agent_runtime_governance.pipeline import Pipeline
from agent_runtime_governance.runtime import Runtime


class NamedMiddleware(Middleware):
    kind = MiddlewareKind.OBSERVING

    def __init__(self, name: str, *, priority: int = 100) -> None:
        self.name = name
        self.priority = priority

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        return context


def test_registry_preserves_public_pipeline_registration_order() -> None:
    high_priority = NamedMiddleware("first", priority=900)
    low_priority = NamedMiddleware("second", priority=10)

    registry = MiddlewareRegistry([high_priority, low_priority])

    assert registry.names == ("first", "second")
    assert tuple(registry) == (high_priority, low_priority)


def test_registry_exposes_deterministic_priority_order_without_reordering_pipeline() -> None:
    first = NamedMiddleware("first", priority=20)
    tied = NamedMiddleware("tied", priority=20)
    low = NamedMiddleware("low", priority=5)

    registry = MiddlewareRegistry([first, tied, low])

    assert registry.priority_ordered == (low, first, tied)
    assert Pipeline([first, tied, low]).names == ("first", "tied", "low")


def test_registry_rejects_duplicate_names_after_metadata_validation() -> None:
    with pytest.raises(ValueError, match="duplicate middleware names: duplicate"):
        MiddlewareRegistry([NamedMiddleware("duplicate"), NamedMiddleware("duplicate")])


def test_registry_rejects_malformed_metadata() -> None:
    class InvalidMiddleware(NamedMiddleware):
        @property
        def metadata(self):  # type: ignore[override]
            return MiddlewareMetadata(
                name=self.name,
                kind=MiddlewareKind.OBSERVING,
                priority=True,
            )

    with pytest.raises(TypeError, match="priority"):
        MiddlewareRegistry([InvalidMiddleware("invalid")])


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        (
            MiddlewareMetadata("other", MiddlewareKind.OBSERVING),
            "name must match",
        ),
        (
            MiddlewareMetadata("consistent", MiddlewareKind.GATING),
            "kind must match",
        ),
        (
            MiddlewareMetadata("consistent", MiddlewareKind.OBSERVING, priority=1),
            "priority must match",
        ),
        (
            MiddlewareMetadata(
                "consistent", MiddlewareKind.OBSERVING, replayable=False
            ),
            "replayable must match",
        ),
    ],
)
def test_registry_rejects_metadata_that_disagrees_with_public_middleware_state(
    metadata: MiddlewareMetadata, message: str
) -> None:
    class InconsistentMetadataMiddleware(NamedMiddleware):
        @property
        def metadata(self) -> MiddlewareMetadata:
            return metadata

    with pytest.raises(ValueError, match=message):
        Pipeline([InconsistentMetadataMiddleware("consistent")])


@pytest.mark.asyncio
async def test_runner_uses_runtime_owned_callback_and_selection() -> None:
    selected = NamedMiddleware("selected")
    skipped = NamedMiddleware("skipped")
    runner = PipelineRunner([selected, skipped])
    context = ExecutionContext.create(ToolCall("work"))
    calls: list[str] = []

    async def invoke(middleware: Middleware, current: ExecutionContext) -> ExecutionContext:
        calls.append(middleware.name)
        return current.evolve(metadata={**current.metadata, middleware.name: True})

    result = await runner.run(
        context,
        invoke=invoke,
        include=lambda middleware, _context: middleware.name == "selected",
    )

    assert calls == ["selected"]
    assert result.metadata == {"selected": True}


@pytest.mark.asyncio
async def test_runtime_runner_tracks_replaced_pipeline_and_public_order() -> None:
    calls: list[str] = []

    class RecordingGate(NamedMiddleware):
        kind = MiddlewareKind.GATING

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            calls.append(self.name)
            return context

    runtime = Runtime([RecordingGate("discarded")])
    first = RecordingGate("first")
    second = RecordingGate("second")
    runtime.pipeline = [first, second]

    @runtime.tool()
    async def work() -> str:
        return "ok"

    assert await work.ainvoke() == "ok"
    assert calls == ["first", "second"]
    assert runtime.pipeline.names == ("first", "second")
    assert runtime._pipeline_runner.registry.middlewares == (first, second)
