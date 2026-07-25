from __future__ import annotations

import pytest

from agent_runtime_governance import (
    DecisionOutcome,
    DecisionRecord,
    GovernanceDenied,
    HookPoint,
    LLMMiddleware,
    Middleware,
    MiddlewareKind,
    Pipeline,
    Runtime,
)


class NamedMiddleware(Middleware):
    kind = MiddlewareKind.OBSERVING

    def __init__(self, name: str) -> None:
        self.name = name

    async def process(self, context):
        return context


def test_pipeline_preserves_explicit_order() -> None:
    pipeline = Pipeline([NamedMiddleware("a"), NamedMiddleware("b")])
    assert pipeline.names == ("a", "b")


def test_pipeline_append_returns_new_value() -> None:
    original = Pipeline([NamedMiddleware("a")])
    updated = original.append(NamedMiddleware("b"))
    assert original.names == ("a",)
    assert updated.names == ("a", "b")


def test_pipeline_insert_and_remove() -> None:
    pipeline = Pipeline([NamedMiddleware("a"), NamedMiddleware("c")])
    updated = pipeline.insert_before("c", NamedMiddleware("b")).remove("a")
    assert updated.names == ("b", "c")


def test_pipeline_replace() -> None:
    pipeline = Pipeline([NamedMiddleware("a")]).replace("a", NamedMiddleware("b"))
    assert pipeline.names == ("b",)


def test_pipeline_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        Pipeline([NamedMiddleware("a"), NamedMiddleware("a")])


def test_middleware_metadata_is_available() -> None:
    metadata = NamedMiddleware("observer").metadata
    assert metadata.name == "observer"
    assert metadata.kind is MiddlewareKind.OBSERVING
    assert metadata.priority == 100


def test_before_and_after_tool_hooks_run() -> None:
    events: list[str] = []
    runtime = Runtime()

    @runtime.before_tool
    def before(context):
        events.append("before")
        return context.evolve(metadata={"hooked": True})

    @runtime.after_tool
    def after(context):
        events.append("after")

    @runtime.tool()
    def work() -> bool:
        return True

    assert work() is True
    assert events == ["before", "after"]


@pytest.mark.asyncio
async def test_async_hook_runs() -> None:
    runtime = Runtime()
    called = False

    @runtime.hook(HookPoint.BEFORE_PIPELINE)
    async def before(context):
        nonlocal called
        called = True

    @runtime.tool()
    def work() -> bool:
        return True

    assert await work.ainvoke() is True
    assert called


def test_noncritical_hook_failure_does_not_block() -> None:
    runtime = Runtime()

    @runtime.before_tool
    def broken(context):
        raise RuntimeError("telemetry down")

    @runtime.tool()
    def work() -> bool:
        return True

    assert work() is True


def test_critical_before_tool_failure_denies() -> None:
    runtime = Runtime()

    @runtime.before_tool(critical=True)
    def broken(context):
        raise RuntimeError("required check down")

    @runtime.tool()
    def work() -> bool:
        return True

    with pytest.raises(GovernanceDenied):
        work()


def test_hook_cannot_rewrite_decision() -> None:
    runtime = Runtime()

    @runtime.before_tool
    def invalid(context):
        return context.with_decision(
            DecisionRecord(DecisionOutcome.DENY, "hook tried to decide", "hook")
        )

    @runtime.tool()
    def work() -> bool:
        return True

    assert work() is True


def test_llm_hooks_wrap_semantic_middleware() -> None:
    events: list[str] = []
    runtime = Runtime([LLMMiddleware(lambda context: True)])

    @runtime.before_llm
    def before(context):
        events.append("before")

    @runtime.after_llm
    def after(context):
        events.append("after")

    @runtime.tool()
    def work() -> bool:
        return True

    work()
    assert events == ["before", "after"]
