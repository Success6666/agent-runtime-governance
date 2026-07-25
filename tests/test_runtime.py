from __future__ import annotations

import pytest

from agent_runtime_governance import (
    GovernanceDenied,
    InvocationOptions,
    Middleware,
    MiddlewareKind,
    ObservingMiddleware,
    RegistryError,
    RiskTier,
    Rule,
    RuleMiddleware,
    Runtime,
    ToolExecutionError,
)


def test_decorated_sync_tool_runs_through_runtime() -> None:
    runtime = Runtime()

    @runtime.tool()
    def add(left: int, right: int) -> int:
        return left + right

    assert add(2, 3) == 5


@pytest.mark.asyncio
async def test_async_tool_is_awaited() -> None:
    runtime = Runtime()

    @runtime.tool()
    async def add(left: int, right: int) -> int:
        return left + right

    assert await add.ainvoke(4, 5) == 9


def test_tool_keyword_named_user_is_not_reserved() -> None:
    runtime = Runtime()

    @runtime.tool()
    def greet(user: str) -> str:
        return f"hello {user}"

    assert greet(user="Ada") == "hello Ada"


def test_unknown_tool_is_rejected() -> None:
    runtime = Runtime()
    with pytest.raises(RegistryError):
        runtime.invoke("missing")


def test_duplicate_tool_name_is_rejected() -> None:
    runtime = Runtime()

    @runtime.tool(name="same")
    def first() -> None:
        return None

    with pytest.raises(RegistryError):

        @runtime.tool(name="same")
        def second() -> None:
            return None


def test_rule_denial_prevents_tool_execution() -> None:
    called = False
    runtime = Runtime([RuleMiddleware([Rule("destroy", r"\bdestroy\b", "destructive intent")])])

    @runtime.tool(risk=RiskTier.HIGH)
    def dangerous() -> None:
        nonlocal called
        called = True

    with pytest.raises(GovernanceDenied) as caught:
        runtime.invoke(
            "dangerous",
            _governance=InvocationOptions(input_text="destroy the database"),
        )
    assert not called
    assert caught.value.context.decision is not None


class BrokenGate(Middleware):
    name = "broken_gate"
    kind = MiddlewareKind.GATING

    async def process(self, context):
        raise RuntimeError("unavailable")


def test_gating_failure_fails_closed() -> None:
    runtime = Runtime([BrokenGate()])

    @runtime.tool()
    def work() -> bool:
        return True

    with pytest.raises(GovernanceDenied) as caught:
        work()
    assert "failed closed" in str(caught.value)


class BrokenObserver(ObservingMiddleware):
    name = "broken_observer"

    async def process(self, context):
        raise RuntimeError("metrics unavailable")


@pytest.mark.asyncio
async def test_observer_failure_does_not_block_execution() -> None:
    runtime = Runtime([BrokenObserver()])

    @runtime.tool()
    def work() -> bool:
        return True

    result = await runtime.arun("work")
    assert result.value is True
    assert any(entry.middleware == "broken_observer" for entry in result.context.history)


def test_tool_failure_carries_final_context() -> None:
    runtime = Runtime()

    @runtime.tool()
    def fail() -> None:
        raise ValueError("bad input")

    with pytest.raises(ToolExecutionError) as caught:
        fail()
    assert caught.value.context.status.value == "failed"
    assert "ValueError" in (caught.value.context.error or "")


@pytest.mark.asyncio
async def test_sync_invoke_rejected_inside_event_loop() -> None:
    runtime = Runtime()

    @runtime.tool()
    def work() -> bool:
        return True

    with pytest.raises(RuntimeError, match="use ainvoke"):
        work()

