from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_runtime_governance import (
    AuditDeliveryError,
    AuditMiddleware,
    CapacityExceededError,
    GovernanceDenied,
    HookPoint,
    InvocationOptions,
    Middleware,
    MiddlewareKind,
    ObservingMiddleware,
    ProductionProfile,
    RegistryError,
    RiskTier,
    Rule,
    RuleMiddleware,
    Runtime,
    RuntimeLimits,
    ToolExecutionError,
)
from agent_runtime_governance._blocking import run_blocking


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


def test_close_seals_admission_before_releasing_its_lifecycle_lock() -> None:
    """A request racing shutdown must observe the closed admission boundary."""

    runtime = Runtime()
    calls: list[str] = []

    @runtime.tool()
    def work() -> str:
        calls.append("ran")
        return "ran"

    class CloseTransitionLock:
        def __init__(self) -> None:
            self._lock = threading.Lock()
            self.closed_marked = threading.Event()
            self.resume_close = threading.Event()
            self._paused = False

        def __enter__(self) -> "CloseTransitionLock":
            self._lock.acquire()
            return self

        def __exit__(self, *args: object) -> None:
            self._lock.release()
            if (
                not self._paused
                and threading.current_thread().name == "runtime-close"
                and runtime._closed
            ):
                self._paused = True
                self.closed_marked.set()
                assert self.resume_close.wait(timeout=1)

    transition_lock = CloseTransitionLock()
    runtime._lifecycle_lock = transition_lock  # type: ignore[assignment]
    closer = threading.Thread(target=runtime.close, name="runtime-close")
    closer.start()
    try:
        assert transition_lock.closed_marked.wait(timeout=1)
        with pytest.raises(RuntimeError, match="runtime is closed"):
            asyncio.run(runtime.ainvoke("work"))
        assert calls == []
    finally:
        transition_lock.resume_close.set()
        closer.join(timeout=1)
    assert not closer.is_alive()


def test_close_remains_in_progress_until_executor_shutdown_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second closer cannot observe a successful shutdown prematurely."""

    runtime = Runtime()
    shutdown_started = threading.Event()
    release_shutdown = threading.Event()
    original_shutdown = runtime._shutdown_executors

    def blocked_shutdown(*, wait: bool) -> None:
        shutdown_started.set()
        assert release_shutdown.wait(timeout=1)
        original_shutdown(wait=wait)

    monkeypatch.setattr(runtime, "_shutdown_executors", blocked_shutdown)
    closer = threading.Thread(target=runtime.close)
    closer.start()
    try:
        assert shutdown_started.wait(timeout=1)
        with pytest.raises(RuntimeError, match="already in progress"):
            runtime.close()
    finally:
        release_shutdown.set()
        closer.join(timeout=1)
    assert not closer.is_alive()


def test_production_runtime_rejects_nonwaiting_close() -> None:
    runtime = Runtime(production_profile=ProductionProfile())

    with pytest.raises(ValueError, match=r"close\(wait=True\)"):
        runtime.close(wait=False)

    runtime.close()


@pytest.mark.asyncio
async def test_close_rejects_active_tool_without_closing_runtime() -> None:
    """Synchronous close never abandons a tool already admitted for execution."""

    runtime = Runtime()
    entered = asyncio.Event()
    release = asyncio.Event()

    @runtime.tool()
    async def slow() -> str:
        entered.set()
        await release.wait()
        return "finished"

    @runtime.tool()
    async def inspect() -> str:
        return "available"

    running = asyncio.create_task(runtime.arun("slow"))
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        with pytest.raises(RuntimeError, match="runtime work is pending"):
            runtime.close()

        assert await runtime.ainvoke("inspect") == "available"
        release.set()
        assert (await running).value == "finished"
    finally:
        release.set()
        await asyncio.gather(running, return_exceptions=True)
        await runtime.aclose()


class BlockingMiddleware(Middleware):
    name = "blocking"
    kind = MiddlewareKind.GATING

    def __init__(self, entered: asyncio.Event, release: asyncio.Event) -> None:
        self.entered = entered
        self.release = release

    async def process(self, context):
        self.entered.set()
        await self.release.wait()
        return context


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["arun", "apreview", "areplay"])
async def test_aclose_waits_for_active_public_operation(operation: str) -> None:
    """Async close admits no new work and waits for pre-existing work to finish."""

    entered = asyncio.Event()
    release = asyncio.Event()
    runtime = Runtime([BlockingMiddleware(entered, release)])
    closing: asyncio.Task[None] | None = None

    @runtime.tool()
    async def work() -> str:
        return "finished"

    if operation == "arun":
        running = asyncio.create_task(runtime.arun("work"))
    elif operation == "apreview":
        running = asyncio.create_task(runtime.apreview("work"))
    else:
        release.set()
        context = await runtime.apreview("work")
        release.clear()
        entered.clear()
        running = asyncio.create_task(runtime.areplay(context))

    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0)
        assert not closing.done()
        with pytest.raises(RuntimeError, match="runtime is closed"):
            await runtime.apreview("work")

        release.set()
        await running
        await asyncio.wait_for(closing, timeout=1)
        with pytest.raises(RuntimeError, match="cannot schedule new futures"):
            runtime.sync_executor.submit(lambda: None)
    finally:
        release.set()
        await asyncio.gather(running, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_ignores_completed_finalizer_not_yet_removed() -> None:
    """A stale done finalizer cannot make async shutdown spin forever."""

    runtime = Runtime()
    completed = asyncio.create_task(asyncio.sleep(0))
    await completed
    with runtime._lifecycle_lock:
        runtime._reconciliation_finalizers.add(completed)

    await asyncio.wait_for(runtime.aclose(), timeout=1)


@pytest.mark.asyncio
async def test_aclose_rejects_self_shutdown_from_active_operation() -> None:
    """A tool cannot deadlock shutdown by waiting for its own completion."""

    runtime = Runtime()

    @runtime.tool()
    async def unsafe_close() -> str:
        with pytest.raises(RuntimeError, match="cannot be called from an active"):
            await runtime.aclose()
        return "still-running"

    try:
        assert await runtime.ainvoke("unsafe_close") == "still-running"
        assert not runtime._closed
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_rejects_cross_loop_shutdown_while_work_is_active() -> None:
    """Async shutdown must not await a task owned by a different event loop."""

    runtime = Runtime()
    entered = asyncio.Event()
    release = asyncio.Event()
    errors: list[BaseException] = []

    @runtime.tool()
    async def slow() -> str:
        entered.set()
        await release.wait()
        return "finished"

    async def close_from_other_loop() -> None:
        try:
            await runtime.aclose()
        except BaseException as exc:
            errors.append(exc)

    running = asyncio.create_task(runtime.arun("slow"))
    closer: threading.Thread | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        closer = threading.Thread(target=lambda: asyncio.run(close_from_other_loop()))
        closer.start()
        closer.join(timeout=1)
        assert not closer.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], RuntimeError)
        assert "another event loop" in str(errors[0])
        assert not runtime._closed
        assert not runtime._closing

        release.set()
        assert (await running).value == "finished"
    finally:
        release.set()
        if closer is not None:
            closer.join(timeout=1)
        await asyncio.gather(running, return_exceptions=True)
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_waits_for_detached_uncooperative_async_tool() -> None:
    """A timeout does not make an ignored async tool safe to abandon."""

    runtime = Runtime(
        limits=RuntimeLimits(
            execution_timeout_seconds=0.02,
            cancellation_grace_seconds=0.002,
        )
    )
    entered = asyncio.Event()
    release = asyncio.Event()

    @runtime.tool()
    async def mutate() -> str:
        entered.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue
        return "finished"

    closing: asyncio.Task[None] | None = None
    try:
        with pytest.raises(ToolExecutionError):
            await runtime.arun("mutate")
        await asyncio.wait_for(entered.wait(), timeout=1)
        assert any(not task.done() for task in runtime._detached_stage_tasks)

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_waits_for_timed_out_uncooperative_sync_hook() -> None:
    """A cancelled thread-backed critical hook remains in shutdown ownership."""

    runtime = Runtime(
        limits=RuntimeLimits(
            hook_timeout_seconds=0.02,
            cancellation_grace_seconds=0.002,
        )
    )
    entered = threading.Event()
    release = threading.Event()

    @runtime.hook(point=HookPoint.BEFORE_PIPELINE, critical=True)
    def blocking_hook(context):
        entered.set()
        assert release.wait(timeout=1)
        return context

    @runtime.tool()
    def read() -> str:
        return "unexpected"

    closing: asyncio.Task[None] | None = None
    try:
        with pytest.raises(GovernanceDenied, match="hook:before_pipeline"):
            await runtime.arun("read")
        assert entered.wait(timeout=1)

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_waits_for_timed_out_uncooperative_sync_audit_sink() -> None:
    """Fail-closed synchronous audit delivery cannot outlive graceful close."""

    entered = threading.Event()
    release = threading.Event()

    class BlockingSink:
        def write(self, event) -> None:
            entered.set()
            assert release.wait(timeout=1)

    runtime = Runtime(
        [AuditMiddleware(BlockingSink(), critical=True)],
        limits=RuntimeLimits(
            observer_timeout_seconds=0.02,
            cancellation_grace_seconds=0.002,
        ),
    )

    @runtime.tool()
    def mutate() -> str:
        return "executed"

    closing: asyncio.Task[None] | None = None
    try:
        with pytest.raises(AuditDeliveryError):
            await runtime.arun("mutate")
        assert entered.wait(timeout=1)

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_blocking_extension_capacity_stays_bounded_after_timeout() -> None:
    """Timed-out worker threads retain their permit until the real call ends."""

    runtime = Runtime(
        limits=RuntimeLimits(
            execution_timeout_seconds=0.02,
            max_blocking_extension_in_flight=1,
        )
    )
    entered = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def block() -> None:
        calls.append("block")
        entered.set()
        assert release.wait(timeout=1)

    first = asyncio.create_task(runtime._run_blocking_extension(block))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        with pytest.raises(CapacityExceededError):
            await runtime._run_blocking_extension(lambda: calls.append("unexpected"))
        assert calls == ["block"]

        release.set()
        await asyncio.wait_for(first, timeout=1)
    finally:
        release.set()
        await asyncio.gather(first, return_exceptions=True)
        await runtime.aclose()


@pytest.mark.asyncio
async def test_sync_extension_cannot_escape_runtime_lifecycle_with_nested_thread() -> None:
    """A managed sync callback fails closed rather than using a global worker."""

    runtime = Runtime()
    nested_effects: list[str] = []

    @runtime.hook(point=HookPoint.BEFORE_PIPELINE, critical=True)
    def nested_blocking_hook(context):
        async def invoke_nested() -> None:
            await run_blocking(lambda: nested_effects.append("unexpected"))

        asyncio.run(invoke_nested())
        return context

    @runtime.tool()
    def read() -> str:
        return "unexpected"

    try:
        with pytest.raises(GovernanceDenied, match="nested blocking work"):
            await runtime.arun("read")
        assert nested_effects == []
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_sync_extension_cannot_close_its_own_runtime() -> None:
    """A copied active context prevents self-join from a sync callback."""

    runtime = Runtime()

    @runtime.hook(point=HookPoint.BEFORE_PIPELINE, critical=True)
    def close_hook(context):
        with pytest.raises(RuntimeError, match="cannot be called from an active"):
            runtime.close()
        return context

    @runtime.tool()
    def read() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("read") == "ok"
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_waits_for_timed_out_sync_tool_on_external_executor() -> None:
    """Injected tool executors cannot hide a still-running sync tool at close."""

    executor = ThreadPoolExecutor(max_workers=1)
    runtime = Runtime(
        sync_executor=executor,
        limits=RuntimeLimits(
            execution_timeout_seconds=0.02,
            cancellation_grace_seconds=0.002,
        ),
    )
    entered = threading.Event()
    release = threading.Event()

    @runtime.tool()
    def mutate() -> str:
        entered.set()
        assert release.wait(timeout=1)
        return "finished"

    closing: asyncio.Task[None] | None = None
    try:
        with pytest.raises(ToolExecutionError):
            await runtime.arun("mutate")
        assert entered.wait(timeout=1)

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()
        executor.shutdown(wait=True, cancel_futures=True)


@pytest.mark.asyncio
async def test_cancelled_aclose_keeps_internal_shutdown_running() -> None:
    """Caller cancellation cannot leave a closed runtime with live executors."""

    runtime = Runtime()
    release_finalizer = asyncio.Event()

    async def finalizer() -> None:
        await release_finalizer.wait()

    pending_finalizer = asyncio.create_task(finalizer())
    with runtime._lifecycle_lock:
        runtime._reconciliation_finalizers.add(pending_finalizer)
    pending_finalizer.add_done_callback(runtime._forget_reconciliation_finalizer)

    caller = asyncio.create_task(runtime.aclose())
    await asyncio.sleep(0)
    assert runtime._closing
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert runtime._closing

    release_finalizer.set()
    close_task = runtime._async_close_task
    assert close_task is not None
    await asyncio.wait_for(asyncio.shield(close_task), timeout=1)

    assert runtime._async_close_task is None
    assert not runtime._closing
    with pytest.raises(RuntimeError, match="cannot schedule new futures"):
        runtime.sync_executor.submit(lambda: None)


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
    assert caught.value.context.status.value == "unknown"
    assert "ValueError" in (caught.value.context.error or "")


def test_closed_sync_invoke_does_not_start_an_owned_event_loop() -> None:
    runtime = Runtime()
    runtime.close()

    with pytest.raises(RuntimeError, match="runtime is closed"):
        runtime.invoke("missing")

    assert runtime._get_sync_loop() is None


@pytest.mark.asyncio
async def test_sync_invoke_rejected_inside_event_loop() -> None:
    runtime = Runtime()

    @runtime.tool()
    def work() -> bool:
        return True

    with pytest.raises(RuntimeError, match="use ainvoke"):
        work()
