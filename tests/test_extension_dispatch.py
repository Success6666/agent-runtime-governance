from __future__ import annotations

import asyncio
import gc
import threading
import time
import warnings
from contextlib import contextmanager
from contextvars import ContextVar
from functools import partial, wraps
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, generate_latest

import agent_runtime_governance.telemetry as telemetry_module
from agent_runtime_governance import (
    AuditMiddleware,
    LLMMiddleware,
    OPADecision,
    OPAMiddleware,
    OpenTelemetryMiddleware,
    PrometheusMiddleware,
    Runtime,
    RuntimeLimits,
    SlackNotificationMiddleware,
    SnapshotMiddleware,
    VerifiedPrincipal,
)
from agent_runtime_governance._blocking import (
    invoke_extension,
    schedule_extension_cleanup,
)
from agent_runtime_governance._extensions import (
    _ExtensionDispatcher,
    invoke_standalone_extension,
    is_native_async_callable,
)
from agent_runtime_governance.context import ExecutionContext, ExecutionStatus, ToolCall
from agent_runtime_governance.hooks import HookPoint
from agent_runtime_governance.middleware.base import GatingMiddleware


async def _wait_until(predicate: Any, *, timeout_seconds: float = 1.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while not predicate():
        if loop.time() >= deadline:
            raise AssertionError("condition did not become true before timeout")
        await asyncio.sleep(0.001)


async def _assert_ticker_stays_responsive(awaitable: Any) -> Any:
    """Prove a synchronous extension does not monopolize the caller loop."""

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    intervals: list[float] = []

    async def ticker() -> None:
        previous = loop.time()
        while not stop.is_set():
            await asyncio.sleep(0.01)
            current = loop.time()
            intervals.append(current - previous)
            previous = current

    task = asyncio.create_task(ticker())
    await asyncio.sleep(0)
    try:
        return await awaitable
    finally:
        stop.set()
        await task
        assert len(intervals) >= 8
        assert max(intervals) < 0.1


@pytest.mark.asyncio
async def test_standalone_sync_fallback_closes_late_coroutine_after_cancellation() -> None:
    entered = threading.Event()
    release = threading.Event()
    returned = threading.Event()

    async def delayed_result() -> None:
        return None

    def callback() -> Any:
        entered.set()
        assert release.wait(timeout=1)
        coroutine = delayed_result()
        returned.set()
        return coroutine

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", RuntimeWarning)
        task = asyncio.create_task(invoke_standalone_extension(callback))
        try:
            assert await asyncio.wait_for(
                asyncio.to_thread(entered.wait, 1), timeout=1.1
            )
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            release.set()
            assert await asyncio.wait_for(
                asyncio.to_thread(returned.wait, 1), timeout=1.1
            )
            await asyncio.sleep(0)
            gc.collect()
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
    assert not any("was never awaited" in str(item.message) for item in captured)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_workers": 0}, "max_workers"),
        ({"max_in_flight": 0}, "max_in_flight"),
        ({"capacity_timeout_seconds": 0}, "capacity_timeout_seconds"),
    ],
)
def test_extension_dispatcher_rejects_invalid_capacity(
    kwargs: dict[str, float | int], message: str
) -> None:
    options: dict[str, object] = {
        "max_workers": 1,
        "max_in_flight": 1,
        "capacity_timeout_seconds": 1.0,
        "admission_lock": threading.Lock(),
        "is_accepting": lambda: True,
    }
    options.update(kwargs)

    with pytest.raises(ValueError, match=message):
        _ExtensionDispatcher(**options)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_extension_dispatcher_isolates_metrics_observer_errors() -> None:
    class BrokenObserver:
        def record_queue_wait(self, **_kwargs: object) -> None:
            raise RuntimeError("metrics unavailable")

        def record_execution(self, **_kwargs: object) -> None:
            raise RuntimeError("metrics unavailable")

        def record_saturation(self, **_kwargs: object) -> None:
            raise RuntimeError("metrics unavailable")

        def record_detached_work(self, **_kwargs: object) -> None:
            raise RuntimeError("metrics unavailable")

    dispatcher = _ExtensionDispatcher(
        max_workers=1,
        max_in_flight=1,
        capacity_timeout_seconds=1.0,
        admission_lock=threading.Lock(),
        is_accepting=lambda: True,
    )
    dispatcher.add_observer(BrokenObserver())  # type: ignore[arg-type]
    try:
        assert await dispatcher.invoke(lambda: "ok") == "ok"
    finally:
        dispatcher.shutdown(wait=True)


def test_extension_dispatcher_replaces_observers_by_identity() -> None:
    class Observer:
        def __init__(self) -> None:
            self.queue_wait_calls = 0

        def record_queue_wait(self, **_kwargs: object) -> None:
            self.queue_wait_calls += 1

        def record_execution(self, **_kwargs: object) -> None:
            pass

        def record_saturation(self, **_kwargs: object) -> None:
            pass

        def record_detached_work(self, **_kwargs: object) -> None:
            pass

    dispatcher = _ExtensionDispatcher(
        max_workers=1,
        max_in_flight=1,
        capacity_timeout_seconds=1.0,
        admission_lock=threading.Lock(),
        is_accepting=lambda: True,
    )
    removed = Observer()
    current = Observer()
    try:
        dispatcher.add_observer(removed)  # type: ignore[arg-type]
        dispatcher.replace_observers([current, current])  # type: ignore[list-item]
        dispatcher._notify("record_queue_wait", mode="sync", seconds=0.0)

        assert dispatcher._observers == [current]
        assert removed.queue_wait_calls == 0
        assert current.queue_wait_calls == 1
    finally:
        dispatcher.shutdown(wait=True)


@pytest.mark.asyncio
async def test_extension_dispatcher_rejects_new_work_after_shutdown() -> None:
    dispatcher = _ExtensionDispatcher(
        max_workers=1,
        max_in_flight=1,
        capacity_timeout_seconds=1.0,
        admission_lock=threading.Lock(),
        is_accepting=lambda: True,
    )
    dispatcher.shutdown(wait=True)

    async def native() -> str:
        return "unexpected"

    try:
        assert dispatcher.create_cleanup_task(lambda: asyncio.sleep(0)) is None
        with pytest.raises(RuntimeError, match="runtime is closed"):
            await dispatcher.invoke(native)
        with pytest.raises(RuntimeError, match="runtime is closed"):
            await dispatcher.invoke(lambda: "unexpected")
    finally:
        dispatcher.shutdown(wait=True)


def test_native_async_detection_handles_a_recursive_wrapped_chain() -> None:
    def callback() -> None:
        return None

    callback.__wrapped__ = callback  # type: ignore[attr-defined]

    assert not is_native_async_callable(callback)


@pytest.mark.asyncio
async def test_aclose_rejects_cleanup_submitted_after_drain() -> None:
    runtime = Runtime()
    allow_late_submission = asyncio.Event()
    submitted = asyncio.Event()
    release_shutdown = asyncio.Event()
    scheduled: list[asyncio.Task[Any] | None] = []

    async def cleanup() -> None:
        raise AssertionError("late cleanup must not start after Runtime close")

    async def submit_late_cleanup() -> None:
        await allow_late_submission.wait()
        scheduled.append(schedule_extension_cleanup(cleanup()))
        submitted.set()

    background: asyncio.Task[Any] | None = None

    @runtime.tool()
    async def work() -> str:
        nonlocal background
        background = asyncio.create_task(submit_late_cleanup())
        return "ok"

    original_drain = runtime._extension_dispatcher.drain_cleanup_tasks

    async def gated_drain() -> None:
        await original_drain()
        allow_late_submission.set()
        await submitted.wait()
        await release_shutdown.wait()

    runtime._extension_dispatcher.drain_cleanup_tasks = gated_drain  # type: ignore[method-assign]
    closing: asyncio.Task[None] | None = None
    try:
        assert await runtime.ainvoke("work") == "ok"
        assert background is not None
        closing = asyncio.create_task(runtime.aclose())
        await asyncio.wait_for(submitted.wait(), timeout=1)
        assert scheduled == [None]
        release_shutdown.set()
        await asyncio.wait_for(closing, timeout=1)
        await background
        assert runtime._closed
    finally:
        release_shutdown.set()
        if background is not None:
            await asyncio.gather(background, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_waits_for_background_native_extension_admitted_before_return() -> None:
    runtime = Runtime()
    entered = asyncio.Event()
    release = asyncio.Event()
    cancelled = asyncio.Event()
    effects: list[str] = []
    background: asyncio.Task[Any] | None = None

    async def extension() -> None:
        while not release.is_set():
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
        effects.append("completed")

    @runtime.tool()
    async def work() -> str:
        nonlocal background
        background = asyncio.create_task(invoke_extension(extension))
        await entered.wait()
        return "ok"

    closing: asyncio.Task[None] | None = None
    try:
        assert await runtime.ainvoke("work") == "ok"
        assert background is not None
        await asyncio.wait_for(cancelled.wait(), timeout=1)

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()
        assert not effects

        release.set()
        await asyncio.wait_for(closing, timeout=1)
        assert effects == ["completed"]
    finally:
        release.set()
        if background is not None:
            await asyncio.gather(background, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_aclose_drains_cleanup_admitted_by_an_active_operation() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    cleaned = asyncio.Event()

    class DeferredCleanup(GatingMiddleware):
        name = "deferred_cleanup"

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            entered.set()
            await release.wait()

            async def cleanup() -> None:
                cleaned.set()

            assert schedule_extension_cleanup(cleanup()) is not None
            return context

    runtime = Runtime([DeferredCleanup()])

    @runtime.tool()
    def work() -> str:
        return "ok"

    invocation = asyncio.create_task(runtime.ainvoke("work"))
    closing: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0)
        assert not closing.done()
        release.set()
        assert await asyncio.wait_for(invocation, timeout=1) == "ok"
        await asyncio.wait_for(closing, timeout=1)
        assert cleaned.is_set()
    finally:
        release.set()
        await asyncio.gather(invocation, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_native_async_callable_instances_and_partials_stay_on_calling_loop() -> None:
    observed: list[tuple[str, int, int]] = []
    caller_thread = threading.get_ident()
    caller_loop = id(asyncio.get_running_loop())

    class AsyncHook:
        async def __call__(self, context):
            observed.append(("hook", threading.get_ident(), id(asyncio.get_running_loop())))
            return context

    async def review(context) -> bool:
        observed.append(("review", threading.get_ident(), id(asyncio.get_running_loop())))
        return True

    runtime = Runtime([LLMMiddleware(partial(review))])
    runtime.hooks.register(HookPoint.BEFORE_PIPELINE, AsyncHook())

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert observed == [
            ("hook", caller_thread, caller_loop),
            ("review", caller_thread, caller_loop),
        ]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_wrapped_async_callback_stays_on_the_calling_loop() -> None:
    wrapper_threads: list[str] = []
    coroutine_threads: list[int] = []
    caller_thread = threading.get_ident()

    def synchronous_decorator(callback):
        @wraps(callback)
        def wrapped(context):
            wrapper_threads.append(threading.current_thread().name)
            return callback(context)

        return wrapped

    @synchronous_decorator
    async def review(context) -> bool:
        coroutine_threads.append(threading.get_ident())
        return True

    runtime = Runtime([LLMMiddleware(review)])

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert wrapper_threads == [threading.current_thread().name]
        assert coroutine_threads == [caller_thread]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_async_policy_observer_snapshot_and_notification_adapters_work() -> None:
    observed: list[tuple[str, int, int]] = []
    caller_thread = threading.get_ident()
    caller_loop = id(asyncio.get_running_loop())

    class AsyncOPA:
        async def evaluate(self, context) -> OPADecision:
            observed.append(("opa", threading.get_ident(), id(asyncio.get_running_loop())))
            return OPADecision(True, "allowed")

    class AsyncAudit:
        async def write(self, event) -> None:
            observed.append(("audit", threading.get_ident(), id(asyncio.get_running_loop())))

    class AsyncSnapshots:
        def __init__(self) -> None:
            self.snapshots: list[object] = []

        async def write(self, snapshot) -> None:
            observed.append(("snapshot", threading.get_ident(), id(asyncio.get_running_loop())))
            self.snapshots.append(snapshot)

        def read_trace(self, trace_id: str) -> tuple[object, ...]:
            return tuple(self.snapshots)

    async def send(payload: dict[str, Any]) -> None:
        observed.append(("slack", threading.get_ident(), id(asyncio.get_running_loop())))

    snapshots = AsyncSnapshots()
    runtime = Runtime(
        [
            OPAMiddleware(AsyncOPA()),
            AuditMiddleware(AsyncAudit()),
            SnapshotMiddleware(snapshots),
            SlackNotificationMiddleware(
                send, statuses=frozenset({ExecutionStatus.SUCCEEDED})
            ),
        ]
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert {name for name, _, _ in observed} == {
            "opa",
            "audit",
            "snapshot",
            "slack",
        }
        assert all(
            thread_id == caller_thread and loop_id == caller_loop
            for _, thread_id, loop_id in observed
        )
        assert snapshots.snapshots
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_async_identity_and_binding_providers_stay_on_calling_loop() -> None:
    observed: list[tuple[str, int, int]] = []
    caller_thread = threading.get_ident()
    caller_loop = id(asyncio.get_running_loop())

    class AsyncIdentity:
        async def verify(self, claims=None) -> VerifiedPrincipal:
            observed.append(("identity", threading.get_ident(), id(asyncio.get_running_loop())))
            return VerifiedPrincipal("issuer", "subject", "tenant")

    async def get_key(*, tenant: str, version: str) -> bytes:
        observed.append(("binding", threading.get_ident(), id(asyncio.get_running_loop())))
        return b"key"

    runtime = Runtime(identity_provider=AsyncIdentity(), require_verified_identity=True)

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert (
            await runtime._call_binding_provider(
                get_key,
                stage="identity digest key",
                deadline=None,
                tenant="tenant",
                version="v1",
            )
            == b"key"
        )
        assert {name for name, _, _ in observed} == {"identity", "binding"}
        assert all(
            thread_id == caller_thread and loop_id == caller_loop
            for _, thread_id, loop_id in observed
        )
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_sync_capacity_separates_workers_from_admitted_queue() -> None:
    runtime = Runtime(
        limits=RuntimeLimits(
            execution_timeout_seconds=1.0,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=2,
        )
    )
    entered = threading.Event()
    release = threading.Event()

    def block() -> str:
        entered.set()
        assert release.wait(timeout=1)
        return "first"

    first = asyncio.create_task(runtime._run_blocking_extension(block))
    second = asyncio.create_task(runtime._run_blocking_extension(lambda: "second"))
    third = asyncio.create_task(runtime._run_blocking_extension(lambda: "third"))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        await _wait_until(
            lambda: runtime.extension_dispatch_snapshot.in_flight == 2
            and runtime.extension_dispatch_snapshot.executor_queued == 1
        )
        await _wait_until(
            lambda: runtime.extension_dispatch_snapshot.admission_waiters == 1
        )
        snapshot = runtime.extension_dispatch_snapshot
        assert snapshot.worker_capacity == 1
        assert snapshot.in_flight_capacity == 2
        assert snapshot.active_workers == 1
        assert snapshot.executor_queued == 1
        assert snapshot.saturated is True

        release.set()
        assert await first == "first"
        assert await second == "second"
        assert await third == "third"
    finally:
        release.set()
        await asyncio.gather(first, second, third, return_exceptions=True)
        await runtime.aclose()


@pytest.mark.asyncio
async def test_async_extension_is_not_queued_behind_saturated_sync_workers() -> None:
    runtime = Runtime(
        limits=RuntimeLimits(
            execution_timeout_seconds=1.0,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        )
    )
    entered = threading.Event()
    release = threading.Event()
    caller_thread = threading.get_ident()

    def block() -> None:
        entered.set()
        assert release.wait(timeout=1)

    async def async_extension() -> str:
        assert threading.get_ident() == caller_thread
        await asyncio.sleep(0)
        return "async"

    first = asyncio.create_task(runtime._run_blocking_extension(block))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        assert (
            await asyncio.wait_for(
                runtime._invoke_extension(async_extension), timeout=0.5
            )
            == "async"
        )
    finally:
        release.set()
        await asyncio.gather(first, return_exceptions=True)
        await runtime.aclose()


@pytest.mark.asyncio
async def test_sync_observer_does_not_stall_a_ten_millisecond_ticker() -> None:
    def send(payload: dict[str, Any]) -> None:
        time.sleep(0.15)

    runtime = Runtime(
        [
            SlackNotificationMiddleware(
                send,
                statuses=frozenset({ExecutionStatus.SUCCEEDED}),
            )
        ]
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await _assert_ticker_stays_responsive(runtime.ainvoke("work")) == "ok"
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_sync_otel_terminal_export_uses_one_dispatch_turn(monkeypatch) -> None:
    class Span:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            self.attributes[key] = value

        def end(self) -> None:
            self.end_calls += 1

    class Tracer:
        def __init__(self) -> None:
            self.span = Span()

        def start_span(self, _name: str, *, attributes: dict[str, object]) -> Span:
            self.span.attributes.update(attributes)
            return self.span

    original_invoke_extension = telemetry_module.invoke_extension
    dispatches: list[str] = []

    async def record_dispatch(callback, *args, **kwargs):
        dispatches.append(getattr(callback, "__name__", type(callback).__name__))
        return await original_invoke_extension(callback, *args, **kwargs)

    monkeypatch.setattr(telemetry_module, "invoke_extension", record_dispatch)
    tracer = Tracer()
    middleware = OpenTelemetryMiddleware(tracer)
    context = ExecutionContext.create(ToolCall("work"))

    await middleware.process(context)
    dispatches.clear()

    await middleware.process(context.evolve(status=ExecutionStatus.SUCCEEDED))

    assert dispatches == ["_finish_sync_span"]
    assert tracer.span.attributes["arg.status"] == ExecutionStatus.SUCCEEDED.value
    assert tracer.span.end_calls == 1


@pytest.mark.asyncio
async def test_sync_otel_terminal_awaits_wrapped_attributes_before_end() -> None:
    class Span:
        def __init__(self) -> None:
            self.status = ExecutionStatus.PENDING.value

        def set_attribute(self, key: str, value: object):
            async def apply() -> None:
                await asyncio.sleep(0)
                if key == "arg.status":
                    self.status = str(value)

            return apply()

        def end(self) -> None:
            assert self.status == ExecutionStatus.SUCCEEDED.value

    class Tracer:
        def __init__(self) -> None:
            self.span = Span()

        def start_span(self, _name: str, *, attributes: dict[str, object]) -> Span:
            del attributes
            return self.span

    middleware = OpenTelemetryMiddleware(Tracer())
    context = ExecutionContext.create(ToolCall("work"))

    await middleware.process(context)
    await middleware.process(context.evolve(status=ExecutionStatus.SUCCEEDED))


@pytest.mark.asyncio
async def test_native_async_otel_terminal_records_failed_and_aborted_spans() -> None:
    class Span:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.exceptions: list[BaseException] = []
            self.ended = False

        async def set_attribute(self, key: str, value: object) -> None:
            self.attributes[key] = value

        async def record_exception(self, error: BaseException) -> None:
            self.exceptions.append(error)

        async def end(self) -> None:
            self.ended = True

    class Tracer:
        def __init__(self) -> None:
            self.spans: list[Span] = []

        async def start_span(
            self, _name: str, *, attributes: dict[str, object]
        ) -> Span:
            span = Span()
            span.attributes.update(attributes)
            self.spans.append(span)
            return span

    tracer = Tracer()
    middleware = OpenTelemetryMiddleware(tracer)
    failed = ExecutionContext.create(ToolCall("failed"))
    aborted = ExecutionContext.create(ToolCall("aborted"))

    await middleware.process(failed)
    await middleware.process(failed.evolve(status=ExecutionStatus.FAILED))
    await middleware.process(aborted)
    assert await middleware.aabort(aborted.trace_id, description="cancelled")

    assert tracer.spans[0].attributes["arg.status"] == ExecutionStatus.FAILED.value
    assert tracer.spans[0].exceptions
    assert tracer.spans[0].ended
    assert tracer.spans[1].exceptions
    assert tracer.spans[1].ended


@pytest.mark.asyncio
async def test_native_async_otel_drops_an_unsupported_parent_context() -> None:
    class Span:
        def __init__(self) -> None:
            self.ended = False

        def set_attribute(self, _key: str, _value: object) -> None:
            return None

        def end(self) -> None:
            self.ended = True

    class Tracer:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.span = Span()

        async def start_span(self, _name: str, *, attributes: dict[str, object]) -> Span:
            self.attributes = dict(attributes)
            return self.span

    tracer = Tracer()
    middleware = OpenTelemetryMiddleware(tracer, parent_context=object())
    context = ExecutionContext.create(ToolCall("work"))

    await middleware.process(context)
    assert tracer.attributes["arg.parent_context_dropped"] is True
    assert await middleware.aabort(context.trace_id)
    assert tracer.span.ended


@pytest.mark.asyncio
async def test_sync_tracer_does_not_stall_a_ten_millisecond_ticker() -> None:
    class Span:
        def set_attribute(self, key: str, value: object) -> None:
            return None

        def end(self) -> None:
            return None

    class Tracer:
        def start_span(self, name: str, *, attributes: dict[str, object]) -> Span:
            time.sleep(0.15)
            return Span()

    runtime = Runtime([OpenTelemetryMiddleware(Tracer())])

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await _assert_ticker_stays_responsive(runtime.ainvoke("work")) == "ok"
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_legacy_sync_tracer_does_not_stall_a_ten_millisecond_ticker() -> None:
    caller_thread = threading.get_ident()
    manager_threads: list[int] = []

    class Span:
        def set_attribute(self, key: str, value: object) -> None:
            return None

        def end(self) -> None:
            return None

    class LegacyTracer:
        def start_as_current_span(self, name: str, **kwargs: object):
            @contextmanager
            def manager():
                manager_threads.append(threading.get_ident())
                time.sleep(0.15)
                try:
                    yield Span()
                finally:
                    time.sleep(0.15)

            return manager()

    runtime = Runtime([OpenTelemetryMiddleware(LegacyTracer())])

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await _assert_ticker_stays_responsive(runtime.ainvoke("work")) == "ok"
        assert manager_threads
        assert manager_threads == [manager_threads[0]]
        assert manager_threads[0] != caller_thread
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_legacy_otel_manager_releases_on_runtime_shutdown_signal() -> None:
    exited = threading.Event()

    class Span:
        def set_attribute(self, _key: str, _value: object) -> None:
            return None

        def end(self) -> None:
            return None

    class LegacyTracer:
        def start_as_current_span(self, _name: str, **_kwargs: object):
            @contextmanager
            def manager():
                try:
                    yield Span()
                finally:
                    exited.set()

            return manager()

    shutdown = threading.Event()
    middleware = OpenTelemetryMiddleware(
        LegacyTracer(), terminal_wait_seconds=1.0
    )
    middleware._bind_extension_shutdown_signal(shutdown)
    context = ExecutionContext.create(ToolCall("work"))

    await middleware.process(context)
    shutdown.set()

    assert await asyncio.wait_for(asyncio.to_thread(exited.wait, 1), timeout=1.1)
    await _wait_until(lambda: middleware.active_span_count == 0)


@pytest.mark.asyncio
async def test_pipeline_replacement_rebinds_shared_legacy_otel_shutdown() -> None:
    exited = threading.Event()

    class Span:
        def set_attribute(self, _key: str, _value: object) -> None:
            return None

        def end(self) -> None:
            return None

    class LegacyTracer:
        def start_as_current_span(self, _name: str, **_kwargs: object):
            @contextmanager
            def manager():
                try:
                    yield Span()
                finally:
                    exited.set()

            return manager()

    middleware = OpenTelemetryMiddleware(LegacyTracer(), terminal_wait_seconds=1.0)
    first = Runtime([middleware])
    second = Runtime([middleware])
    context = ExecutionContext.create(ToolCall("work"))

    try:
        first.pipeline = [middleware]
        assert (
            middleware._extension_shutdown_signal
            is first._extension_dispatcher.shutdown_signal
        )
        assert (
            middleware._extension_shutdown_signal
            is not second._extension_dispatcher.shutdown_signal
        )
        await middleware.process(context)

        await first.aclose()

        assert await asyncio.wait_for(asyncio.to_thread(exited.wait, 1), timeout=1.1)
        await _wait_until(lambda: middleware.active_span_count == 0)
    finally:
        if not first._closed:
            await first.aclose()
        if not second._closed:
            await second.aclose()


@pytest.mark.asyncio
async def test_cancelled_sync_extension_remains_visible_until_aclose_waits_for_it() -> None:
    runtime = Runtime(
        limits=RuntimeLimits(
            execution_timeout_seconds=1.0,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        )
    )
    entered = threading.Event()
    release = threading.Event()

    def block() -> None:
        entered.set()
        assert release.wait(timeout=1)

    task = asyncio.create_task(runtime._run_blocking_extension(block))
    closing: asyncio.Task[None] | None = None
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await _wait_until(
            lambda: runtime.extension_dispatch_snapshot.detached_sync_work == 1
        )

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
        assert runtime.extension_dispatch_snapshot.detached_sync_work == 0
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_foreign_event_loop_future_is_rejected() -> None:
    runtime = Runtime()
    foreign_loop = asyncio.new_event_loop()
    foreign_future = foreign_loop.create_future()
    foreign_future.set_result("unexpected")

    def callback():
        return foreign_future

    async def async_callback():
        return foreign_future

    try:
        with pytest.raises(RuntimeError, match="different event loop"):
            await runtime._invoke_extension(callback)
        with pytest.raises(RuntimeError, match="different event loop"):
            await runtime._invoke_extension(async_callback)
    finally:
        foreign_loop.close()
        await runtime.aclose()


@pytest.mark.asyncio
async def test_prometheus_exposes_low_cardinality_extension_dispatch_metrics() -> None:
    registry = CollectorRegistry()
    metrics = PrometheusMiddleware(registry=registry, prefix="dispatch_test")
    runtime = Runtime(
        [metrics],
        limits=RuntimeLimits(max_blocking_extension_workers=4),
    )

    async def async_hook(context):
        return context

    def sync_hook(context):
        return context

    runtime.hooks.register(HookPoint.BEFORE_PIPELINE, async_hook)
    runtime.hooks.register(HookPoint.BEFORE_PIPELINE, sync_hook)

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        output = generate_latest(registry).decode()
        extension_lines = "\n".join(
            line for line in output.splitlines() if "extension_dispatch" in line
        )
        assert 'dispatch_test_extension_dispatch_queue_wait_seconds_count{mode="async"} 1.0' in output
        assert 'dispatch_test_extension_dispatch_queue_wait_seconds_count{mode="sync"} 1.0' in output
        assert 'dispatch_test_extension_dispatch_workers{state="capacity"} 4.0' in output
        assert 'dispatch_test_extension_dispatch_queue_depth{state="executor"} 0.0' in output
        assert 'tool="' not in extension_lines
        assert "trace" not in extension_lines
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_timed_out_otel_start_is_finalized_before_runtime_shutdown() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingSpan:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.end_threads: list[str] = []
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            self.attributes[key] = value

        def end(self) -> None:
            self.end_threads.append(threading.current_thread().name)
            self.end_calls += 1

    class BlockingTracer:
        def __init__(self) -> None:
            self.spans: list[BlockingSpan] = []
            self.start_threads: list[str] = []

        def start_span(self, name: str, *, attributes: dict[str, object]) -> BlockingSpan:
            self.start_threads.append(threading.current_thread().name)
            entered.set()
            assert release.wait(timeout=1)
            span = BlockingSpan()
            span.attributes.update(attributes)
            self.spans.append(span)
            return span

    tracer = BlockingTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    runtime = Runtime(
        [middleware],
        limits=RuntimeLimits(
            observer_timeout_seconds=0.02,
            cancellation_grace_seconds=0.01,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        ),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    closing: asyncio.Task[None] | None = None
    try:
        invocation = asyncio.create_task(runtime.ainvoke("work"))
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        assert await invocation == "ok"
        assert middleware.active_span_count == 1

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
        span = tracer.spans[0]
        assert span.end_calls == 1
        assert tracer.start_threads == span.end_threads
        assert middleware.active_span_count == 0
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


def test_sync_invoke_retains_late_otel_start_until_runtime_close() -> None:
    entered = threading.Event()
    release = threading.Event()

    class Span:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            self.attributes[key] = value

        def end(self) -> None:
            self.end_calls += 1

    class BlockingTracer:
        def __init__(self) -> None:
            self.spans: list[Span] = []

        def start_span(self, name: str, *, attributes: dict[str, object]) -> Span:
            entered.set()
            assert release.wait(timeout=1)
            span = Span()
            span.attributes.update(attributes)
            self.spans.append(span)
            return span

    tracer = BlockingTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    runtime = Runtime(
        [middleware],
        limits=RuntimeLimits(
            observer_timeout_seconds=0.02,
            cancellation_grace_seconds=0.01,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        ),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert runtime.invoke("work") == "ok"
        assert entered.wait(timeout=1)
        assert middleware.active_span_count == 1

        release.set()
        asyncio.run(runtime.aclose())

        assert tracer.spans[0].end_calls == 1
        assert middleware.active_span_count == 0
        assert runtime._get_sync_loop() is None
    finally:
        release.set()
        if not runtime._closed:
            asyncio.run(runtime.aclose())


def test_sync_invoke_aclose_delegates_cleanup_to_its_owner_loop() -> None:
    entered = threading.Event()
    release = threading.Event()

    class Span:
        def __init__(self) -> None:
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            return None

        def end(self) -> None:
            self.end_calls += 1

    class BlockingTracer:
        def __init__(self) -> None:
            self.span: Span | None = None

        def start_span(self, name: str, *, attributes: dict[str, object]) -> Span:
            entered.set()
            assert release.wait(timeout=1)
            self.span = Span()
            return self.span

    tracer = BlockingTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    runtime = Runtime(
        [middleware],
        limits=RuntimeLimits(
            observer_timeout_seconds=0.02,
            cancellation_grace_seconds=0.01,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        ),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    async def close_after_release() -> None:
        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()
        release.set()
        await asyncio.wait_for(closing, timeout=1)

    try:
        assert runtime.invoke("work") == "ok"
        assert entered.wait(timeout=1)
        asyncio.run(close_after_release())
        assert tracer.span is not None
        assert tracer.span.end_calls == 1
        assert middleware.active_span_count == 0
        assert runtime._get_sync_loop() is None
    finally:
        release.set()
        if not runtime._closed:
            asyncio.run(runtime.aclose())


def test_sync_invoke_preserves_caller_contextvars() -> None:
    marker = ContextVar("sync_invoke_marker", default="missing")
    runtime = Runtime()

    @runtime.tool()
    async def read_marker() -> str:
        return marker.get()

    token = marker.set("present")
    try:
        assert runtime.invoke("read_marker") == "present"
    finally:
        marker.reset(token)
        runtime.close()


@pytest.mark.asyncio
async def test_timed_out_otel_end_remains_owned_until_cleanup_finishes() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingSpan:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            self.attributes[key] = value

        def end(self) -> None:
            self.end_calls += 1
            entered.set()
            assert release.wait(timeout=1)

    class Tracer:
        def __init__(self) -> None:
            self.span = BlockingSpan()

        def start_span(self, name: str, *, attributes: dict[str, object]) -> BlockingSpan:
            self.span.attributes.update(attributes)
            return self.span

    tracer = Tracer()
    middleware = OpenTelemetryMiddleware(tracer)
    runtime = Runtime(
        [middleware],
        limits=RuntimeLimits(
            observer_timeout_seconds=0.02,
            cancellation_grace_seconds=0.01,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        ),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    closing: asyncio.Task[None] | None = None
    try:
        invocation = asyncio.create_task(runtime.ainvoke("work"))
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        assert await invocation == "ok"
        assert middleware.active_span_count == 1

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()

        release.set()
        await asyncio.wait_for(closing, timeout=1)
        assert tracer.span.end_calls == 1
        assert middleware.active_span_count == 0
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        elif not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_native_async_otel_lifecycle_stays_on_calling_loop() -> None:
    observations: list[tuple[str, int, int]] = []
    caller_thread = threading.get_ident()
    caller_loop = id(asyncio.get_running_loop())

    class AsyncSpan:
        async def set_attribute(self, key: str, value: object) -> None:
            observations.append(
                ("attribute", threading.get_ident(), id(asyncio.get_running_loop()))
            )

        async def end(self) -> None:
            observations.append(("end", threading.get_ident(), id(asyncio.get_running_loop())))

    class AsyncTracer:
        async def start_span(self, name: str, *, attributes: dict[str, object]) -> AsyncSpan:
            observations.append(("start", threading.get_ident(), id(asyncio.get_running_loop())))
            return AsyncSpan()

    runtime = Runtime([OpenTelemetryMiddleware(AsyncTracer())])

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert {name for name, _, _ in observations} >= {"start", "attribute", "end"}
        assert all(
            thread_id == caller_thread and loop_id == caller_loop
            for _, thread_id, loop_id in observations
        )
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_wrapped_async_otel_start_stays_on_calling_loop() -> None:
    wrapper_threads: list[str] = []
    coroutine_threads: list[int] = []
    caller_thread = threading.get_ident()

    def synchronous_decorator(callback):
        @wraps(callback)
        def wrapped(*args, **kwargs):
            wrapper_threads.append(threading.current_thread().name)
            return callback(*args, **kwargs)

        return wrapped

    class Span:
        def set_attribute(self, key: str, value: object) -> None:
            return None

        def end(self) -> None:
            return None

    class Tracer:
        @synchronous_decorator
        async def start_span(self, name: str, *, attributes: dict[str, object]) -> Span:
            coroutine_threads.append(threading.get_ident())
            return Span()

    runtime = Runtime([OpenTelemetryMiddleware(Tracer())])

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert wrapper_threads == [threading.current_thread().name]
        assert coroutine_threads == [caller_thread]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_legacy_otel_manager_exits_in_its_owner_task() -> None:
    active_span = ContextVar("legacy_otel_span", default=None)
    events: list[tuple[str, str, int]] = []

    class Span:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            self.attributes[key] = value

        def end(self) -> None:
            self.end_calls += 1

    class LegacyTracer:
        def __init__(self) -> None:
            self.span = Span()

        def start_as_current_span(self, name: str, **kwargs: object):
            @contextmanager
            def manager():
                token = active_span.set(name)
                task = asyncio.current_task()
                events.append(("enter", task.get_name() if task else "", threading.get_ident()))
                try:
                    yield self.span
                finally:
                    task = asyncio.current_task()
                    events.append(("exit", task.get_name() if task else "", threading.get_ident()))
                    active_span.reset(token)
                    self.span.end()

            return manager()

    tracer = LegacyTracer()
    runtime = Runtime([OpenTelemetryMiddleware(tracer)])

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert [event[0] for event in events] == ["enter", "exit"]
        assert events[0][1] == events[1][1]
        assert events[0][2] == events[1][2]
        assert tracer.span.attributes["arg.status"] == ExecutionStatus.SUCCEEDED.value
        assert tracer.span.end_calls == 1
        assert active_span.get() is None
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_legacy_otel_manager_does_not_expire_a_live_tool_span() -> None:
    class Span:
        def __init__(self) -> None:
            self.end_calls = 0

        def set_attribute(self, _key: str, _value: object) -> None:
            return None

        def end(self) -> None:
            self.end_calls += 1

    class LegacyTracer:
        def __init__(self) -> None:
            self.spans: list[Span] = []

        def start_as_current_span(self, _name: str, **_kwargs: object):
            span = Span()
            self.spans.append(span)

            @contextmanager
            def manager():
                yield span
                span.end()

            return manager()

    tracer = LegacyTracer()
    runtime = Runtime(
        [OpenTelemetryMiddleware(tracer, terminal_wait_seconds=0.01)]
    )

    @runtime.tool()
    async def work() -> str:
        await asyncio.sleep(0.12)
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert len(tracer.spans) == 1
        assert tracer.spans[0].end_calls == 1
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_legacy_otel_terminal_awaits_wrapped_attributes_before_end() -> None:
    class Span:
        def __init__(self) -> None:
            self.status = ExecutionStatus.PENDING.value
            self.end_calls = 0

        def set_attribute(self, key: str, value: object):
            async def apply() -> None:
                await asyncio.sleep(0)
                if key == "arg.status":
                    self.status = str(value)

            return apply()

        def end(self) -> None:
            assert self.status == ExecutionStatus.SUCCEEDED.value
            self.end_calls += 1

    class LegacyTracer:
        def __init__(self) -> None:
            self.span = Span()

        def start_as_current_span(self, _name: str, **_kwargs: object):
            @contextmanager
            def manager():
                yield self.span
                self.span.end()

            return manager()

    tracer = LegacyTracer()
    runtime = Runtime([OpenTelemetryMiddleware(tracer)])

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert tracer.span.status == ExecutionStatus.SUCCEEDED.value
        assert tracer.span.end_calls == 1
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_close_rejects_detached_synchronous_extension_work() -> None:
    runtime = Runtime(
        limits=RuntimeLimits(
            execution_timeout_seconds=1.0,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        )
    )
    entered = threading.Event()
    release = threading.Event()

    def block() -> None:
        entered.set()
        assert release.wait(timeout=1)

    task = asyncio.create_task(runtime._run_blocking_extension(block))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await _wait_until(
            lambda: runtime.extension_dispatch_snapshot.detached_sync_work == 1
        )

        with pytest.raises(RuntimeError, match="synchronous extension work is pending"):
            runtime.close(wait=False)
        assert not runtime._closed

        release.set()
        await runtime.aclose()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", ["finish", "abort"])
async def test_legacy_sync_terminal_api_keeps_context_manager_with_its_owner(
    terminal: str,
) -> None:
    active_span = ContextVar("legacy_terminal_span", default=None)

    class Span:
        def __init__(self) -> None:
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            return None

        def end(self) -> None:
            self.end_calls += 1

    class LegacyTracer:
        def __init__(self) -> None:
            self.span = Span()
            self.exit_calls = 0

        def start_as_current_span(self, name: str, **kwargs: object):
            @contextmanager
            def manager():
                token = active_span.set(name)
                try:
                    yield self.span
                finally:
                    active_span.reset(token)
                    self.exit_calls += 1
                    self.span.end()

            return manager()

    tracer = LegacyTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    context = ExecutionContext.create(ToolCall("work"))

    await middleware.process(context)
    if terminal == "finish":
        assert middleware.finish(context.evolve(status=ExecutionStatus.SUCCEEDED))
    else:
        assert middleware.abort(context.trace_id)

    await _wait_until(lambda: tracer.exit_calls == 1)
    assert tracer.span.end_calls == 1
    await _wait_until(lambda: middleware.active_span_count == 0)
    assert active_span.get() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", ["finish", "abort"])
async def test_sync_otel_terminal_api_defers_native_async_callbacks(
    terminal: str,
) -> None:
    class AsyncSpan:
        def __init__(self) -> None:
            self.ended = asyncio.Event()

        async def set_attribute(self, key: str, value: object) -> None:
            return None

        async def end(self) -> None:
            self.ended.set()

    class AsyncTracer:
        def __init__(self) -> None:
            self.span = AsyncSpan()

        async def start_span(
            self, name: str, *, attributes: dict[str, object]
        ) -> AsyncSpan:
            return self.span

    tracer = AsyncTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    context = ExecutionContext.create(ToolCall("work"))

    await middleware.process(context)
    if terminal == "finish":
        assert middleware.finish(context.evolve(status=ExecutionStatus.SUCCEEDED))
    else:
        assert middleware.abort(context.trace_id)

    await asyncio.wait_for(tracer.span.ended.wait(), timeout=1)
    await _wait_until(lambda: middleware.active_span_count == 0)


@pytest.mark.asyncio
async def test_timed_out_native_otel_start_is_cancelled_before_shutdown() -> None:
    start_cancelled = asyncio.Event()

    class AsyncTracer:
        async def start_span(self, name: str, *, attributes: dict[str, object]):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                start_cancelled.set()
                raise

    middleware = OpenTelemetryMiddleware(AsyncTracer())
    runtime = Runtime(
        [middleware],
        limits=RuntimeLimits(
            observer_timeout_seconds=0.02,
            cancellation_grace_seconds=0.01,
        ),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        await asyncio.wait_for(start_cancelled.wait(), timeout=1)
        await asyncio.wait_for(runtime.aclose(), timeout=1)
        assert middleware.active_span_count == 0
    finally:
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", ["finish", "abort"])
async def test_concurrent_otel_terminal_calls_end_once_and_forget_failed_span(
    terminal: str,
) -> None:
    class Span:
        def __init__(self) -> None:
            self.end_calls = 0

        def set_attribute(self, key: str, value: object) -> None:
            return None

        def end(self) -> None:
            self.end_calls += 1
            raise RuntimeError("span exporter failed")

    class Tracer:
        def __init__(self) -> None:
            self.span = Span()

        def start_span(self, name: str, *, attributes: dict[str, object]) -> Span:
            return self.span

    tracer = Tracer()
    middleware = OpenTelemetryMiddleware(tracer)
    context = ExecutionContext.create(ToolCall("work"))
    await middleware.process(context)

    if terminal == "finish":
        calls = [
            asyncio.to_thread(
                middleware.finish,
                context.evolve(status=ExecutionStatus.SUCCEEDED),
            )
            for _ in range(2)
        ]
    else:
        calls = [
            asyncio.to_thread(middleware.abort, context.trace_id)
            for _ in range(2)
        ]
    outcomes = await asyncio.gather(*calls, return_exceptions=True)

    assert tracer.span.end_calls == 1
    assert middleware.active_span_count == 0
    assert all(isinstance(outcome, RuntimeError) for outcome in outcomes)


@pytest.mark.asyncio
async def test_timed_out_decorated_async_otel_start_is_cancelled_before_shutdown() -> None:
    start_cancelled = asyncio.Event()

    def synchronous_decorator(callback):
        @wraps(callback)
        def wrapped(*args, **kwargs):
            return callback(*args, **kwargs)

        return wrapped

    class Tracer:
        @synchronous_decorator
        async def start_span(self, name: str, *, attributes: dict[str, object]):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                start_cancelled.set()
                raise

    middleware = OpenTelemetryMiddleware(Tracer())
    runtime = Runtime(
        [middleware],
        limits=RuntimeLimits(
            observer_timeout_seconds=0.02,
            cancellation_grace_seconds=0.01,
        ),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        await asyncio.wait_for(start_cancelled.wait(), timeout=1)
        await asyncio.wait_for(runtime.aclose(), timeout=1)
        assert middleware.active_span_count == 0
    finally:
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_sync_otel_finish_claims_a_span_while_start_is_pending() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    class Span:
        def __init__(self) -> None:
            self.end_calls = 0

        async def set_attribute(self, key: str, value: object) -> None:
            return None

        async def end(self) -> None:
            self.end_calls += 1

    class Tracer:
        def __init__(self) -> None:
            self.span = Span()

        async def start_span(
            self, name: str, *, attributes: dict[str, object]
        ) -> Span:
            started.set()
            await release.wait()
            return self.span

    tracer = Tracer()
    middleware = OpenTelemetryMiddleware(tracer)
    context = ExecutionContext.create(ToolCall("work"))
    processing = asyncio.create_task(middleware.process(context))
    await asyncio.wait_for(started.wait(), timeout=1)

    assert middleware.finish(context.evolve(status=ExecutionStatus.SUCCEEDED))
    release.set()
    await asyncio.wait_for(processing, timeout=1)
    await _wait_until(lambda: tracer.span.end_calls == 1)
    assert middleware.active_span_count == 0


def test_cross_loop_async_otel_terminal_runs_on_span_owner_loop() -> None:
    started = threading.Event()
    stopped = threading.Event()
    owner_errors: list[BaseException] = []
    owner: dict[str, Any] = {}

    class Span:
        def __init__(self) -> None:
            self.end_calls = 0

        async def set_attribute(self, key: str, value: object) -> None:
            return None

        async def end(self) -> None:
            self.end_calls += 1

    span = Span()

    class Tracer:
        async def start_span(self, name: str, *, attributes: dict[str, object]) -> Span:
            started.set()
            await owner["release"].wait()
            return span

    middleware = OpenTelemetryMiddleware(Tracer())
    context = ExecutionContext.create(ToolCall("work"))

    def run_owner_loop() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        owner["loop"] = loop
        owner["release"] = asyncio.Event()
        owner["stop"] = asyncio.Event()

        async def drive() -> None:
            process = asyncio.create_task(middleware.process(context))
            await asyncio.wait_for(asyncio.to_thread(started.wait, 1), timeout=1.1)
            await owner["stop"].wait()
            await process

        try:
            loop.run_until_complete(drive())
        except BaseException as exc:
            owner_errors.append(exc)
        finally:
            loop.close()
            asyncio.set_event_loop(None)
            stopped.set()

    thread = threading.Thread(target=run_owner_loop, name="otel-owner-loop")
    thread.start()
    assert started.wait(timeout=1)

    async def finish_from_foreign_loop() -> bool:
        terminal = asyncio.create_task(
            middleware.afinish(context.evolve(status=ExecutionStatus.SUCCEEDED))
        )
        await asyncio.sleep(0.02)
        owner["loop"].call_soon_threadsafe(owner["release"].set)
        return await asyncio.wait_for(terminal, timeout=1)

    try:
        assert asyncio.run(finish_from_foreign_loop())
    finally:
        if "loop" in owner:
            owner["loop"].call_soon_threadsafe(owner["release"].set)
            owner["loop"].call_soon_threadsafe(owner["stop"].set)
        thread.join(timeout=1)

    assert stopped.is_set()
    assert not owner_errors
    assert span.end_calls == 1
    assert middleware.active_span_count == 0


def test_sync_otel_terminal_resolves_unrecognized_awaitable_callback() -> None:
    completed: list[str] = []

    async def async_end() -> None:
        completed.append("ended")

    class Span:
        def set_attribute(self, key: str, value: object) -> None:
            return None

        def end(self):
            return async_end()

    class Tracer:
        def __init__(self) -> None:
            self.span = Span()

        def start_span(self, name: str, *, attributes: dict[str, object]) -> Span:
            return self.span

    middleware = OpenTelemetryMiddleware(Tracer())
    context = ExecutionContext.create(ToolCall("work"))
    asyncio.run(middleware.process(context))

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", RuntimeWarning)
        assert middleware.finish(context.evolve(status=ExecutionStatus.SUCCEEDED))
        gc.collect()

    assert completed == ["ended"]
    assert middleware.active_span_count == 0
    assert not any("was never awaited" in str(item.message) for item in captured)


@pytest.mark.asyncio
async def test_close_rejects_running_synchronous_extension_work() -> None:
    runtime = Runtime(
        limits=RuntimeLimits(
            execution_timeout_seconds=1.0,
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        )
    )
    entered = threading.Event()
    release = threading.Event()

    def block() -> None:
        entered.set()
        assert release.wait(timeout=1)

    task = asyncio.create_task(runtime._run_blocking_extension(block))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        with pytest.raises(RuntimeError, match="synchronous extension work is pending"):
            runtime.close(wait=False)
        assert not runtime._closed

        release.set()
        await task
        await runtime.aclose()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        if not runtime._closed:
            await runtime.aclose()
