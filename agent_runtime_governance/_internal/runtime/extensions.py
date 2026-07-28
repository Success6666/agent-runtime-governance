"""Async-first dispatch for third-party runtime extensions.

The public runtime has to own synchronous extension work: unlike a best-effort
``asyncio.to_thread`` call, a runtime-owned worker can remain in shutdown
coordination after its awaiting coroutine is cancelled.  Native async
extensions must stay on the caller's event loop so a saturated synchronous
worker pool never delays them.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Iterable
from concurrent.futures import Future as ConcurrentFuture
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import dataclass
from functools import partial
from threading import Event, Lock
from time import perf_counter
from typing import Any, Awaitable, Callable, Protocol, TypeVar

from ...resilience import CapacityExceededError, RuntimeBulkhead
from .blocking import is_extension_cleanup_active, suspend_blocking_runner

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ExtensionDispatchSnapshot:
    """A read-only view of runtime-owned synchronous extension capacity."""

    worker_capacity: int
    in_flight_capacity: int
    active_workers: int
    in_flight: int
    executor_queued: int
    admission_waiters: int
    detached_sync_work: int
    saturated: bool


class ExtensionDispatchObserver(Protocol):
    """Internal low-cardinality instrumentation sink."""

    def record_queue_wait(self, *, mode: str, seconds: float) -> None: ...

    def record_execution(self, *, mode: str, seconds: float) -> None: ...

    def record_saturation(self, *, mode: str) -> None: ...

    def record_detached_work(self, *, count: int) -> None: ...


class _ExtensionDispatcher:
    """Own one bounded synchronous fallback domain for a ``Runtime``.

    ``admission_lock`` is the Runtime lifecycle lock.  Holding it across the
    accepting-state check and executor submission preserves the old atomic
    shutdown boundary without coupling this internal component to ``Runtime``.
    """

    def __init__(
        self,
        *,
        max_workers: int,
        max_in_flight: int,
        capacity_timeout_seconds: float,
        admission_lock: Lock,
        is_accepting: Callable[[], bool],
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least one")
        if max_in_flight < 1:
            raise ValueError("max_in_flight must be at least one")
        if capacity_timeout_seconds <= 0:
            raise ValueError("capacity_timeout_seconds must be greater than zero")
        self._worker_capacity = min(max_workers, max_in_flight)
        self._in_flight_capacity = max_in_flight
        self._capacity_timeout_seconds = capacity_timeout_seconds
        self._executor = ThreadPoolExecutor(
            max_workers=self._worker_capacity,
            thread_name_prefix="arg-extension",
        )
        self._bulkhead = RuntimeBulkhead(max_in_flight)
        self._admission_lock = admission_lock
        self._is_accepting = is_accepting
        self._state_lock = Lock()
        self._active_workers = 0
        self._detached_sync_futures: set[ConcurrentFuture[Any]] = set()
        self._cleanup_tasks: set[asyncio.Task[Any]] = set()
        self._observers: list[ExtensionDispatchObserver] = []
        self._shutdown = False
        self._shutdown_signal = Event()

    async def invoke(
        self,
        callback: Callable[..., T],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Invoke an extension without moving known async work to a thread."""

        if is_native_async_callable(callback):
            return await self._invoke_native_async(callback, *args, **kwargs)
        value = await self.invoke_sync(callback, *args, **kwargs)
        return await resolve_extension_result(value)

    async def invoke_sync(
        self,
        callback: Callable[..., T],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Run a callback in the owned sync domain without changing its result."""

        return await self._invoke_sync(callback, *args, **kwargs)

    def add_observer(self, observer: ExtensionDispatchObserver) -> None:
        """Attach an internal observer; instrumentation can never affect work."""

        with self._state_lock:
            self._observers.append(observer)

    def replace_observers(self, observers: Iterable[ExtensionDispatchObserver]) -> None:
        """Replace Runtime-managed observers without retaining removed middleware."""

        unique: list[ExtensionDispatchObserver] = []
        observer_ids: set[int] = set()
        for observer in observers:
            if id(observer) not in observer_ids:
                observer_ids.add(id(observer))
                unique.append(observer)
        with self._state_lock:
            self._observers = unique

    @property
    def shutdown_signal(self) -> Event:
        """Signal synchronous extensions that Runtime shutdown has begun."""

        return self._shutdown_signal

    def create_cleanup_task(
        self,
        factory: Callable[[], Awaitable[Any]],
    ) -> asyncio.Task[Any] | None:
        """Create and retain terminal cleanup unless worker shutdown has begun."""

        with self._state_lock:
            if self._shutdown:
                return None
            task = asyncio.create_task(factory(), name="extension-cleanup")
            self._cleanup_tasks.add(task)
        task.add_done_callback(self._forget_cleanup_task)
        return task

    def has_pending_cleanup_tasks(self) -> bool:
        """Return whether admitted terminal work still needs event-loop cleanup."""

        with self._state_lock:
            return any(not task.done() for task in self._cleanup_tasks)

    def has_detached_sync_work(self) -> bool:
        """Return whether a cancelled caller still has synchronous work running."""

        with self._state_lock:
            return any(not future.done() for future in self._detached_sync_futures)

    def pending_cleanup_tasks(self) -> tuple[asyncio.Task[Any], ...]:
        """Return pending cleanup tasks for Runtime cross-loop coordination."""

        with self._state_lock:
            return tuple(task for task in self._cleanup_tasks if not task.done())

    async def drain_cleanup_tasks(self) -> None:
        """Wait for admitted terminal cleanup before closing worker capacity."""

        while True:
            tasks = self.pending_cleanup_tasks()
            if not tasks:
                return
            await asyncio.gather(*tasks, return_exceptions=True)

    def snapshot(self) -> ExtensionDispatchSnapshot:
        """Return a consistent, implementation-independent capacity snapshot."""

        capacity, available, waiters = self._bulkhead.snapshot()
        with self._state_lock:
            active_workers = self._active_workers
            detached_sync_work = len(self._detached_sync_futures)
        in_flight = capacity - available
        return ExtensionDispatchSnapshot(
            worker_capacity=self._worker_capacity,
            in_flight_capacity=self._in_flight_capacity,
            active_workers=active_workers,
            in_flight=in_flight,
            executor_queued=max(0, in_flight - active_workers),
            admission_waiters=waiters,
            detached_sync_work=detached_sync_work,
            saturated=available == 0 or waiters > 0,
        )

    def shutdown(self, *, wait: bool) -> None:
        """Stop the owned worker pool after Runtime has rejected new work."""

        with self._state_lock:
            if self._shutdown:
                return
            if any(not task.done() for task in self._cleanup_tasks):
                raise RuntimeError(
                    "extension cleanup is pending; use await runtime.aclose()"
                )
            if not wait and any(
                not future.done() for future in self._detached_sync_futures
            ):
                raise RuntimeError(
                    "synchronous extension work is pending; use await runtime.aclose()"
                )
            self._shutdown = True
            self._shutdown_signal.set()
        self._executor.shutdown(wait=wait, cancel_futures=True)

    async def _invoke_native_async(
        self,
        callback: Callable[..., T],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> T:
        self._assert_accepting()
        started = perf_counter()
        try:
            return await resolve_extension_result(callback(*args, **kwargs))
        finally:
            self._notify(
                "record_queue_wait", mode="async", seconds=0.0
            )
            self._notify(
                "record_execution",
                mode="async",
                seconds=max(0.0, perf_counter() - started),
            )

    async def _invoke_sync(
        self,
        callback: Callable[..., T],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        queued_at = perf_counter()
        if self.snapshot().saturated:
            self._notify("record_saturation", mode="sync")
        try:
            lease = await self._bulkhead.acquire(self._capacity_timeout_seconds)
        except CapacityExceededError:
            self._notify("record_saturation", mode="sync")
            raise
        inherited_context = copy_context()

        def invoke() -> T:
            started = perf_counter()
            self._worker_started()
            self._notify(
                "record_queue_wait",
                mode="sync",
                seconds=max(0.0, started - queued_at),
            )
            try:
                # A worker inherits the active runtime context.  Suspending the
                # runner prevents a callback from recursively consuming this
                # bounded executor through SDK helpers.
                with suspend_blocking_runner():
                    return callback(*args, **kwargs)
            finally:
                self._notify(
                    "record_execution",
                    mode="sync",
                    seconds=max(0.0, perf_counter() - started),
                )
                self._worker_finished()

        try:
            with self._admission_lock:
                if not self._is_accepting() and not is_extension_cleanup_active():
                    raise RuntimeError("runtime is closed")
                with self._state_lock:
                    if self._shutdown:
                        raise RuntimeError("runtime is closed")
                future = self._executor.submit(inherited_context.run, invoke)
        except BaseException:
            lease.release()
            raise
        future.add_done_callback(lambda _future: lease.release())
        wrapped = asyncio.wrap_future(future)
        try:
            value = await asyncio.shield(wrapped)
        except asyncio.CancelledError:
            wrapped.add_done_callback(_consume_asyncio_future_result)
            if not future.cancel():
                if future.done():
                    _discard_unawaited_result(future)
                else:
                    self._mark_detached(future)
            raise
        return value

    def _assert_accepting(self) -> None:
        with self._admission_lock:
            if not self._is_accepting() and not is_extension_cleanup_active():
                raise RuntimeError("runtime is closed")
            with self._state_lock:
                if self._shutdown:
                    raise RuntimeError("runtime is closed")

    def _worker_started(self) -> None:
        with self._state_lock:
            self._active_workers += 1

    def _worker_finished(self) -> None:
        with self._state_lock:
            self._active_workers -= 1

    def _mark_detached(self, future: ConcurrentFuture[Any]) -> None:
        with self._state_lock:
            if future in self._detached_sync_futures:
                return
            self._detached_sync_futures.add(future)
            count = len(self._detached_sync_futures)
        future.add_done_callback(self._forget_detached)
        future.add_done_callback(_discard_unawaited_result)
        self._notify("record_detached_work", count=count)

    def _forget_detached(self, future: ConcurrentFuture[Any]) -> None:
        with self._state_lock:
            self._detached_sync_futures.discard(future)
            count = len(self._detached_sync_futures)
        self._notify("record_detached_work", count=count)

    def _forget_cleanup_task(self, task: asyncio.Task[Any]) -> None:
        with self._state_lock:
            self._cleanup_tasks.discard(task)
        _consume_task_result(task)

    def _notify(self, method: str, **kwargs: Any) -> None:
        with self._state_lock:
            observers = tuple(self._observers)
        for observer in observers:
            try:
                getattr(observer, method)(**kwargs)
            except BaseException:
                # Observability is deliberately non-authoritative.
                continue


async def invoke_standalone_extension(
    callback: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Dispatch an extension outside a Runtime without using its worker pool."""

    if is_native_async_callable(callback):
        return await resolve_extension_result(callback(*args, **kwargs))
    caller_cancelled = Event()

    def invoke() -> T:
        value = callback(*args, **kwargs)
        if caller_cancelled.is_set():
            _discard_unawaited_value(value)
        return value

    worker_task = asyncio.create_task(
        asyncio.to_thread(invoke),
        name="standalone-extension",
    )
    try:
        value = await asyncio.shield(worker_task)
    except asyncio.CancelledError:
        # ``to_thread`` cannot stop a Python callback. Keep its result owned
        # until it arrives so a late coroutine is closed instead of leaked.
        caller_cancelled.set()
        worker_task.add_done_callback(_discard_unawaited_result)
        raise
    return await resolve_extension_result(value)


def is_native_async_callable(callback: Callable[..., Any]) -> bool:
    """Recognize native async callables without executing synchronous wrappers."""

    target: Any = callback
    while isinstance(target, partial):
        target = target.func
    # ``functools.wraps`` is the supported way to preserve an async callback's
    # identity through a decorator.  Treat such wrappers as native async so a
    # saturated legacy-worker pool cannot delay their coroutine body.  A
    # malformed self-referential ``__wrapped__`` chain is still a normal
    # synchronous callback rather than a dispatch-time failure.
    try:
        target = inspect.unwrap(target)
    except ValueError:
        pass
    if inspect.iscoroutinefunction(target):
        return True
    call = getattr(type(target), "__call__", None)
    if call is None:
        return False
    try:
        call = inspect.unwrap(call)
    except ValueError:
        pass
    return inspect.iscoroutinefunction(call)


async def resolve_extension_result(value: T | Awaitable[T]) -> T:
    """Await a callback result once and reject loop-bound foreign futures."""

    _reject_foreign_future(value)
    if inspect.isawaitable(value):
        result = await value
        _reject_foreign_future(result)
        return result
    return value


def _reject_foreign_future(value: Any) -> None:
    if isinstance(value, asyncio.Future) and value.get_loop() is not asyncio.get_running_loop():
        raise RuntimeError("extension returned an awaitable bound to a different event loop")


def _discard_unawaited_result(future: Any) -> None:
    """Close an abandoned coroutine produced by a cancelled sync callback."""

    if future.cancelled():
        return
    try:
        value = future.result()
    except BaseException:
        return
    _discard_unawaited_value(value)


def _consume_asyncio_future_result(future: asyncio.Future[Any]) -> None:
    """Observe a detached asyncio wrapper's terminal exception."""

    try:
        future.result()
    except BaseException:
        return


def _discard_unawaited_value(value: Any) -> None:
    if inspect.iscoroutine(value):
        value.close()


def _consume_task_result(task: asyncio.Task[Any]) -> None:
    try:
        task.result()
    except BaseException:
        pass
