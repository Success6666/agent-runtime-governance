from __future__ import annotations

import asyncio
import threading
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from time import monotonic
from typing import AsyncIterator, Awaitable, Callable, TypeVar

T = TypeVar("T")


class StageTimeoutError(TimeoutError):
    """A governance stage exceeded its configured deadline."""

    def __init__(self, stage: str, timeout_seconds: float) -> None:
        super().__init__(f"{stage} exceeded {timeout_seconds:.3f}s timeout")
        self.stage = stage
        self.timeout_seconds = timeout_seconds


class CapacityExceededError(RuntimeError):
    """The runtime could not accept work before the admission deadline."""


class CircuitOpenError(RuntimeError):
    """An external dependency is temporarily isolated after repeated failures."""


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Small synchronous circuit breaker for blocking integration clients."""

    def __init__(self, failure_threshold: int = 5, recovery_seconds: float = 30.0) -> None:
        if failure_threshold < 0:
            raise ValueError("failure_threshold cannot be negative")
        if recovery_seconds <= 0:
            raise ValueError("recovery_seconds must be greater than zero")
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._opened_at is None:
                return CircuitState.CLOSED
            if monotonic() - self._opened_at >= self.recovery_seconds:
                return CircuitState.HALF_OPEN
            return CircuitState.OPEN

    def call(self, function: Callable[..., T], *args: object, **kwargs: object) -> T:
        if self.failure_threshold == 0:
            return function(*args, **kwargs)
        self._before_call()
        try:
            result = function(*args, **kwargs)
        except Exception:
            self._record_failure()
            raise
        self._record_success()
        return result

    def _before_call(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if monotonic() - self._opened_at < self.recovery_seconds:
                raise CircuitOpenError("external dependency circuit breaker is open")
            if self._probe_in_flight:
                raise CircuitOpenError(
                    "external dependency circuit breaker recovery probe is in flight"
                )
            self._probe_in_flight = True

    def _record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False

    def _record_failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = monotonic()


@dataclass(frozen=True, slots=True)
class RuntimeLimits:
    """Bound latency and concurrency without changing governance policy."""

    middleware_timeout_seconds: float = 10.0
    observer_timeout_seconds: float = 5.0
    hook_timeout_seconds: float = 5.0
    execution_timeout_seconds: float = 30.0
    idempotency_operation_timeout_seconds: float = 30.0
    admission_timeout_seconds: float = 1.0
    cancellation_grace_seconds: float = 0.25
    max_in_flight: int = 128

    def __post_init__(self) -> None:
        for name in (
            "middleware_timeout_seconds",
            "observer_timeout_seconds",
            "hook_timeout_seconds",
            "execution_timeout_seconds",
            "idempotency_operation_timeout_seconds",
            "admission_timeout_seconds",
            "cancellation_grace_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.max_in_flight < 1:
            raise ValueError("max_in_flight must be at least one")


class RuntimeBulkhead:
    """A process-local admission limit safe across asyncio event loops."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least one")
        self._capacity = capacity
        self._available = capacity
        self._lock = threading.Lock()
        self._waiters: deque[_BulkheadWaiter] = deque()

    async def acquire(self, timeout_seconds: float) -> "BulkheadLease":
        if timeout_seconds <= 0:
            raise CapacityExceededError(
                f"runtime capacity was not available within {timeout_seconds:.3f}s"
            )
        loop = asyncio.get_running_loop()
        waiter = _BulkheadWaiter(loop=loop, future=loop.create_future())
        if self._acquire_or_enqueue(waiter):
            return BulkheadLease(self._release)
        try:
            await asyncio.wait_for(
                asyncio.shield(waiter.future),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            self._withdraw(waiter, state="timed_out")
            raise CapacityExceededError(
                f"runtime capacity was not available within {timeout_seconds:.3f}s"
            ) from exc
        except BaseException:
            self._withdraw(waiter, state="cancelled")
            raise
        return BulkheadLease(self._release)

    def _acquire_or_enqueue(self, waiter: "_BulkheadWaiter") -> bool:
        with self._lock:
            if self._available <= 0 or self._waiters:
                self._waiters.append(waiter)
                return False
            self._available -= 1
            waiter.state = "granted"
            return True

    def _withdraw(self, waiter: "_BulkheadWaiter", *, state: str) -> None:
        with self._lock:
            if waiter.state == "waiting":
                try:
                    self._waiters.remove(waiter)
                except ValueError:
                    pass
            elif waiter.state == "granted":
                self._available += 1
            else:
                return
            waiter.state = state
            if not waiter.future.done():
                waiter.future.cancel()
            self._grant_next_locked()

    def _release(self) -> None:
        with self._lock:
            if self._available >= self._capacity:
                raise RuntimeError("bulkhead permit released too many times")
            self._available += 1
            self._grant_next_locked()

    def _grant_next_locked(self) -> None:
        while self._available > 0 and self._waiters:
            waiter = self._waiters.popleft()
            if waiter.state != "waiting":
                continue
            waiter.state = "granted"
            self._available -= 1
            try:
                waiter.loop.call_soon_threadsafe(self._deliver, waiter)
            except RuntimeError:
                waiter.state = "cancelled"
                self._available += 1

    def _deliver(self, waiter: "_BulkheadWaiter") -> None:
        with self._lock:
            if waiter.state != "granted":
                return
            if waiter.future.done():
                waiter.state = "cancelled"
                self._available += 1
                self._grant_next_locked()
                return
            waiter.future.set_result(None)

    @asynccontextmanager
    async def slot(self, timeout_seconds: float) -> AsyncIterator[None]:
        lease = await self.acquire(timeout_seconds)
        try:
            yield
        finally:
            lease.release()


class BulkheadLease:
    """An idempotently releasable capacity reservation."""

    def __init__(self, release_callback: Callable[[], None]) -> None:
        self._release_callback = release_callback
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
            self._release_callback()


@dataclass(slots=True)
class _BulkheadWaiter:
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[None]
    state: str = "waiting"


async def await_stage(
    awaitable: Awaitable[T],
    *,
    stage: str,
    timeout_seconds: float,
    cancellation_grace_seconds: float = 0.25,
) -> T:
    if timeout_seconds <= 0:
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise StageTimeoutError(stage, max(0.0, timeout_seconds))
    task = asyncio.ensure_future(awaitable)
    cancellation_requested = False
    try:
        done, _ = await asyncio.wait({task}, timeout=timeout_seconds)
        if task in done:
            return task.result()
        cancellation_requested = True
        await _cancel_with_grace(task, cancellation_grace_seconds)
        raise StageTimeoutError(stage, timeout_seconds)
    except BaseException:
        if not task.done() and not cancellation_requested:
            await _cancel_with_grace(task, cancellation_grace_seconds)
        raise


async def _cancel_with_grace(
    task: asyncio.Future[object], grace_seconds: float
) -> None:
    task.cancel()
    done, _ = await asyncio.wait({task}, timeout=max(0.0, grace_seconds))
    if task in done:
        await asyncio.gather(task, return_exceptions=True)
        return
    task.add_done_callback(_consume_future_result)


def _consume_future_result(task: asyncio.Future[object]) -> None:
    try:
        task.result()
    except BaseException:
        pass
