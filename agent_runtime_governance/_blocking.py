"""Runtime-scoped execution for synchronous third-party extensions.

``asyncio.to_thread`` deliberately does not own or await its worker after the
awaiting task is cancelled.  That is useful for best-effort application code,
but unsafe for a governed runtime: a timed-out hook, policy client, or audit
sink can otherwise continue performing effects after ``Runtime.aclose()`` has
reported success.  The runtime installs an owned runner for public operations;
standalone middleware retains the normal ``asyncio.to_thread`` fallback.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Awaitable, Callable, Iterator, TypeVar, cast

T = TypeVar("T")
BlockingRunner = Callable[..., Awaitable[Any]]
ExtensionRunner = BlockingRunner
ExtensionCleanupScheduler = Callable[[Awaitable[Any]], asyncio.Task[Any] | None]

_BLOCKING_RUNNER: ContextVar[BlockingRunner | None] = ContextVar(
    "agent_runtime_governance_blocking_runner",
    default=None,
)
_EXTENSION_RUNNER: ContextVar[ExtensionRunner | None] = ContextVar(
    "agent_runtime_governance_extension_runner",
    default=None,
)
_EXTENSION_CLEANUP_SCHEDULER: ContextVar[ExtensionCleanupScheduler | None] = ContextVar(
    "agent_runtime_governance_extension_cleanup_scheduler",
    default=None,
)
_EXTENSION_CLEANUP_TASK: ContextVar[asyncio.Task[Any] | None] = ContextVar(
    "agent_runtime_governance_extension_cleanup_task",
    default=None,
)
_EXTENSION_LIFECYCLE_TASK: ContextVar[asyncio.Task[Any] | None] = ContextVar(
    "agent_runtime_governance_extension_lifecycle_task",
    default=None,
)
_MANAGED_BLOCKING_WORKER: ContextVar[bool] = ContextVar(
    "agent_runtime_governance_managed_blocking_worker",
    default=False,
)
_STANDALONE_CLEANUP_TASKS: set[asyncio.Task[Any]] = set()


async def run_blocking(
    callback: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run a known-synchronous callback through the active Runtime when present."""

    runner = _BLOCKING_RUNNER.get()
    if runner is not None:
        return cast(T, await runner(callback, *args, **kwargs))
    if _MANAGED_BLOCKING_WORKER.get():
        raise RuntimeError("a synchronous extension cannot submit nested blocking work")
    return await asyncio.to_thread(callback, *args, **kwargs)


async def invoke_extension(
    callback: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Use the Runtime async-first dispatcher when an operation is active."""

    runner = _EXTENSION_RUNNER.get()
    if runner is not None:
        return cast(T, await runner(callback, *args, **kwargs))
    if _MANAGED_BLOCKING_WORKER.get():
        raise RuntimeError("a synchronous extension cannot submit nested blocking work")
    # Delayed import avoids a module cycle: the dispatcher uses the context
    # manager below for Runtime-owned synchronous workers.
    from ._extensions import invoke_standalone_extension

    return await invoke_standalone_extension(callback, *args, **kwargs)


def install_extension_runner(
    runner: ExtensionRunner,
) -> Token[ExtensionRunner | None]:
    """Bind a Runtime async-first extension runner to the current operation."""

    return _EXTENSION_RUNNER.set(runner)


def reset_extension_runner(token: Token[ExtensionRunner | None]) -> None:
    """Restore the extension-runner binding for the current operation."""

    _EXTENSION_RUNNER.reset(token)


def install_extension_cleanup_scheduler(
    scheduler: ExtensionCleanupScheduler,
) -> Token[ExtensionCleanupScheduler | None]:
    """Bind runtime-owned cleanup tracking to the current operation."""

    return _EXTENSION_CLEANUP_SCHEDULER.set(scheduler)


def reset_extension_cleanup_scheduler(
    token: Token[ExtensionCleanupScheduler | None],
) -> None:
    """Restore the cleanup scheduler binding for the current operation."""

    _EXTENSION_CLEANUP_SCHEDULER.reset(token)


def schedule_extension_cleanup(awaitable: Awaitable[Any]) -> asyncio.Task[Any] | None:
    """Create a terminal extension cleanup task owned by the active Runtime."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        _discard_unstarted_awaitable(awaitable)
        raise RuntimeError("extension cleanup must be scheduled from an event loop")
    scheduler = _EXTENSION_CLEANUP_SCHEDULER.get()
    if scheduler is not None:
        return scheduler(awaitable)
    task = asyncio.create_task(awaitable, name="extension-cleanup")
    _STANDALONE_CLEANUP_TASKS.add(task)
    task.add_done_callback(_STANDALONE_CLEANUP_TASKS.discard)
    task.add_done_callback(_consume_cleanup_result)
    return task


@contextmanager
def extension_cleanup_scope() -> Iterator[None]:
    """Allow an admitted terminal cleanup to finish while Runtime is closing."""

    current = asyncio.current_task()
    if current is None:
        raise RuntimeError("extension cleanup must run in an asyncio task")
    token = _EXTENSION_CLEANUP_TASK.set(current)
    try:
        yield
    finally:
        _EXTENSION_CLEANUP_TASK.reset(token)


def is_extension_cleanup_active() -> bool:
    """Return whether the current task is finalizing admitted extension work."""

    try:
        current = asyncio.current_task()
    except RuntimeError:
        return False
    return current is not None and _EXTENSION_CLEANUP_TASK.get() is current


def has_extension_cleanup_context() -> bool:
    """Return whether this context descended from an admitted cleanup task."""

    return _EXTENSION_CLEANUP_TASK.get() is not None


@contextmanager
def extension_lifecycle_scope() -> Iterator[None]:
    """Mark one explicitly owned extension lifecycle task as shutdown-safe."""

    current = asyncio.current_task()
    if current is None:
        raise RuntimeError("extension lifecycle work must run in an asyncio task")
    token = _EXTENSION_LIFECYCLE_TASK.set(current)
    try:
        yield
    finally:
        _EXTENSION_LIFECYCLE_TASK.reset(token)


def is_extension_lifecycle_active() -> bool:
    """Return whether the current task has an explicit extension owner."""

    try:
        current = asyncio.current_task()
    except RuntimeError:
        return False
    return current is not None and _EXTENSION_LIFECYCLE_TASK.get() is current


def _consume_cleanup_result(task: asyncio.Task[Any]) -> None:
    try:
        task.result()
    except BaseException:
        pass


def _discard_unstarted_awaitable(awaitable: Awaitable[Any]) -> None:
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()


def install_blocking_runner(runner: BlockingRunner) -> Token[BlockingRunner | None]:
    """Bind a runtime-owned synchronous runner to the current async context."""

    return _BLOCKING_RUNNER.set(runner)


def reset_blocking_runner(token: Token[BlockingRunner | None]) -> None:
    """Restore the runner binding installed by :func:`install_blocking_runner`."""

    _BLOCKING_RUNNER.reset(token)


@contextmanager
def suspend_blocking_runner() -> Iterator[None]:
    """Prevent a callback running in a worker from recursively consuming it."""

    runner_token = _BLOCKING_RUNNER.set(None)
    extension_runner_token = _EXTENSION_RUNNER.set(None)
    cleanup_scheduler_token = _EXTENSION_CLEANUP_SCHEDULER.set(None)
    worker_token = _MANAGED_BLOCKING_WORKER.set(True)
    try:
        yield
    finally:
        _MANAGED_BLOCKING_WORKER.reset(worker_token)
        _EXTENSION_CLEANUP_SCHEDULER.reset(cleanup_scheduler_token)
        _EXTENSION_RUNNER.reset(extension_runner_token)
        _BLOCKING_RUNNER.reset(runner_token)
