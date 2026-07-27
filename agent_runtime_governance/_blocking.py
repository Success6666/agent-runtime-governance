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

_BLOCKING_RUNNER: ContextVar[BlockingRunner | None] = ContextVar(
    "agent_runtime_governance_blocking_runner",
    default=None,
)
_MANAGED_BLOCKING_WORKER: ContextVar[bool] = ContextVar(
    "agent_runtime_governance_managed_blocking_worker",
    default=False,
)


async def run_blocking(
    callback: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run a synchronous callback through the active runtime when present."""

    runner = _BLOCKING_RUNNER.get()
    if runner is None:
        if _MANAGED_BLOCKING_WORKER.get():
            raise RuntimeError(
                "a synchronous extension cannot submit nested blocking work"
            )
        return await asyncio.to_thread(callback, *args, **kwargs)
    return cast(T, await runner(callback, *args, **kwargs))


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
    worker_token = _MANAGED_BLOCKING_WORKER.set(True)
    try:
        yield
    finally:
        _MANAGED_BLOCKING_WORKER.reset(worker_token)
        _BLOCKING_RUNNER.reset(runner_token)
