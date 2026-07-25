from __future__ import annotations

import asyncio
import threading

import pytest

from agent_runtime_governance.resilience import (
    CapacityExceededError,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    RuntimeBulkhead,
    RuntimeLimits,
    StageTimeoutError,
    await_stage,
)


def test_runtime_limits_reject_invalid_values() -> None:
    with pytest.raises(ValueError):
        RuntimeLimits(max_in_flight=0)
    with pytest.raises(ValueError):
        RuntimeLimits(hook_timeout_seconds=0)


@pytest.mark.asyncio
async def test_stage_timeout_is_structured() -> None:
    async def wait_forever() -> None:
        await asyncio.sleep(1)

    with pytest.raises(StageTimeoutError) as caught:
        await await_stage(wait_forever(), stage="llm", timeout_seconds=0.01)
    assert caught.value.stage == "llm"


@pytest.mark.asyncio
async def test_bulkhead_rejects_excess_work() -> None:
    bulkhead = RuntimeBulkhead(1)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def occupy() -> None:
        async with bulkhead.slot(0.2):
            entered.set()
            await release.wait()

    task = asyncio.create_task(occupy())
    await entered.wait()
    with pytest.raises(CapacityExceededError):
        async with bulkhead.slot(0.01):
            pass
    release.set()
    await task


@pytest.mark.asyncio
async def test_bulkhead_release_notifies_waiting_admission() -> None:
    bulkhead = RuntimeBulkhead(1)
    first = await bulkhead.acquire(0.2)
    waiting = asyncio.create_task(bulkhead.acquire(0.5))
    await asyncio.sleep(0)

    first.release()
    second = await asyncio.wait_for(waiting, timeout=0.2)
    second.release()


@pytest.mark.asyncio
async def test_cancelled_bulkhead_waiter_does_not_leak_permit() -> None:
    bulkhead = RuntimeBulkhead(1)
    first = await bulkhead.acquire(0.2)
    waiting = asyncio.create_task(bulkhead.acquire(1))
    await asyncio.sleep(0)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting

    first.release()
    replacement = await bulkhead.acquire(0.2)
    replacement.release()


@pytest.mark.asyncio
async def test_bulkhead_grants_contended_waiters_in_fifo_order() -> None:
    bulkhead = RuntimeBulkhead(1)
    first = await bulkhead.acquire(0.2)
    order: list[int] = []

    async def contend(index: int) -> None:
        lease = await bulkhead.acquire(1)
        order.append(index)
        await asyncio.sleep(0)
        lease.release()

    tasks = []
    for index in range(10):
        tasks.append(asyncio.create_task(contend(index)))
        await asyncio.sleep(0)
    first.release()
    await asyncio.gather(*tasks)
    assert order == list(range(10))


@pytest.mark.asyncio
async def test_bulkhead_hands_permit_between_event_loops() -> None:
    bulkhead = RuntimeBulkhead(1)
    first = await bulkhead.acquire(0.2)
    entered = threading.Event()
    finished = threading.Event()

    def run_other_loop() -> None:
        async def contend() -> None:
            entered.set()
            lease = await bulkhead.acquire(1)
            lease.release()
            finished.set()

        asyncio.run(contend())

    thread = threading.Thread(target=run_other_loop)
    thread.start()
    assert await asyncio.to_thread(entered.wait, 1)
    first.release()
    assert await asyncio.to_thread(finished.wait, 1)
    await asyncio.to_thread(thread.join, 1)
    assert not thread.is_alive()


def test_circuit_breaker_opens_and_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"value": 10.0}
    monkeypatch.setattr("agent_runtime_governance.resilience.monotonic", lambda: clock["value"])
    breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=5)

    def fail() -> None:
        raise ConnectionError("down")

    with pytest.raises(ConnectionError):
        breaker.call(fail)
    with pytest.raises(ConnectionError):
        breaker.call(fail)
    assert breaker.state is CircuitState.OPEN
    with pytest.raises(CircuitOpenError):
        breaker.call(lambda: "blocked")

    clock["value"] += 5
    assert breaker.state is CircuitState.HALF_OPEN
    assert breaker.call(lambda: "ok") == "ok"
    assert breaker.state is CircuitState.CLOSED
