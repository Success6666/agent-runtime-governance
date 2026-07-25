from __future__ import annotations

import asyncio

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
