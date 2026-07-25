from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from agent_runtime_governance.audit import InMemoryAuditSink
from agent_runtime_governance.context import ExecutionMode, ExecutionStatus
from agent_runtime_governance.errors import (
    AuditDeliveryError,
    ContractValidationError,
    GovernanceDenied,
    ToolExecutionError,
    get_cancellation_context,
)
from agent_runtime_governance.hooks import HookPoint
from agent_runtime_governance.middleware import AuditMiddleware, GatingMiddleware
from agent_runtime_governance.registry import SQLiteIdempotencyStore
from agent_runtime_governance.resilience import (
    CapacityExceededError,
    RuntimeLimits,
    await_stage,
)
from agent_runtime_governance.runtime import InvocationOptions, Runtime


@pytest.mark.asyncio
async def test_parameter_contract_fails_before_tool_execution() -> None:
    calls: list[int] = []
    runtime = Runtime()

    @runtime.tool(
        parameters_schema={
            "type": "object",
            "required": ["count"],
            "properties": {"count": {"type": "integer", "minimum": 1}},
            "additionalProperties": False,
        }
    )
    def create(count: int) -> int:
        calls.append(count)
        return count

    with pytest.raises(ToolExecutionError) as caught:
        await create.ainvoke(0)
    assert isinstance(caught.value.cause, ContractValidationError)
    assert caught.value.context.status is ExecutionStatus.FAILED
    assert calls == []


@pytest.mark.asyncio
async def test_invalid_mutating_result_is_reported_as_unknown() -> None:
    runtime = Runtime()

    @runtime.tool(result_schema={"type": "integer"})
    def mutate() -> str:
        return "committed-but-invalid-result"

    with pytest.raises(ToolExecutionError) as caught:
        await mutate.ainvoke()
    assert isinstance(caught.value.cause, ContractValidationError)
    assert caught.value.context.status is ExecutionStatus.UNKNOWN


@pytest.mark.asyncio
async def test_sqlite_idempotency_cache_is_reused_after_runtime_restart(tmp_path) -> None:
    path = tmp_path / "idempotency.db"
    executions: list[str] = []
    options = InvocationOptions(tenant="tenant-a", idempotency_key="operation-1")

    first = Runtime(idempotency_store=SQLiteIdempotencyStore(path))

    @first.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def write(value: int) -> dict[str, int]:
        executions.append("first")
        return {"value": value}

    assert await write.ainvoke(3, _governance=options) == {"value": 3}

    restarted = Runtime(idempotency_store=SQLiteIdempotencyStore(path))

    @restarted.tool(name="write", execution_mode=ExecutionMode.IDEMPOTENT)
    def restarted_write(value: int) -> dict[str, int]:
        executions.append("restarted")
        return {"value": value}

    assert await restarted_write.ainvoke(3, _governance=options) == {"value": 3}
    assert executions == ["first"]


@pytest.mark.asyncio
async def test_critical_audit_failure_prevents_execution() -> None:
    class FailingSink:
        def write(self, event) -> None:
            raise OSError("audit volume unavailable")

    runtime = Runtime([AuditMiddleware(FailingSink(), critical=True)])
    calls: list[str] = []

    @runtime.tool()
    def mutate() -> None:
        calls.append("executed")

    with pytest.raises(AuditDeliveryError) as caught:
        await mutate.ainvoke()
    assert caught.value.post_execution is False
    assert caught.value.context.denied
    assert calls == []


@pytest.mark.asyncio
async def test_post_execution_audit_failure_preserves_unknown_outcome() -> None:
    class FailSecondWrite:
        def __init__(self) -> None:
            self.writes = 0

        def write(self, event) -> None:
            self.writes += 1
            if self.writes == 2:
                raise OSError("audit volume became read-only")

    sink = FailSecondWrite()
    runtime = Runtime([AuditMiddleware(sink, critical=True)])
    side_effects: list[str] = []

    @runtime.tool()
    def mutate() -> str:
        side_effects.append("committed")
        return "ok"

    with pytest.raises(AuditDeliveryError) as caught:
        await mutate.ainvoke()
    assert caught.value.post_execution is True
    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    assert side_effects == ["committed"]


@pytest.mark.asyncio
async def test_deadline_budget_applies_to_gating_middleware() -> None:
    class SlowGate(GatingMiddleware):
        name = "slow"

        async def process(self, context):
            await asyncio.sleep(1)
            return context

    runtime = Runtime(
        [SlowGate()],
        limits=RuntimeLimits(middleware_timeout_seconds=0.01),
    )
    calls: list[str] = []

    @runtime.tool()
    def read() -> None:
        calls.append("executed")

    with pytest.raises(GovernanceDenied, match="failed closed"):
        await read.ainvoke()
    assert calls == []


@pytest.mark.asyncio
async def test_absolute_deadline_applies_to_hooks() -> None:
    runtime = Runtime(limits=RuntimeLimits(hook_timeout_seconds=1))
    calls: list[str] = []

    @runtime.hook(point=HookPoint.BEFORE_PIPELINE, critical=True)
    async def slow_hook(context):
        await asyncio.sleep(1)
        return context

    @runtime.tool()
    def read() -> None:
        calls.append("executed")

    options = InvocationOptions(
        deadline=datetime.now(timezone.utc) + timedelta(milliseconds=10)
    )
    with pytest.raises(GovernanceDenied, match="hook:before_pipeline"):
        await read.ainvoke(_governance=options)
    assert calls == []


@pytest.mark.asyncio
async def test_runtime_bulkhead_rejects_excess_concurrency() -> None:
    runtime = Runtime(
        limits=RuntimeLimits(
            max_in_flight=1,
            admission_timeout_seconds=0.01,
            execution_timeout_seconds=1,
        )
    )
    started = asyncio.Event()
    release = asyncio.Event()

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    async def hold() -> None:
        started.set()
        await release.wait()

    first = asyncio.create_task(hold.ainvoke())
    await started.wait()
    with pytest.raises(CapacityExceededError):
        await hold.ainvoke()
    release.set()
    await first


@pytest.mark.asyncio
async def test_cancellation_propagates_and_marks_context_unknown() -> None:
    runtime = Runtime()
    started = asyncio.Event()

    @runtime.tool()
    async def mutate() -> None:
        started.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(runtime.arun("mutate"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as caught:
        await task
    context = get_cancellation_context(caught.value)
    assert context is not None
    assert context.status is ExecutionStatus.UNKNOWN
    assert any(entry.outcome == "cancelled" for entry in context.history)


@pytest.mark.asyncio
async def test_stage_wrapper_preserves_dependency_timeout_error() -> None:
    async def dependency() -> None:
        raise TimeoutError("dependency supplied timeout")

    with pytest.raises(TimeoutError, match="dependency supplied timeout"):
        await await_stage(dependency(), stage="gate", timeout_seconds=1)


def test_contract_serialization_does_not_call_repr() -> None:
    class Hostile:
        def __repr__(self) -> str:
            raise AssertionError("repr must not run")

    sink = InMemoryAuditSink()
    runtime = Runtime([AuditMiddleware(sink)])

    @runtime.tool()
    def read(value) -> None:
        return None

    read(Hostile())
    assert sink.events
