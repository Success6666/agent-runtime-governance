from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from agent_runtime_governance import (
    InMemoryIdempotencyStore,
    InvocationOptions,
    RetryMiddleware,
    Runtime,
    RuntimeLimits,
    SQLiteIdempotencyStore,
)
from agent_runtime_governance.context import (
    ExecutionContext,
    ExecutionMode,
    ExecutionStatus,
    ToolCall,
)
from agent_runtime_governance.errors import (
    GovernanceDenied,
    ToolExecutionError,
    get_cancellation_context,
)
from agent_runtime_governance.hooks import HookPoint
from agent_runtime_governance.resilience import StageTimeoutError, await_stage


class SlowAcquireStore(InMemoryIdempotencyStore):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.marked_unknown = threading.Event()

    def acquire(self, namespace: str, key: str, fingerprint: str):
        self.entered.set()
        time.sleep(0.2)
        return super().acquire(namespace, key, fingerprint)

    def mark_unknown(self, claim, error: BaseException) -> None:
        super().mark_unknown(claim, error)
        self.marked_unknown.set()


class FailingCompletionStore(InMemoryIdempotencyStore):
    def complete(self, claim, result) -> None:
        raise OSError("idempotency database unavailable")


class FailingRenewalStore(InMemoryIdempotencyStore):
    def acquire(self, namespace: str, key: str, fingerprint: str):
        claim = super().acquire(namespace, key, fingerprint)
        if claim.owner:
            return type(claim)(
                claim.namespace,
                claim.key,
                claim.fingerprint,
                claim.owner,
                claim.future,
                "renewal-owner",
                0.03,
            )
        return claim

    def renew(self, claim) -> None:
        raise OSError("idempotency lease renewal unavailable")


def test_default_mutating_tool_is_not_retried() -> None:
    attempts = 0
    runtime = Runtime([RetryMiddleware(max_attempts=3, retry_on=(ConnectionError,))])

    @runtime.tool()
    def write() -> None:
        nonlocal attempts
        attempts += 1
        raise ConnectionError("uncertain write")

    with pytest.raises(ToolExecutionError) as caught:
        write()

    assert attempts == 1
    assert caught.value.context.tool_call.name == "write"
    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    assert any(entry.outcome == "skipped" for entry in caught.value.context.history)


@pytest.mark.asyncio
async def test_read_only_tool_can_be_retried_without_idempotency_key() -> None:
    attempts = 0
    runtime = Runtime([RetryMiddleware(max_attempts=2, retry_on=(ConnectionError,))])

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def read() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionError("temporary")
        return "ok"

    assert await read.ainvoke() == "ok"
    assert attempts == 2


def test_idempotent_tool_without_key_is_denied_before_execution() -> None:
    attempts = 0
    runtime = Runtime([RetryMiddleware(max_attempts=2, retry_on=(ConnectionError,))])

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def write() -> None:
        nonlocal attempts
        attempts += 1
        raise ConnectionError("temporary")

    with pytest.raises(GovernanceDenied, match="idempotency key"):
        write()
    assert attempts == 0


@pytest.mark.asyncio
async def test_idempotent_tool_with_key_can_retry_and_caches_success() -> None:
    attempts = 0
    runtime = Runtime([RetryMiddleware(max_attempts=2, retry_on=(ConnectionError,))])

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def write(value: int) -> int:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionError("temporary")
        return value * 2

    options = InvocationOptions(idempotency_key="write-1")
    assert await write.ainvoke(3, _governance=options) == 6
    assert await write.ainvoke(3, _governance=options) == 6
    assert attempts == 2


@pytest.mark.asyncio
async def test_concurrent_idempotent_calls_execute_once() -> None:
    executions = 0
    started = asyncio.Event()
    release = asyncio.Event()
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def write(value: int) -> int:
        nonlocal executions
        executions += 1
        started.set()
        await release.wait()
        return value

    options = InvocationOptions(idempotency_key="same-request")
    first = asyncio.create_task(write.ainvoke(7, _governance=options))
    await started.wait()
    second = asyncio.create_task(write.ainvoke(7, _governance=options))
    await asyncio.sleep(0)
    release.set()

    assert await asyncio.gather(first, second) == [7, 7]
    assert executions == 1


@pytest.mark.asyncio
async def test_cancellation_does_not_wait_for_idempotency_storage_io() -> None:
    store = SlowAcquireStore()
    runtime = Runtime(idempotency_store=store)
    executions = 0

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def write() -> None:
        nonlocal executions
        executions += 1

    task = asyncio.create_task(
        runtime.arun(
            "write",
            _governance=InvocationOptions(idempotency_key="cancel-acquire"),
        )
    )
    assert await asyncio.to_thread(store.entered.wait, 1)
    started = time.perf_counter()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.perf_counter() - started < 0.1
    assert await asyncio.to_thread(store.marked_unknown.wait, 1)
    assert executions == 0


@pytest.mark.asyncio
async def test_idempotency_acquire_honors_absolute_deadline() -> None:
    store = SlowAcquireStore()
    runtime = Runtime(idempotency_store=store)
    executions = 0

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def write() -> None:
        nonlocal executions
        executions += 1

    deadline = datetime.now(timezone.utc) + timedelta(milliseconds=20)
    started = time.perf_counter()
    with pytest.raises(ToolExecutionError) as caught:
        await write.ainvoke(
            _governance=InvocationOptions(
                idempotency_key="deadline-acquire",
                deadline=deadline,
            )
        )
    assert time.perf_counter() - started < 0.15
    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    assert await asyncio.to_thread(store.marked_unknown.wait, 1)
    assert executions == 0


@pytest.mark.asyncio
async def test_idempotency_key_is_bound_to_parameter_fingerprint() -> None:
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def write(value: int) -> int:
        return value

    options = InvocationOptions(idempotency_key="request-1")
    assert await write.ainvoke(1, _governance=options) == 1
    with pytest.raises(GovernanceDenied, match="different parameters"):
        await write.ainvoke(2, _governance=options)


def test_deadline_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        InvocationOptions(deadline=datetime.now())


@pytest.mark.asyncio
async def test_sync_timeout_uses_unknown_terminal_state() -> None:
    side_effects: list[str] = []
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.MUTATING)
    def slow_write() -> None:
        time.sleep(0.05)
        side_effects.append("committed")

    options = InvocationOptions(
        deadline=datetime.now(timezone.utc) + timedelta(milliseconds=10)
    )
    with pytest.raises(ToolExecutionError) as caught:
        await slow_write.ainvoke(_governance=options)

    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    await asyncio.sleep(0.06)
    assert side_effects == ["committed"]


def test_tool_spec_exposes_contract_and_size_fields() -> None:
    runtime = Runtime()
    schema = {"type": "object"}

    @runtime.tool(
        execution_mode=ExecutionMode.READ_ONLY,
        parameters_schema=schema,
        result_schema={"type": "integer"},
        max_parameters_bytes=64,
        max_result_bytes=8,
    )
    def echo(value: int) -> int:
        return value

    spec = runtime.registry.get("echo")
    assert spec.execution_mode is ExecutionMode.READ_ONLY
    assert spec.parameters_schema == schema
    assert spec.result_schema == {"type": "integer"}
    assert spec.max_parameters_bytes == 64
    assert spec.max_result_bytes == 8


def test_parameter_and_result_size_limits_are_enforced() -> None:
    runtime = Runtime()

    @runtime.tool(max_parameters_bytes=20)
    def limited_input(value: str) -> str:
        return value

    @runtime.tool(max_result_bytes=3)
    def limited_result() -> str:
        return "long"

    with pytest.raises(ToolExecutionError, match="parameters exceed"):
        limited_input("a" * 30)
    with pytest.raises(ToolExecutionError, match="result exceeds"):
        limited_result()


@pytest.mark.asyncio
async def test_sync_timeout_retains_capacity_until_thread_really_finishes() -> None:
    lock = threading.Lock()
    active = 0
    max_active = 0
    executions = 0
    runtime = Runtime(
        limits=RuntimeLimits(
            max_in_flight=1,
            admission_timeout_seconds=0.02,
            execution_timeout_seconds=0.02,
        )
    )

    @runtime.tool()
    def slow_write() -> str:
        nonlocal active, max_active, executions
        with lock:
            active += 1
            executions += 1
            max_active = max(max_active, active)
        try:
            time.sleep(0.12)
            return "ok"
        finally:
            with lock:
                active -= 1

    with pytest.raises(ToolExecutionError):
        await slow_write.ainvoke()
    with pytest.raises(ToolExecutionError):
        await slow_write.ainvoke()

    await asyncio.sleep(0.13)
    assert max_active == 1
    assert executions == 1
    runtime.close()


@pytest.mark.asyncio
async def test_idempotency_wait_honors_request_deadline() -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    runtime = Runtime(
        limits=RuntimeLimits(execution_timeout_seconds=1),
    )

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def write() -> str:
        started.set()
        await release.wait()
        return "ok"

    first = asyncio.create_task(
        write.ainvoke(
            _governance=InvocationOptions(idempotency_key="shared-operation")
        )
    )
    await started.wait()
    deadline = datetime.now(timezone.utc) + timedelta(milliseconds=20)
    before = time.perf_counter()
    with pytest.raises(ToolExecutionError) as caught:
        await write.ainvoke(
            _governance=InvocationOptions(
                idempotency_key="shared-operation",
                deadline=deadline,
            )
        )
    assert time.perf_counter() - before < 0.2
    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    release.set()
    assert await first == "ok"


@pytest.mark.asyncio
async def test_stage_timeout_does_not_wait_forever_for_cancel_suppression() -> None:
    async def suppress_once() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.04)

    before = time.perf_counter()
    with pytest.raises(StageTimeoutError):
        await await_stage(
            suppress_once(),
            stage="uncooperative",
            timeout_seconds=0.01,
            cancellation_grace_seconds=0.01,
        )
    assert time.perf_counter() - before < 0.1
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_after_execute_cancellation_preserves_unknown_context() -> None:
    hook_started = asyncio.Event()
    runtime = Runtime()

    @runtime.hook(HookPoint.AFTER_EXECUTE)
    async def wait_after_execute(context):
        hook_started.set()
        await asyncio.Event().wait()
        return context

    @runtime.tool()
    def commit() -> str:
        return "committed"

    task = asyncio.create_task(runtime.arun("commit"))
    await hook_started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as caught:
        await task
    context = get_cancellation_context(caught.value)
    assert context is not None
    assert context.status is ExecutionStatus.UNKNOWN
    assert any(item.outcome == "cancelled" for item in context.history)


@pytest.mark.asyncio
async def test_preview_runs_critical_pipeline_hooks_like_execution() -> None:
    runtime = Runtime()

    @runtime.hook(HookPoint.BEFORE_PIPELINE, critical=True)
    def reject(context):
        raise RuntimeError("maintenance window")

    @runtime.tool()
    def operate() -> None:
        raise AssertionError("preview must not execute tools")

    preview = await runtime.apreview("operate")
    assert preview.denied
    with pytest.raises(GovernanceDenied):
        await runtime.arun("operate")


@pytest.mark.asyncio
async def test_replay_uses_current_execution_mode() -> None:
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.MUTATING)
    def operate() -> None:
        return None

    recorded = ExecutionContext.create(
        ToolCall("operate"),
        execution_mode=ExecutionMode.READ_ONLY,
    )
    replayed = await runtime.areplay(recorded)
    assert replayed.execution_mode is ExecutionMode.MUTATING


@pytest.mark.asyncio
async def test_preview_and_replay_enforce_required_idempotency_key() -> None:
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def operate() -> None:
        raise AssertionError("governance-only paths must not execute tools")

    preview = await runtime.apreview("operate")
    assert preview.denied
    assert "idempotency key" in preview.decision.reason

    recorded = ExecutionContext.create(
        ToolCall("operate"),
        execution_mode=ExecutionMode.READ_ONLY,
    )
    replayed = await runtime.areplay(recorded)
    assert replayed.denied
    assert "idempotency key" in replayed.decision.reason


@pytest.mark.asyncio
async def test_idempotency_cache_returns_isolated_normalized_values() -> None:
    runtime = Runtime()
    executions = 0

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def read() -> tuple[dict[str, list[int]], ...]:
        nonlocal executions
        executions += 1
        return ({"items": [1]},)

    options = InvocationOptions(idempotency_key="read-1")
    first = await read.ainvoke(_governance=options)
    first[0]["items"].append(2)
    second = await read.ainvoke(_governance=options)
    assert second == [{"items": [1]}]
    assert executions == 1


@pytest.mark.asyncio
async def test_idempotency_uses_isolated_parameter_snapshot() -> None:
    runtime = Runtime()
    started = asyncio.Event()
    release = asyncio.Event()
    executions = 0

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def write(payload: list[int]) -> list[int]:
        nonlocal executions
        executions += 1
        started.set()
        await release.wait()
        return list(payload)

    payload = [1]
    options = InvocationOptions(idempotency_key="isolated-input")
    first = asyncio.create_task(write.ainvoke(payload, _governance=options))
    await started.wait()
    payload.append(2)
    release.set()

    assert await first == [1]
    assert await write.ainvoke([1], _governance=options) == [1]
    assert executions == 1


@pytest.mark.asyncio
async def test_uncooperative_async_tool_retains_execution_capacity() -> None:
    runtime = Runtime(
        limits=RuntimeLimits(
            max_in_flight=1,
            admission_timeout_seconds=0.02,
            execution_timeout_seconds=0.01,
            cancellation_grace_seconds=0.01,
        )
    )
    active = 0
    max_active = 0
    started = asyncio.Event()

    @runtime.tool()
    async def slow_write() -> None:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        started.set()
        deadline = time.perf_counter() + 0.12
        try:
            while time.perf_counter() < deadline:
                try:
                    await asyncio.sleep(0.01)
                except asyncio.CancelledError:
                    continue
        finally:
            active -= 1

    with pytest.raises(ToolExecutionError):
        await slow_write.ainvoke()
    await started.wait()
    with pytest.raises(ToolExecutionError):
        await slow_write.ainvoke()
    await asyncio.sleep(0.14)
    assert max_active == 1


def test_registered_schema_is_deeply_immutable() -> None:
    runtime = Runtime()
    schema = {
        "type": "object",
        "properties": {"value": {"type": "integer"}},
        "required": ["value"],
    }

    @runtime.tool(parameters_schema=schema)
    def accept(value: int) -> int:
        return value

    schema["properties"]["value"]["type"] = "string"
    assert accept(1) == 1
    with pytest.raises(TypeError):
        runtime.registry.get("accept").parameters_schema["properties"]["value"][
            "type"
        ] = "string"


@pytest.mark.asyncio
async def test_sqlite_idempotency_lease_is_renewed_during_long_execution(
    tmp_path,
) -> None:
    store = SQLiteIdempotencyStore(
        tmp_path / "leases.db",
        lease_seconds=0.06,
    )
    runtime = Runtime(idempotency_store=store)
    started = asyncio.Event()

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def write() -> str:
        started.set()
        await asyncio.sleep(0.16)
        return "ok"

    options = InvocationOptions(idempotency_key="long-operation")
    owner = asyncio.create_task(write.ainvoke(_governance=options))
    await started.wait()
    await asyncio.sleep(0.09)
    with pytest.raises(ToolExecutionError) as caught:
        await write.ainvoke(_governance=options)
    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    assert await owner == "ok"


@pytest.mark.asyncio
async def test_idempotency_completion_failure_reports_unknown() -> None:
    runtime = Runtime(idempotency_store=FailingCompletionStore())

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def write() -> str:
        return "committed"

    with pytest.raises(ToolExecutionError) as caught:
        await write.ainvoke(
            _governance=InvocationOptions(idempotency_key="completion-failure")
        )
    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    assert "database unavailable" in (caught.value.context.error or "")


@pytest.mark.asyncio
async def test_idempotency_renewal_failure_reports_unknown() -> None:
    runtime = Runtime(idempotency_store=FailingRenewalStore())

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def write() -> str:
        await asyncio.sleep(0.05)
        return "committed"

    with pytest.raises(ToolExecutionError) as caught:
        await write.ainvoke(
            _governance=InvocationOptions(idempotency_key="renewal-failure")
        )
    assert caught.value.context.status is ExecutionStatus.UNKNOWN
    assert "lease renewal failed" in (caught.value.context.error or "")
