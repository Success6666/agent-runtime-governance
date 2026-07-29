from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from agent_runtime_governance import (
    ActionContract,
    BoundAction,
    CapacityExceededError,
    ExecutionContext,
    ExecutionMode,
    ExecutionStatus,
    HistoryEntry,
    InvocationOptions,
    Rule,
    RuleMiddleware,
    Runtime,
    RuntimeEvent,
    RuntimeEventAction,
    RuntimeLimits,
    StageTimeoutError,
    ToolCall,
)
from agent_runtime_governance.decisions import DecisionOutcome, DecisionRecord
from agent_runtime_governance.errors import (
    GovernanceDenied,
    ToolExecutionError,
    get_cancellation_context,
)
from agent_runtime_governance.runtime_events import RUNTIME_EVENT_SCHEMA_V1


async def _wait_until(predicate: Any, *, timeout_seconds: float = 1.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while not predicate():
        if loop.time() >= deadline:
            raise AssertionError("condition did not become true before timeout")
        await asyncio.sleep(0.001)


def _bound_action() -> BoundAction:
    contract = ActionContract(
        contract_id="runtime.events.write",
        contract_version=1,
        tool_name="emit_event",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={
            "type": "object",
            "properties": {"payload": {"type": "string"}},
            "required": ["payload"],
            "additionalProperties": False,
        },
        effect_class="event.write",
        precondition_requirements=(),
        max_parameters_bytes=1024,
    )
    return contract.bind(
        {"payload": "parameters-canary"},
        identity_issuer="issuer-canary",
        principal="user-canary",
        tenant="tenant-canary",
        identity_digest_key=b"0123456789abcdef0123456789abcdef",
        identity_digest_key_version="2026-07",
        policy_version="policy-v1",
        policy_digest="a" * 64,
    )


def test_runtime_event_projection_is_versioned_immutable_and_redacted() -> None:
    action = _bound_action()
    context = ExecutionContext.create(
        ToolCall(
            "emit_event",
            args=("parameters-canary",),
            kwargs={"provider_receipt": "provider-receipt-canary"},
        ),
        user="user-canary",
        tenant="tenant-canary",
        input_text="input-canary",
        metadata={
            "approval_reason": "approval-reason-canary",
            "provider_receipt": "provider-receipt-canary",
        },
    ).bind_action(action)
    context = (
        context.with_decision(
            DecisionRecord(
                DecisionOutcome.DENY,
                "approval-reason-canary",
                "provider-canary",
            )
        )
        .evolve(
            result={"result": "result-canary"},
            error="provider-receipt-canary",
        )
        .append_history(
            HistoryEntry(
                "provider-canary",
                "receipt",
                "provider-receipt-canary",
                data={"provider_receipt": "provider-receipt-canary"},
            )
        )
    )

    event = RuntimeEvent.from_context(context)

    assert event.schema_version == RUNTIME_EVENT_SCHEMA_V1
    assert event.event_type == "terminal"
    assert event.action.action_digest == action.action_digest
    assert event.action.parameters_digest == action.parameters_digest
    assert event.action.tenant_digest == action.tenant_digest
    assert not hasattr(event, "context")
    assert not hasattr(event, "runtime")
    assert isinstance(event.action, RuntimeEventAction)
    with pytest.raises(FrozenInstanceError):
        event.status = ExecutionStatus.FAILED.value  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        event.action.action_digest = "b" * 64  # type: ignore[misc]

    payload = json.dumps(event.to_dict(), sort_keys=True)
    for canary in (
        "user-canary",
        "tenant-canary",
        "parameters-canary",
        "input-canary",
        "result-canary",
        "approval-reason-canary",
        "provider-receipt-canary",
    ):
        assert canary not in payload


def test_runtime_event_rejects_nonterminal_statuses() -> None:
    action = RuntimeEventAction.from_bound_action(None)
    with pytest.raises(ValueError, match="status must be terminal"):
        RuntimeEvent(
            schema_version=RUNTIME_EVENT_SCHEMA_V1,
            event_type="terminal",
            trace_digest="trace-digest",
            tool_name="emit_event",
            status=ExecutionStatus.PENDING.value,
            execution_mode=ExecutionMode.MUTATING.value,
            risk_tier="LOW",
            requires_approval=False,
            approval_granted=False,
            decision_outcome=None,
            cancelled=False,
            action=action,
        )
    with pytest.raises(ValueError, match="status must be terminal"):
        RuntimeEvent.from_context(ExecutionContext.create(ToolCall("emit_event")))


@pytest.mark.asyncio
async def test_runtime_event_stream_captures_all_terminal_outcomes() -> None:
    events: list[RuntimeEvent] = []

    async def capture(event: RuntimeEvent) -> None:
        events.append(event)

    success = Runtime(event_subscribers=(capture,))
    denied = Runtime(
        [RuleMiddleware([Rule("blocked", r"blocked", "blocked by policy")])],
        event_subscribers=(capture,),
    )
    failed = Runtime(event_subscribers=(capture,))
    cancelled = Runtime(event_subscribers=(capture,))
    started = asyncio.Event()

    @success.tool()
    def succeed() -> str:
        return "ok"

    @denied.tool()
    def reject() -> str:
        return "unreachable"

    @failed.tool(execution_mode=ExecutionMode.READ_ONLY)
    def fail() -> str:
        raise RuntimeError("failure-canary")

    @cancelled.tool()
    async def wait_forever() -> None:
        started.set()
        await asyncio.Event().wait()

    try:
        assert await success.ainvoke("succeed") == "ok"
        with pytest.raises(GovernanceDenied):
            await denied.arun(
                "reject",
                _governance=InvocationOptions(input_text="blocked"),
            )
        with pytest.raises(ToolExecutionError):
            await failed.arun("fail")

        invocation = asyncio.create_task(cancelled.ainvoke("wait_forever"))
        await asyncio.wait_for(started.wait(), timeout=1)
        invocation.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await invocation
        assert get_cancellation_context(caught.value) is not None

        await _wait_until(lambda: len(events) == 4)
        assert {event.status for event in events} == {
            ExecutionStatus.SUCCEEDED.value,
            ExecutionStatus.DENIED.value,
            ExecutionStatus.FAILED.value,
            ExecutionStatus.UNKNOWN.value,
        }
        assert sum(event.cancelled for event in events) == 1
        assert all(not hasattr(event, "context") for event in events)
    finally:
        await asyncio.gather(
            success.aclose(),
            denied.aclose(),
            failed.aclose(),
            cancelled.aclose(),
        )


@pytest.mark.asyncio
async def test_runtime_event_subscriber_failure_cannot_change_tool_result() -> None:
    observed: list[RuntimeEvent] = []

    async def broken(_event: RuntimeEvent) -> None:
        raise RuntimeError("debugger consumer failed")

    async def cancelled_consumer(_event: RuntimeEvent) -> None:
        raise asyncio.CancelledError("debugger consumer cancelled")

    def capture(event: RuntimeEvent) -> None:
        observed.append(event)

    runtime = Runtime(event_subscribers=(broken, cancelled_consumer, capture))
    denied = Runtime(
        [RuleMiddleware([Rule("blocked", r"blocked", "blocked by policy")])],
        event_subscribers=(broken,),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    @denied.tool()
    def reject() -> str:
        return "unreachable"

    try:
        assert await runtime.ainvoke("work") == "ok"
        await _wait_until(lambda: len(observed) == 1)
        assert observed[0].status == ExecutionStatus.SUCCEEDED.value
        with pytest.raises(GovernanceDenied) as caught:
            await denied.arun(
                "reject",
                _governance=InvocationOptions(input_text="blocked"),
            )
        assert caught.value.context.status is ExecutionStatus.DENIED
    finally:
        await asyncio.gather(runtime.aclose(), denied.aclose())


@pytest.mark.asyncio
async def test_runtime_event_subscribers_cannot_reenter_their_runtime() -> None:
    async_errors: list[str] = []
    preview_errors: list[str] = []
    sync_errors: list[str] = []
    observed: list[RuntimeEvent] = []
    calls: list[str] = []

    async def reenter_async(_event: RuntimeEvent) -> None:
        nested = asyncio.create_task(runtime.ainvoke("work"))
        try:
            await nested
        except RuntimeError as exc:
            async_errors.append(str(exc))
        else:
            async_errors.append("accepted")
        try:
            await runtime.apreview("work")
        except RuntimeError as exc:
            preview_errors.append(str(exc))
        else:
            preview_errors.append("accepted")

    def reenter_sync(_event: RuntimeEvent) -> None:
        try:
            runtime.invoke("work")
        except RuntimeError as exc:
            sync_errors.append(str(exc))
        else:
            sync_errors.append("accepted")

    runtime = Runtime(
        event_subscribers=(reenter_async, reenter_sync, observed.append)
    )

    @runtime.tool()
    def work() -> str:
        calls.append("work")
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        await _wait_until(
            lambda: (
                len(async_errors)
                == len(preview_errors)
                == len(sync_errors)
                == len(observed)
                == 1
            )
        )
        assert calls == ["work"]
        assert "runtime event subscriber" in async_errors[0]
        assert "runtime event subscriber" in preview_errors[0]
        assert "runtime event subscriber" in sync_errors[0]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_event_stream_captures_capacity_failure_once() -> None:
    events: list[RuntimeEvent] = []
    runtime = Runtime(
        limits=RuntimeLimits(max_in_flight=1, admission_timeout_seconds=0.05),
        event_subscribers=(events.append,),
    )
    started = asyncio.Event()
    release = asyncio.Event()
    first: asyncio.Task[Any] | None = None

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    async def hold() -> None:
        started.set()
        await release.wait()

    try:
        first = asyncio.create_task(runtime.ainvoke("hold"))
        await asyncio.wait_for(started.wait(), timeout=1)
        with pytest.raises(CapacityExceededError) as caught:
            await runtime.ainvoke("hold")
        assert caught.value.context.status is ExecutionStatus.FAILED
        await _wait_until(
            lambda: any(
                event.status == ExecutionStatus.FAILED.value for event in events
            )
        )
        release.set()
        await first
        await runtime.aclose()
        assert sum(
            event.status == ExecutionStatus.FAILED.value for event in events
        ) == 1
    finally:
        release.set()
        if first is not None:
            await asyncio.gather(first, return_exceptions=True)
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_event_stream_captures_admission_deadline_failure_once() -> None:
    events: list[RuntimeEvent] = []
    runtime = Runtime(event_subscribers=(events.append,))

    @runtime.tool()
    def work() -> str:
        return "unreachable"

    try:
        with pytest.raises(StageTimeoutError) as caught:
            await runtime.arun(
                "work",
                _governance=InvocationOptions(
                    deadline=datetime.now(timezone.utc) - timedelta(seconds=1)
                ),
            )
        assert caught.value.context.status is ExecutionStatus.FAILED
        await runtime.aclose()
        assert [event.status for event in events] == [ExecutionStatus.FAILED.value]
    finally:
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_unsubscribed_runtime_event_consumer_does_not_block_sync_close() -> None:
    observed: list[RuntimeEvent] = []
    runtime = Runtime()
    subscription = runtime.events.subscribe(observed.append)
    subscription.unsubscribe()

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        runtime.close()
        assert runtime._closed
        assert not observed
    finally:
        if not runtime._closed:
            await runtime.aclose()


@pytest.mark.asyncio
async def test_sync_runtime_event_subscriber_uses_owned_extension_dispatcher() -> None:
    entered = threading.Event()
    release = threading.Event()
    worker_names: list[str] = []
    runtime = Runtime(
        limits=RuntimeLimits(
            max_blocking_extension_workers=1,
            max_blocking_extension_in_flight=1,
        )
    )

    def block(_event: RuntimeEvent) -> None:
        worker_names.append(threading.current_thread().name)
        entered.set()
        assert release.wait(timeout=1)

    runtime.events.subscribe(block)

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.1)
        assert worker_names and worker_names[0].startswith("arg-extension")

        closing = asyncio.create_task(runtime.aclose())
        await asyncio.sleep(0.02)
        assert not closing.done()
        release.set()
        await closing
    finally:
        release.set()
        if not runtime._closed:
            await runtime.aclose()
