from __future__ import annotations

import asyncio
import gc
import inspect
import threading
import warnings

import pytest

from agent_runtime_governance import (
    CircuitState,
    GovernanceDenied,
    InvocationOptions,
    OPAClient,
    OPAMiddleware,
    Rule,
    RuleMiddleware,
    Runtime,
    RuntimeLimits,
    SlackNotificationMiddleware,
    SlackWebhookNotifier,
)
from agent_runtime_governance.context import ExecutionContext, ToolCall


def _context() -> ExecutionContext:
    return ExecutionContext.create(ToolCall("work"))


@pytest.mark.asyncio
async def test_sync_public_transport_methods_return_native_awaitables_once() -> None:
    calls: list[str] = []

    async def opa_transport(payload: dict[str, object]) -> dict[str, object]:
        calls.append("opa")
        return {"result": True}

    async def slack_transport(payload: dict[str, object]) -> None:
        calls.append("slack")

    client = OPAClient(
        "http://localhost:8181", "agent/allow", transport=opa_transport
    )
    decision = client.evaluate(_context())
    assert inspect.isawaitable(decision)
    assert (await decision).allow

    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C", transport=slack_transport
    )
    sent = notifier.send({"text": "done"})
    assert inspect.isawaitable(sent)
    await sent
    assert calls == ["opa", "slack"]


@pytest.mark.asyncio
async def test_sync_wrapped_transports_preserve_public_awaitables() -> None:
    calls: list[str] = []

    async def complete_opa() -> dict[str, object]:
        calls.append("opa")
        return {"result": True}

    def opa_transport(_payload: dict[str, object]):
        return complete_opa()

    client = OPAClient(
        "http://localhost:8181", "agent/allow", transport=opa_transport
    )
    decision = client.evaluate(_context())
    assert inspect.isawaitable(decision)
    assert (await decision).allow

    async def complete_slack() -> None:
        calls.append("slack")

    def slack_transport(_payload: dict[str, object]):
        return complete_slack()

    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C", transport=slack_transport
    )
    sent = notifier.send({"text": "done"})
    assert inspect.isawaitable(sent)
    await sent
    assert calls == ["opa", "slack"]


@pytest.mark.asyncio
async def test_slack_async_entry_point_accepts_a_sync_transport() -> None:
    caller_thread = threading.current_thread().name
    threads: list[str] = []

    def transport(_payload: dict[str, object]) -> None:
        threads.append(threading.current_thread().name)

    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C", transport=transport
    )

    await notifier.asend({"text": "done"})

    assert threads and threads[0] != caller_thread


@pytest.mark.asyncio
async def test_default_opa_and_slack_transports_use_encoded_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opa_requests: list[bytes] = []
    client = OPAClient("http://localhost:8181", "agent/allow")

    def post_opa(encoded: bytes) -> dict[str, object]:
        opa_requests.append(encoded)
        return {"result": True}

    monkeypatch.setattr(client, "_post", post_opa)
    assert (await client.aevaluate(_context())).allow
    assert opa_requests

    slack_requests: list[bytes] = []
    notifier = SlackWebhookNotifier("https://hooks.slack.com/services/T/B/C")

    def post_slack(encoded: bytes) -> None:
        slack_requests.append(encoded)

    monkeypatch.setattr(notifier, "_post", post_slack)
    await notifier.asend({"text": "async"})
    assert notifier.send({"text": "sync"}) is None
    assert len(slack_requests) == 2


def test_opa_rejects_a_non_mapping_response() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        OPAClient._parse_response([])  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "denied"),
    [
        ({"result": True}, False),
        ({"result": {"allow": False, "reason": "maintenance"}}, True),
    ],
)
async def test_runtime_opa_native_async_transport_stays_on_calling_loop(
    response: dict[str, object], denied: bool
) -> None:
    caller_thread = threading.get_ident()
    caller_loop = id(asyncio.get_running_loop())
    observed: list[tuple[int, int]] = []

    async def transport(payload: dict[str, object]) -> dict[str, object]:
        observed.append((threading.get_ident(), id(asyncio.get_running_loop())))
        return response

    runtime = Runtime(
        [
            OPAMiddleware(
                OPAClient(
                    "http://localhost:8181",
                    "agent/allow",
                    transport=transport,
                )
            )
        ]
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        if denied:
            with pytest.raises(GovernanceDenied, match="maintenance"):
                await runtime.ainvoke("work")
        else:
            assert await runtime.ainvoke("work") == "ok"
        assert observed == [(caller_thread, caller_loop)]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_opa_sync_transport_uses_controlled_worker() -> None:
    observed: list[str] = []

    def transport(payload: dict[str, object]) -> dict[str, object]:
        observed.append(threading.current_thread().name)
        return {"result": True}

    runtime = Runtime(
        [
            OPAMiddleware(
                OPAClient(
                    "http://localhost:8181",
                    "agent/allow",
                    transport=transport,
                )
            )
        ]
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        assert await runtime.ainvoke("work") == "ok"
        assert observed and observed[0].startswith("arg-extension")
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_opa_async_transport_records_failure_only_after_completion() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def transport(payload: dict[str, object]) -> dict[str, object]:
        entered.set()
        await release.wait()
        raise ConnectionError("OPA unavailable")

    client = OPAClient(
        "http://localhost:8181",
        "agent/allow",
        transport=transport,
        failure_threshold=1,
    )
    task = asyncio.create_task(client.aevaluate(_context()))
    await asyncio.wait_for(entered.wait(), timeout=1)
    assert client._circuit_breaker.state is CircuitState.CLOSED

    release.set()
    with pytest.raises(ConnectionError, match="OPA unavailable"):
        await task
    assert client._circuit_breaker.state is CircuitState.OPEN


@pytest.mark.asyncio
async def test_opa_async_transport_rejects_malformed_response() -> None:
    async def transport(payload: dict[str, object]) -> dict[str, object]:
        return {"result": {"allow": "not-a-boolean"}}

    client = OPAClient(
        "http://localhost:8181", "agent/allow", transport=transport
    )
    with pytest.raises(ValueError, match="result.allow"):
        await client.aevaluate(_context())


@pytest.mark.asyncio
async def test_runtime_opa_timeout_cancels_native_transport_without_warning() -> None:
    cancelled = asyncio.Event()

    async def transport(payload: dict[str, object]) -> dict[str, object]:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    client = OPAClient(
        "http://localhost:8181",
        "agent/allow",
        transport=transport,
        failure_threshold=1,
    )
    runtime = Runtime(
        [
            OPAMiddleware(client)
        ],
        limits=RuntimeLimits(
            middleware_timeout_seconds=0.01,
            cancellation_grace_seconds=0.01,
        ),
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", RuntimeWarning)
        try:
            with pytest.raises(GovernanceDenied, match="failed closed"):
                await runtime.ainvoke("work")
            await asyncio.wait_for(cancelled.wait(), timeout=1)
            assert client._circuit_breaker.state is CircuitState.CLOSED
            await asyncio.sleep(0)
            gc.collect()
        finally:
            await runtime.aclose()
    assert not any("was never awaited" in str(item.message) for item in captured)


@pytest.mark.asyncio
async def test_runtime_slack_native_async_transport_stays_on_calling_loop() -> None:
    caller_thread = threading.get_ident()
    caller_loop = id(asyncio.get_running_loop())
    observed: list[tuple[int, int]] = []

    async def transport(payload: dict[str, object]) -> None:
        observed.append((threading.get_ident(), id(asyncio.get_running_loop())))

    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C", transport=transport
    )
    runtime = Runtime(
        [
            RuleMiddleware([Rule("deny", r"\bdeny\b", "blocked")]),
            SlackNotificationMiddleware(notifier.send),
        ]
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        with pytest.raises(GovernanceDenied):
            await runtime.ainvoke(
                "work", _governance=InvocationOptions(input_text="deny")
            )
        assert observed == [(caller_thread, caller_loop)]
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_runtime_slack_sync_transport_uses_controlled_worker() -> None:
    observed: list[str] = []

    def transport(payload: dict[str, object]) -> None:
        observed.append(threading.current_thread().name)

    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C", transport=transport
    )
    runtime = Runtime(
        [
            RuleMiddleware([Rule("deny", r"\bdeny\b", "blocked")]),
            SlackNotificationMiddleware(notifier.send),
        ]
    )

    @runtime.tool()
    def work() -> str:
        return "ok"

    try:
        with pytest.raises(GovernanceDenied):
            await runtime.ainvoke(
                "work", _governance=InvocationOptions(input_text="deny")
            )
        assert observed and observed[0].startswith("arg-extension")
    finally:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_slack_async_transport_records_error_and_handles_cancellation() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    cancelled = asyncio.Event()
    attempts = 0

    async def transport(payload: dict[str, object]) -> None:
        nonlocal attempts
        attempts += 1
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        raise OSError("webhook unavailable")

    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C",
        transport=transport,
        failure_threshold=1,
    )
    failed = asyncio.create_task(notifier.asend({"text": "failed"}))
    await asyncio.wait_for(entered.wait(), timeout=1)
    assert notifier._circuit_breaker.state is CircuitState.CLOSED
    release.set()
    with pytest.raises(OSError, match="webhook unavailable"):
        await failed
    assert notifier._circuit_breaker.state is CircuitState.OPEN

    with pytest.raises(RuntimeError, match="circuit breaker"):
        await notifier.asend({"text": "blocked"})
    assert attempts == 1

    entered.clear()
    release.clear()
    pending = asyncio.create_task(SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C", transport=transport
    ).asend({"text": "cancelled"}))
    await asyncio.wait_for(entered.wait(), timeout=1)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert cancelled.is_set()
