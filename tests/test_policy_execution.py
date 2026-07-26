from __future__ import annotations

import asyncio

import pytest

from agent_runtime_governance import (
    ApprovalMiddleware,
    GovernanceDenied,
    HumanDecisionProvider,
    InMemoryMetrics,
    InvocationOptions,
    MetricsMiddleware,
    OpenTelemetryMiddleware,
    PolicyMiddleware,
    RetryMiddleware,
    RiskTier,
    Runtime,
    SimplePolicy,
    TimeoutMiddleware,
    ToolExecutionError,
)
from agent_runtime_governance.registry import ExecutionMode


def register(runtime: Runtime):
    @runtime.tool()
    def operate() -> str:
        return "ok"

    return operate


def test_policy_denies_named_tool() -> None:
    runtime = Runtime([PolicyMiddleware(SimplePolicy(denied_tools={"operate"}))])
    register(runtime)
    with pytest.raises(GovernanceDenied):
        runtime.invoke("operate")


def test_policy_identity_requires_complete_version_and_digest() -> None:
    with pytest.raises(ValueError, match="provided together"):
        PolicyMiddleware(SimplePolicy(), version="policy-v1")

    middleware = PolicyMiddleware(SimplePolicy())
    assert middleware.action_policy_identity() is None


def test_admin_only_policy_requires_permission() -> None:
    runtime = Runtime([PolicyMiddleware(SimplePolicy(admin_only={"operate"}))])
    register(runtime)
    with pytest.raises(GovernanceDenied):
        runtime.invoke("operate")
    assert runtime.invoke(
        "operate", _governance=InvocationOptions(permissions=frozenset({"admin"}))
    ) == "ok"


def test_policy_checks_required_permissions() -> None:
    policy = SimplePolicy(required_permissions={"operate": {"service:write"}})
    runtime = Runtime([PolicyMiddleware(policy)])
    register(runtime)
    with pytest.raises(GovernanceDenied, match="service:write"):
        runtime.invoke("operate")


def test_policy_can_require_human_decision() -> None:
    runtime = Runtime(
        [
            PolicyMiddleware(SimplePolicy(approval_tools={"operate"})),
            ApprovalMiddleware(HumanDecisionProvider(lambda context, request: True)),
        ]
    )
    assert register(runtime)() == "ok"


@pytest.mark.asyncio
async def test_policy_can_override_risk_tier() -> None:
    runtime = Runtime(
        [PolicyMiddleware(SimplePolicy(risk_overrides={"operate": RiskTier.CRITICAL}))]
    )
    register(runtime)
    result = await runtime.arun("operate")
    assert result.context.risk_tier is RiskTier.CRITICAL


@pytest.mark.asyncio
async def test_retry_recovers_transient_failure() -> None:
    attempts = 0
    runtime = Runtime([RetryMiddleware(max_attempts=3, retry_on=(ConnectionError,))])

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def flaky() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise ConnectionError("temporary")
        return "ok"

    result = await runtime.arun("flaky")
    assert result.value == "ok"
    assert attempts == 2
    assert any(item.outcome == "recovered" for item in result.context.history)


def test_retry_exhaustion_preserves_attempt_history() -> None:
    runtime = Runtime([RetryMiddleware(max_attempts=2, retry_on=(ConnectionError,))])

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def fail() -> None:
        raise ConnectionError("offline")

    with pytest.raises(ToolExecutionError) as caught:
        fail()
    retries = [item for item in caught.value.context.history if item.middleware == "retry"]
    assert len(retries) == 2
    assert retries[-1].outcome == "exhausted"


@pytest.mark.asyncio
async def test_timeout_interrupts_async_tool() -> None:
    runtime = Runtime([TimeoutMiddleware(0.01)])

    @runtime.tool()
    async def slow() -> None:
        await asyncio.sleep(0.05)

    with pytest.raises(ToolExecutionError, match="timeout"):
        await slow.ainvoke()


def test_invalid_execution_configuration_is_rejected() -> None:
    with pytest.raises(ValueError):
        RetryMiddleware(max_attempts=0)
    with pytest.raises(ValueError):
        TimeoutMiddleware(0)


@pytest.mark.asyncio
async def test_metrics_collect_terminal_status_and_duration() -> None:
    collector = InMemoryMetrics()
    runtime = Runtime([MetricsMiddleware(collector)])
    register(runtime)
    await runtime.arun("operate")
    snapshot = collector.snapshot()
    assert snapshot.counters["status.succeeded"] == 1
    assert snapshot.total_duration_ms >= 0


class FakeSpan:
    def __init__(self) -> None:
        self.attributes = {}
        self.ended = False

    def set_attribute(self, key, value) -> None:
        self.attributes[key] = value

    def end(self) -> None:
        self.ended = True


class FakeTracer:
    def __init__(self) -> None:
        self.spans: list[FakeSpan] = []

    def start_span(self, name, *, attributes):
        span = FakeSpan()
        span.attributes.update(attributes)
        self.spans.append(span)
        return span


def test_opentelemetry_middleware_exports_lifecycle() -> None:
    tracer = FakeTracer()
    runtime = Runtime([OpenTelemetryMiddleware(tracer)])
    register(runtime)()
    assert len(tracer.spans) == 1
    assert tracer.spans[0].attributes["arg.status"] == "succeeded"
    assert tracer.spans[0].ended
