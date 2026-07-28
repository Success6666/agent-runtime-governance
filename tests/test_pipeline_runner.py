from __future__ import annotations

import inspect
from threading import Event

import pytest
from prometheus_client import CollectorRegistry

from agent_runtime_governance import Pipeline as PublicPipeline
from agent_runtime_governance._pipeline_runner import MiddlewareRegistry, PipelineRunner
from agent_runtime_governance.context import ExecutionContext, ToolCall
from agent_runtime_governance.decisions import DecisionOutcome, DecisionRecord
from agent_runtime_governance.middleware.base import (
    Middleware,
    MiddlewareKind,
    MiddlewareMetadata,
)
from agent_runtime_governance.middleware.llm import LLMMiddleware
from agent_runtime_governance.pipeline import Pipeline
from agent_runtime_governance.plugins.prometheus import PrometheusMiddleware
from agent_runtime_governance.runtime import Runtime
from agent_runtime_governance.telemetry import OpenTelemetryMiddleware


class NamedMiddleware(Middleware):
    kind = MiddlewareKind.OBSERVING

    def __init__(self, name: str, *, priority: int = 100) -> None:
        self.name = name
        self.priority = priority

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        return context


def test_pipeline_public_api_signature_snapshot_is_preserved() -> None:
    expected_signatures = {
        "__init__": ("self", "middlewares"),
        "__iter__": ("self",),
        "__len__": ("self",),
        "append": ("self", "middleware"),
        "remove": ("self", "name"),
        "insert_before": ("self", "target", "middleware"),
        "insert_after": ("self", "target", "middleware"),
        "replace": ("self", "target", "middleware"),
    }

    assert PublicPipeline is Pipeline
    assert tuple(Pipeline.__dataclass_fields__) == ("middlewares",)
    assert tuple(Pipeline.__dataclass_fields__["middlewares"].default) == ()
    assert {
        name: tuple(inspect.signature(getattr(Pipeline, name)).parameters)
        for name in expected_signatures
    } == expected_signatures
    assert tuple(inspect.signature(Runtime.pipeline.fset).parameters) == ("self", "value")


def test_pipeline_replacement_rebinds_current_extension_integrations() -> None:
    class Tracer:
        def start_span(self, name: str, *, attributes: dict[str, object]) -> object:
            raise AssertionError(f"unexpected span: {name} {attributes}")

    removed_metrics = PrometheusMiddleware(
        registry=CollectorRegistry(),
        prefix="pipeline_removed",
    )
    metrics = PrometheusMiddleware(
        registry=CollectorRegistry(),
        prefix="pipeline_rebind",
    )

    class TrackingOpenTelemetryMiddleware(OpenTelemetryMiddleware):
        def __init__(self) -> None:
            super().__init__(Tracer())
            self.shutdown_signals: list[Event] = []

        def _bind_extension_shutdown_signal(self, signal: Event) -> None:
            self.shutdown_signals.append(signal)
            super()._bind_extension_shutdown_signal(signal)

    telemetry = TrackingOpenTelemetryMiddleware()
    runtime = Runtime([removed_metrics])

    try:
        runtime.pipeline = [metrics, telemetry]
        runtime.pipeline = [metrics, telemetry]

        assert runtime._extension_dispatcher._observers == [metrics]
        assert metrics._extension_snapshot().worker_capacity == (
            runtime.extension_dispatch_snapshot.worker_capacity
        )
        assert telemetry.shutdown_signals == [
            runtime._extension_dispatcher.shutdown_signal
        ] * 2
    finally:
        runtime.close()


def test_runtime_accepts_unhashable_opentelemetry_subclasses() -> None:
    class Tracer:
        def start_span(self, name: str, *, attributes: dict[str, object]) -> object:
            raise AssertionError(f"unexpected span: {name} {attributes}")

    class EqualTelemetry(OpenTelemetryMiddleware):
        def __eq__(self, other: object) -> bool:
            return self is other

    telemetry = EqualTelemetry(Tracer())
    runtime = Runtime([telemetry])

    try:
        runtime.pipeline = [telemetry]
        assert (
            telemetry._extension_shutdown_signal
            is runtime._extension_dispatcher.shutdown_signal
        )
    finally:
        runtime.close()


def test_registry_preserves_public_pipeline_registration_order() -> None:
    high_priority = NamedMiddleware("first", priority=900)
    low_priority = NamedMiddleware("second", priority=10)

    registry = MiddlewareRegistry([high_priority, low_priority])

    assert registry.names == ("first", "second")
    assert tuple(registry) == (high_priority, low_priority)


def test_registry_exposes_deterministic_priority_order_without_reordering_pipeline() -> None:
    first = NamedMiddleware("first", priority=20)
    tied = NamedMiddleware("tied", priority=20)
    low = NamedMiddleware("low", priority=5)

    registry = MiddlewareRegistry([first, tied, low])

    assert registry.priority_ordered == (low, first, tied)
    assert Pipeline([first, tied, low]).names == ("first", "tied", "low")


def test_registry_rejects_duplicate_names_after_metadata_validation() -> None:
    with pytest.raises(ValueError, match="duplicate middleware names: duplicate"):
        MiddlewareRegistry([NamedMiddleware("duplicate"), NamedMiddleware("duplicate")])


def test_registry_rejects_non_middleware_entries() -> None:
    with pytest.raises(TypeError, match="pipeline entries"):
        MiddlewareRegistry([object()])  # type: ignore[list-item]


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("name", "", "name"),
        ("kind", "observing", "kind"),
        ("priority", True, "priority"),
        ("replayable", "yes", "replayable"),
    ],
)
def test_registry_rejects_invalid_public_middleware_state(
    attribute: str, value: object, message: str
) -> None:
    middleware = NamedMiddleware("valid")
    setattr(middleware, attribute, value)

    with pytest.raises((TypeError, ValueError), match=message):
        MiddlewareRegistry([middleware])


def test_registry_rejects_malformed_metadata() -> None:
    class InvalidMiddleware(NamedMiddleware):
        @property
        def metadata(self):  # type: ignore[override]
            return MiddlewareMetadata(
                name=self.name,
                kind=MiddlewareKind.OBSERVING,
                priority=True,
            )

    with pytest.raises(TypeError, match="priority"):
        MiddlewareRegistry([InvalidMiddleware("invalid")])


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        (object(), "MiddlewareMetadata"),
        (MiddlewareMetadata("", MiddlewareKind.OBSERVING), "name"),
        (
            MiddlewareMetadata("valid", "observing"),  # type: ignore[arg-type]
            "kind",
        ),
        (
            MiddlewareMetadata("valid", MiddlewareKind.OBSERVING, priority=True),
            "priority",
        ),
        (
            MiddlewareMetadata(
                "valid", MiddlewareKind.OBSERVING, replayable="yes"
            ),  # type: ignore[arg-type]
            "replayable",
        ),
        (
            MiddlewareMetadata("valid", MiddlewareKind.OBSERVING, version=""),
            "version",
        ),
    ],
)
def test_registry_rejects_invalid_metadata_values(
    metadata: object, message: str
) -> None:
    class InvalidMetadataMiddleware(NamedMiddleware):
        @property
        def metadata(self) -> MiddlewareMetadata:
            return metadata  # type: ignore[return-value]

    with pytest.raises((TypeError, ValueError), match=message):
        MiddlewareRegistry([InvalidMetadataMiddleware("valid")])


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        (
            MiddlewareMetadata("other", MiddlewareKind.OBSERVING),
            "name must match",
        ),
        (
            MiddlewareMetadata("consistent", MiddlewareKind.GATING),
            "kind must match",
        ),
        (
            MiddlewareMetadata("consistent", MiddlewareKind.OBSERVING, priority=1),
            "priority must match",
        ),
        (
            MiddlewareMetadata(
                "consistent", MiddlewareKind.OBSERVING, replayable=False
            ),
            "replayable must match",
        ),
    ],
)
def test_registry_rejects_metadata_that_disagrees_with_public_middleware_state(
    metadata: MiddlewareMetadata, message: str
) -> None:
    class InconsistentMetadataMiddleware(NamedMiddleware):
        @property
        def metadata(self) -> MiddlewareMetadata:
            return metadata

    with pytest.raises(ValueError, match=message):
        Pipeline([InconsistentMetadataMiddleware("consistent")])


@pytest.mark.asyncio
async def test_runner_uses_runtime_owned_callback_and_selection() -> None:
    selected = NamedMiddleware("selected")
    skipped = NamedMiddleware("skipped")
    runner = PipelineRunner([selected, skipped])
    context = ExecutionContext.create(ToolCall("work"))
    calls: list[str] = []

    async def invoke(middleware: Middleware, current: ExecutionContext) -> ExecutionContext:
        calls.append(middleware.name)
        return current.evolve(metadata={**current.metadata, middleware.name: True})

    result = await runner.run(
        context,
        invoke=invoke,
        include=lambda middleware, _context: middleware.name == "selected",
    )

    assert calls == ["selected"]
    assert result.metadata == {"selected": True}


@pytest.mark.asyncio
async def test_runner_accepts_a_prevalidated_registry_and_defaults_to_all_entries() -> None:
    first = NamedMiddleware("first")
    second = NamedMiddleware("second")
    registry = MiddlewareRegistry([first, second])
    runner = PipelineRunner(registry)
    context = ExecutionContext.create(ToolCall("work"))
    calls: list[str] = []

    async def invoke(
        middleware: Middleware, current: ExecutionContext
    ) -> ExecutionContext:
        calls.append(middleware.name)
        return current

    assert await runner.run(context, invoke=invoke) is context
    assert runner.registry is registry
    assert registry.of_kind(MiddlewareKind.OBSERVING) == (first, second)
    with pytest.raises(TypeError, match="MiddlewareKind"):
        registry.of_kind("observing")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_runtime_runner_tracks_replaced_pipeline_and_public_order() -> None:
    calls: list[str] = []

    class RecordingGate(NamedMiddleware):
        kind = MiddlewareKind.GATING

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            calls.append(self.name)
            return context

    runtime = Runtime([RecordingGate("discarded")])
    first = RecordingGate("first")
    second = RecordingGate("second")
    runtime.pipeline = [first, second]

    @runtime.tool()
    async def work() -> str:
        return "ok"

    assert await work.ainvoke() == "ok"
    assert calls == ["first", "second"]
    assert runtime.pipeline.names == ("first", "second")
    assert runtime._pipeline_runner.registry.middlewares == (first, second)


@pytest.mark.asyncio
async def test_runtime_runner_filters_replay_only() -> None:
    calls: list[str] = []

    class RecordingGate(NamedMiddleware):
        kind = MiddlewareKind.GATING

        def __init__(self, name: str, *, replayable: bool = True) -> None:
            super().__init__(name)
            self.replayable = replayable

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            calls.append(self.name)
            return context

    runtime = Runtime(
        [
            RecordingGate("replayable"),
            RecordingGate("non_replayable", replayable=False),
        ]
    )
    context = ExecutionContext.create(ToolCall("work"))

    result = await runtime._run_pre_pipeline(context, replayable_only=True)

    assert calls == ["replayable"]
    assert result is not context


@pytest.mark.asyncio
async def test_runtime_runner_skips_later_gates_after_denial() -> None:
    calls: list[str] = []

    class DenyingGate(NamedMiddleware):
        kind = MiddlewareKind.GATING

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            calls.append(self.name)
            return context.with_decision(
                DecisionRecord(DecisionOutcome.DENY, "blocked", self.name)
            )

    class RecordingGate(NamedMiddleware):
        kind = MiddlewareKind.GATING

        async def process(self, context: ExecutionContext) -> ExecutionContext:
            calls.append(self.name)
            return context

    runtime = Runtime([DenyingGate("deny"), RecordingGate("must_not_run")])

    result = await runtime._run_pre_pipeline(ExecutionContext.create(ToolCall("work")))

    assert result.denied
    assert calls == ["deny"]


@pytest.mark.asyncio
async def test_runtime_runner_stops_a_gate_denied_by_its_before_hook() -> None:
    reviewer_calls: list[ExecutionContext] = []
    runtime = Runtime([LLMMiddleware(lambda context: reviewer_calls.append(context))])

    @runtime.before_llm(critical=True)
    def deny_before_llm(_context: ExecutionContext) -> None:
        raise RuntimeError("required hook unavailable")

    result = await runtime._run_pre_pipeline(ExecutionContext.create(ToolCall("work")))

    assert result.denied
    assert reviewer_calls == []
