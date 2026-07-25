from __future__ import annotations

import sys
from types import ModuleType

import pytest

from agent_runtime_governance import (
    HookPoint,
    InMemoryAuditSink,
    Middleware,
    MiddlewareKind,
    PluginManager,
    RuntimeBuilder,
)


class MarkerMiddleware(Middleware):
    kind = MiddlewareKind.OBSERVING

    def __init__(self, name: str = "marker") -> None:
        self.name = name

    async def process(self, context):
        return context.evolve(metadata={**context.metadata, "marked": True})


class MarkerPlugin:
    name = "marker"
    version = "1.2.3"

    def register(self, builder: RuntimeBuilder) -> None:
        builder.add_middleware(MarkerMiddleware())
        builder.add_service("marker-service", object())


def test_plugin_registers_middleware_and_service() -> None:
    manager = PluginManager()
    record = manager.load(MarkerPlugin())
    runtime = manager.build()

    @runtime.tool()
    def work() -> bool:
        return True

    result = __import__("asyncio").run(runtime.arun("work"))
    assert record.name == "marker"
    assert result.context.metadata["marked"] is True
    assert "marker-service" in manager.builder.services


def test_duplicate_plugin_is_rejected() -> None:
    manager = PluginManager()
    manager.load(MarkerPlugin())
    with pytest.raises(ValueError, match="already loaded"):
        manager.load(MarkerPlugin())


def test_invalid_plugin_is_rejected() -> None:
    with pytest.raises(TypeError):
        PluginManager().load(object())  # type: ignore[arg-type]


def test_plugin_registration_rolls_back_on_duplicate_middleware() -> None:
    class BrokenPlugin:
        name = "broken"
        version = "1"

        def register(self, builder):
            builder.add_middleware(MarkerMiddleware("same"))
            builder.add_middleware(MarkerMiddleware("same"))

    manager = PluginManager()
    with pytest.raises(ValueError, match="duplicate"):
        manager.load(BrokenPlugin())
    assert manager.builder.build().pipeline.names == ()


def test_plugin_module_loading() -> None:
    module_name = "test_runtime_plugin_module"
    module = ModuleType(module_name)
    module.plugin = MarkerPlugin()
    sys.modules[module_name] = module
    try:
        record = PluginManager().load_module(module_name)
        assert record.source == f"module:{module_name}"
    finally:
        sys.modules.pop(module_name, None)


def test_plugin_entry_point_loading(monkeypatch) -> None:
    from agent_runtime_governance.plugins import core

    class Entry:
        name = "marker-entry"

        @staticmethod
        def load():
            return MarkerPlugin()

    class Entries(list):
        def select(self, *, group):
            assert group == "agent_runtime_governance.plugins"
            return self

    monkeypatch.setattr(core.metadata, "entry_points", lambda: Entries([Entry()]))
    loaded = PluginManager().load_entry_points()
    assert loaded[0].source == "entrypoint:marker-entry"


def test_builder_registers_hook() -> None:
    events: list[str] = []
    builder = RuntimeBuilder()
    builder.add_hook(
        HookPoint.BEFORE_EXECUTE,
        lambda context: events.append(context.tool_call.name),
    )
    runtime = builder.build()

    @runtime.tool()
    def work() -> bool:
        return True

    work()
    assert events == ["work"]


def test_builder_named_registrations_are_unique() -> None:
    builder = RuntimeBuilder()
    sink = InMemoryAuditSink()
    builder.add_audit_sink("json", sink)
    with pytest.raises(ValueError, match="already exists"):
        builder.add_audit_sink("json", sink)


def test_builder_registry_views_are_immutable() -> None:
    builder = RuntimeBuilder()
    builder.add_service("x", object())
    with pytest.raises(TypeError):
        builder.services["y"] = object()  # type: ignore[index]
