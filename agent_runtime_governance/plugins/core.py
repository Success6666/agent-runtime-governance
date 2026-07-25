from __future__ import annotations

import importlib
from concurrent.futures import Executor
from dataclasses import dataclass
from importlib import metadata
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from ..audit import AuditSink
from ..decisions import DecisionProvider
from ..hooks import HookCallback, HookPoint, HookRegistry
from ..identity import IdentityProvider
from ..middleware.base import Middleware
from ..pipeline import Pipeline
from ..registry import IdempotencyStore
from ..resilience import RuntimeLimits
from ..runtime import Runtime


class Plugin(Protocol):
    name: str
    version: str

    def register(self, builder: "RuntimeBuilder") -> None: ...


@dataclass(frozen=True, slots=True)
class RegisteredPlugin:
    name: str
    version: str
    source: str


class RuntimeBuilder:
    """Mutable composition surface used only before an immutable Runtime exists."""

    def __init__(
        self,
        *,
        idempotency_store: IdempotencyStore | None = None,
        identity_provider: IdentityProvider | None = None,
        require_verified_identity: bool = False,
        limits: RuntimeLimits | None = None,
        sync_executor: Executor | None = None,
        idempotency_executor: Executor | None = None,
    ) -> None:
        self._middlewares: list[Middleware] = []
        self._hooks: list[tuple[HookPoint, HookCallback, bool]] = []
        self._decision_providers: dict[str, DecisionProvider] = {}
        self._audit_sinks: dict[str, AuditSink] = {}
        self._services: dict[str, Any] = {}
        self._runtime_options: dict[str, Any] = {
            "idempotency_store": idempotency_store,
            "identity_provider": identity_provider,
            "require_verified_identity": require_verified_identity,
            "limits": limits,
            "sync_executor": sync_executor,
            "idempotency_executor": idempotency_executor,
        }

    def with_identity(
        self,
        provider: IdentityProvider,
        *,
        required: bool = True,
    ) -> "RuntimeBuilder":
        self._runtime_options["identity_provider"] = provider
        self._runtime_options["require_verified_identity"] = required
        return self

    def with_idempotency_store(
        self, store: IdempotencyStore
    ) -> "RuntimeBuilder":
        self._runtime_options["idempotency_store"] = store
        return self

    def with_limits(self, limits: RuntimeLimits) -> "RuntimeBuilder":
        self._runtime_options["limits"] = limits
        return self

    def with_sync_executor(self, executor: Executor) -> "RuntimeBuilder":
        self._runtime_options["sync_executor"] = executor
        return self

    def with_idempotency_executor(self, executor: Executor) -> "RuntimeBuilder":
        self._runtime_options["idempotency_executor"] = executor
        return self

    def add_middleware(self, middleware: Middleware) -> "RuntimeBuilder":
        self._middlewares.append(middleware)
        return self

    def add_hook(
        self,
        point: HookPoint,
        callback: HookCallback,
        *,
        critical: bool = False,
    ) -> "RuntimeBuilder":
        self._hooks.append((point, callback, critical))
        return self

    def add_decision_provider(
        self, name: str, provider: DecisionProvider
    ) -> "RuntimeBuilder":
        self._put_unique(self._decision_providers, name, provider)
        return self

    def add_audit_sink(self, name: str, sink: AuditSink) -> "RuntimeBuilder":
        self._put_unique(self._audit_sinks, name, sink)
        return self

    def add_service(self, name: str, service: Any) -> "RuntimeBuilder":
        self._put_unique(self._services, name, service)
        return self

    @property
    def decision_providers(self) -> Mapping[str, DecisionProvider]:
        return MappingProxyType(dict(self._decision_providers))

    @property
    def audit_sinks(self) -> Mapping[str, AuditSink]:
        return MappingProxyType(dict(self._audit_sinks))

    @property
    def services(self) -> Mapping[str, Any]:
        return MappingProxyType(dict(self._services))

    def build(self) -> Runtime:
        self._validate()
        hooks = HookRegistry()
        for point, callback, critical in self._hooks:
            hooks.register(point, callback, critical=critical)
        options = {
            key: value
            for key, value in self._runtime_options.items()
            if value is not None
        }
        return Runtime(Pipeline(self._middlewares), hooks=hooks, **options)

    def _validate(self) -> None:
        Pipeline(self._middlewares)

    def _snapshot(self) -> tuple[Any, ...]:
        return (
            list(self._middlewares),
            list(self._hooks),
            dict(self._decision_providers),
            dict(self._audit_sinks),
            dict(self._services),
            dict(self._runtime_options),
        )

    def _restore(self, state: tuple[Any, ...]) -> None:
        (
            self._middlewares,
            self._hooks,
            self._decision_providers,
            self._audit_sinks,
            self._services,
            self._runtime_options,
        ) = state

    @staticmethod
    def _put_unique(target: dict[str, Any], name: str, value: Any) -> None:
        if not name:
            raise ValueError("registration name cannot be empty")
        if name in target:
            raise ValueError(f"registration {name!r} already exists")
        target[name] = value


class PluginManager:
    ENTRY_POINT_GROUP = "agent_runtime_governance.plugins"

    def __init__(self, builder: RuntimeBuilder | None = None) -> None:
        self.builder = builder or RuntimeBuilder()
        self._plugins: dict[str, RegisteredPlugin] = {}

    @property
    def plugins(self) -> tuple[RegisteredPlugin, ...]:
        return tuple(self._plugins.values())

    def load(self, plugin: Plugin, *, source: str = "object") -> RegisteredPlugin:
        name = getattr(plugin, "name", "")
        version = getattr(plugin, "version", "")
        register = getattr(plugin, "register", None)
        if not name or not version or not callable(register):
            raise TypeError("plugin must define name, version, and register(builder)")
        if name in self._plugins:
            raise ValueError(f"plugin {name!r} is already loaded")
        state = self.builder._snapshot()
        try:
            register(self.builder)
            self.builder._validate()
        except Exception:
            self.builder._restore(state)
            raise
        record = RegisteredPlugin(name=name, version=version, source=source)
        self._plugins[name] = record
        return record

    def load_module(self, module_name: str) -> RegisteredPlugin:
        module = importlib.import_module(module_name)
        plugin = getattr(module, "plugin", None)
        if plugin is None:
            factory = getattr(module, "create_plugin", None)
            if not callable(factory):
                raise TypeError(
                    f"module {module_name!r} must export plugin or create_plugin()"
                )
            plugin = factory()
        return self.load(plugin, source=f"module:{module_name}")

    def load_entry_points(
        self, group: str = ENTRY_POINT_GROUP
    ) -> tuple[RegisteredPlugin, ...]:
        discovered = metadata.entry_points()
        entries = discovered.select(group=group)
        loaded: list[RegisteredPlugin] = []
        for entry in sorted(entries, key=lambda item: item.name):
            loaded.append(self.load(entry.load(), source=f"entrypoint:{entry.name}"))
        return tuple(loaded)

    def build(self) -> Runtime:
        return self.builder.build()
