"""Redacted, immutable terminal events for Runtime consumers.

The runtime owns publication. Consumers only receive a detached DTO and cannot
reach a live ``Runtime`` or ``ExecutionContext`` through this boundary.
"""

from __future__ import annotations

import hashlib
from asyncio import CancelledError
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from threading import Lock
from typing import Any, Awaitable, Protocol

from .action_contracts import BoundAction
from .context import ExecutionContext

RUNTIME_EVENT_SCHEMA_V1 = "arg.runtime-event.v1"
_TRACE_DIGEST_DOMAIN = b"agent-runtime-governance.runtime-event.trace.v1\0"


@dataclass(frozen=True, slots=True)
class RuntimeEventAction:
    """Evidence-safe action identity projected from a bound action."""

    action_digest: str | None
    contract_digest: str | None
    parameters_digest: str | None
    principal_digest: str | None
    tenant_digest: str | None
    identity_digest_key_version: str | None
    policy_version: str | None
    policy_digest: str | None
    precondition_digest: str | None

    @classmethod
    def from_bound_action(cls, action: BoundAction | None) -> "RuntimeEventAction":
        if action is None:
            return cls(
                action_digest=None,
                contract_digest=None,
                parameters_digest=None,
                principal_digest=None,
                tenant_digest=None,
                identity_digest_key_version=None,
                policy_version=None,
                policy_digest=None,
                precondition_digest=None,
            )
        return cls(
            action_digest=action.action_digest,
            contract_digest=action.contract_digest,
            parameters_digest=action.parameters_digest,
            principal_digest=action.principal_digest,
            tenant_digest=action.tenant_digest,
            identity_digest_key_version=action.identity_digest_key_version,
            policy_version=action.policy_version,
            policy_digest=action.policy_digest,
            precondition_digest=action.precondition_digest,
        )

    def to_dict(self) -> dict[str, str | None]:
        """Return the fixed allowlist used by the public event DTO."""

        return {
            "action_digest": self.action_digest,
            "contract_digest": self.contract_digest,
            "parameters_digest": self.parameters_digest,
            "principal_digest": self.principal_digest,
            "tenant_digest": self.tenant_digest,
            "identity_digest_key_version": self.identity_digest_key_version,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "precondition_digest": self.precondition_digest,
        }


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """A versioned, immutable terminal runtime event.

    The DTO is an explicit projection. It intentionally excludes raw identity,
    caller input, parameters, results, decisions, provider data, and context
    history.
    """

    schema_version: str
    event_type: str
    trace_digest: str
    tool_name: str
    status: str
    execution_mode: str
    risk_tier: str
    requires_approval: bool
    approval_granted: bool
    decision_outcome: str | None
    cancelled: bool
    action: RuntimeEventAction

    def __post_init__(self) -> None:
        if self.schema_version != RUNTIME_EVENT_SCHEMA_V1:
            raise ValueError("unsupported runtime event schema version")
        if self.event_type != "terminal":
            raise ValueError("runtime event type must be terminal")

    @classmethod
    def from_context(cls, context: ExecutionContext) -> "RuntimeEvent":
        """Project a terminal context through the fixed public allowlist."""

        decision = context.decision
        return cls(
            schema_version=RUNTIME_EVENT_SCHEMA_V1,
            event_type="terminal",
            trace_digest=_trace_digest(context.trace_id),
            tool_name=context.tool_call.name,
            status=context.status.value,
            execution_mode=context.execution_mode.value,
            risk_tier=context.risk_tier.name,
            requires_approval=context.requires_approval,
            approval_granted=context.approval_granted,
            decision_outcome=None if decision is None else decision.outcome.value,
            cancelled=any(
                entry.middleware == "runtime" and entry.outcome == "cancelled"
                for entry in context.history
            ),
            action=RuntimeEventAction.from_bound_action(context.bound_action),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached representation with no implicit context traversal."""

        return {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "trace_digest": self.trace_digest,
            "tool_name": self.tool_name,
            "status": self.status,
            "execution_mode": self.execution_mode,
            "risk_tier": self.risk_tier,
            "requires_approval": self.requires_approval,
            "approval_granted": self.approval_granted,
            "decision_outcome": self.decision_outcome,
            "cancelled": self.cancelled,
            "action": self.action.to_dict(),
        }


class RuntimeEventSubscriber(Protocol):
    """Receives one detached runtime event without a live runtime handle."""

    def __call__(self, event: RuntimeEvent, /) -> object: ...


RuntimeEventDispatcher = Callable[
    [RuntimeEventSubscriber, RuntimeEvent], Awaitable[Any]
]


@dataclass(frozen=True, slots=True, eq=False)
class RuntimeEventSubscription:
    """An idempotent handle for removing a runtime-event subscriber."""

    _hub: "_RuntimeEventHub"
    _subscriber_id: int

    def unsubscribe(self) -> None:
        self._hub.unsubscribe(self._subscriber_id)


class RuntimeEventStream:
    """Read-only subscription surface for terminal runtime events."""

    __slots__ = ("_hub",)

    def __init__(self, hub: "_RuntimeEventHub") -> None:
        self._hub = hub

    def subscribe(self, subscriber: RuntimeEventSubscriber) -> RuntimeEventSubscription:
        """Subscribe a detached event consumer without exposing ``Runtime``."""

        return self._hub.subscribe(subscriber)


class _RuntimeEventHub:
    """Runtime-owned publisher kept separate from the public reader surface."""

    def __init__(self, subscribers: Iterable[RuntimeEventSubscriber] = ()) -> None:
        self._lock = Lock()
        self._next_subscriber_id = 0
        self._subscribers: dict[int, RuntimeEventSubscriber] = {}
        for subscriber in subscribers:
            self.subscribe(subscriber)

    def subscribe(self, subscriber: RuntimeEventSubscriber) -> RuntimeEventSubscription:
        if not callable(subscriber):
            raise TypeError("runtime event subscriber must be callable")
        with self._lock:
            subscriber_id = self._next_subscriber_id
            self._next_subscriber_id += 1
            self._subscribers[subscriber_id] = subscriber
        return RuntimeEventSubscription(self, subscriber_id)

    def unsubscribe(self, subscriber_id: int) -> None:
        with self._lock:
            self._subscribers.pop(subscriber_id, None)

    async def publish(
        self,
        event: RuntimeEvent,
        dispatcher: RuntimeEventDispatcher,
        subscribers: tuple[RuntimeEventSubscriber, ...],
    ) -> None:
        """Deliver through Runtime dispatch without making consumers authoritative."""

        for subscriber in subscribers:
            try:
                await dispatcher(subscriber, event)
            except (Exception, CancelledError):
                # Debugger and replay consumers cannot alter governance state.
                # This includes cancellation raised by an untrusted consumer;
                # delivery to independent consumers must continue.
                continue

    def subscribers(self) -> tuple[RuntimeEventSubscriber, ...]:
        """Capture the current delivery set without retaining the Runtime."""

        with self._lock:
            return tuple(self._subscribers.values())


def _trace_digest(trace_id: str) -> str:
    return hashlib.sha256(
        _TRACE_DIGEST_DOMAIN + trace_id.encode("utf-8", "surrogatepass")
    ).hexdigest()
