from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import Any, Mapping
from uuid import uuid4

from .decisions import DecisionOutcome, DecisionRecord
from .errors import ContextMutationError


class RiskTier(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    ALLOWED = "allowed"
    DENIED = "denied"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    middleware: str
    outcome: str
    reason: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", _freeze_mapping(self.data))

    def to_dict(self) -> dict[str, Any]:
        return {
            "middleware": self.middleware,
            "outcome": self.outcome,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "data": _thaw(self.data),
        }


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    args: tuple[Any, ...] = ()
    kwargs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "kwargs", _freeze_mapping(self.kwargs))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "args": _thaw(self.args),
            "kwargs": _thaw(self.kwargs),
        }


_IDENTITY_FIELDS = frozenset(
    {
        "trace_id",
        "span_id",
        "parent_span_id",
        "request_id",
        "task_id",
        "conversation_id",
        "user",
        "tenant",
        "permissions",
        "tool_call",
        "input_text",
        "history",
    }
)


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    trace_id: str
    span_id: str
    request_id: str
    tool_call: ToolCall
    parent_span_id: str | None = None
    task_id: str | None = None
    conversation_id: str | None = None
    user: str | None = None
    tenant: str | None = None
    permissions: frozenset[str] = field(default_factory=frozenset)
    input_text: str = ""
    risk_tier: RiskTier = RiskTier.LOW
    risk_score: float = 0.0
    requires_approval: bool = False
    status: ExecutionStatus = ExecutionStatus.PENDING
    decision: DecisionRecord | None = None
    history: tuple[HistoryEntry, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0")
        object.__setattr__(self, "permissions", frozenset(self.permissions))
        object.__setattr__(self, "history", tuple(self.history))
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))

    @classmethod
    def create(
        cls,
        tool_call: ToolCall,
        *,
        input_text: str = "",
        user: str | None = None,
        tenant: str | None = None,
        permissions: frozenset[str] | set[str] = frozenset(),
        task_id: str | None = None,
        conversation_id: str | None = None,
        parent_span_id: str | None = None,
        risk_tier: RiskTier = RiskTier.LOW,
        requires_approval: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> "ExecutionContext":
        return cls(
            trace_id=uuid4().hex,
            span_id=uuid4().hex[:16],
            request_id=uuid4().hex,
            parent_span_id=parent_span_id,
            task_id=task_id,
            conversation_id=conversation_id,
            user=user,
            tenant=tenant,
            permissions=frozenset(permissions),
            input_text=input_text,
            tool_call=tool_call,
            risk_tier=risk_tier,
            requires_approval=requires_approval,
            metadata=metadata or {},
        )

    @property
    def denied(self) -> bool:
        return self.status is ExecutionStatus.DENIED or (
            self.decision is not None
            and self.decision.outcome is DecisionOutcome.DENY
        )

    def evolve(self, **changes: Any) -> "ExecutionContext":
        forbidden = _IDENTITY_FIELDS.intersection(changes)
        if forbidden:
            names = ", ".join(sorted(forbidden))
            raise ContextMutationError(f"immutable context fields cannot change: {names}")
        if self.denied:
            next_status = changes.get("status", self.status)
            next_decision = changes.get("decision", self.decision)
            if next_status is not ExecutionStatus.DENIED or (
                next_decision is not None
                and next_decision.outcome is not DecisionOutcome.DENY
            ):
                raise ContextMutationError("a denied context cannot be allowed later")
        return replace(self, **changes)

    def append_history(self, entry: HistoryEntry) -> "ExecutionContext":
        return replace(self, history=(*self.history, entry))

    def with_decision(self, decision: DecisionRecord) -> "ExecutionContext":
        status = (
            ExecutionStatus.DENIED
            if decision.outcome is DecisionOutcome.DENY
            else self.status
        )
        return self.evolve(decision=decision, status=status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "conversation_id": self.conversation_id,
            "user": self.user,
            "tenant": self.tenant,
            "permissions": sorted(self.permissions),
            "input_text": self.input_text,
            "tool_call": self.tool_call.to_dict(),
            "risk_tier": self.risk_tier.name,
            "risk_score": self.risk_score,
            "requires_approval": self.requires_approval,
            "status": self.status.value,
            "decision": (
                {
                    "outcome": self.decision.outcome.value,
                    "reason": self.decision.reason,
                    "source": self.decision.source,
                }
                if self.decision
                else None
            ),
            "history": [entry.to_dict() for entry in self.history],
            "metadata": _thaw(self.metadata),
            "result": _json_safe(self.result),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionContext":
        decision_data = data.get("decision")
        decision = (
            DecisionRecord(
                outcome=DecisionOutcome(decision_data["outcome"]),
                reason=decision_data["reason"],
                source=decision_data["source"],
            )
            if decision_data
            else None
        )
        tool_data = data["tool_call"]
        return cls(
            trace_id=str(data["trace_id"]),
            span_id=str(data["span_id"]),
            parent_span_id=data.get("parent_span_id"),
            request_id=str(data["request_id"]),
            task_id=data.get("task_id"),
            conversation_id=data.get("conversation_id"),
            user=data.get("user"),
            tenant=data.get("tenant"),
            permissions=frozenset(data.get("permissions", [])),
            input_text=str(data.get("input_text", "")),
            tool_call=ToolCall(
                name=tool_data["name"],
                args=tuple(tool_data.get("args", [])),
                kwargs=tool_data.get("kwargs", {}),
            ),
            risk_tier=RiskTier[data.get("risk_tier", "LOW")],
            risk_score=float(data.get("risk_score", 0.0)),
            requires_approval=bool(data.get("requires_approval", False)),
            status=ExecutionStatus(data.get("status", "pending")),
            decision=decision,
            history=tuple(
                HistoryEntry(
                    middleware=item["middleware"],
                    outcome=item["outcome"],
                    reason=item.get("reason", ""),
                    timestamp=item["timestamp"],
                    data=item.get("data", {}),
                )
                for item in data.get("history", [])
            ),
            metadata=data.get("metadata", {}),
            result=data.get("result"),
            error=data.get("error"),
        )


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted(_thaw(item) for item in value)
    return _json_safe(value)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping | list | tuple | set | frozenset):
        return _thaw(value)
    return repr(value)
