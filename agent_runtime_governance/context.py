from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any, Mapping
from uuid import uuid4

from ._serialization import freeze as _freeze
from ._serialization import freeze_mapping as _freeze_mapping
from ._serialization import json_safe as _json_safe
from ._serialization import thaw as _thaw
from .decisions import DecisionOutcome, DecisionRecord
from .errors import ContextMutationError

if TYPE_CHECKING:
    from .action_contracts import BoundAction

_GOVERNANCE_METADATA_PREFIXES = ("approval_", "identity_", "policy_")
_REPLAY_RUNTIME_METADATA_KEYS = frozenset(
    {"duration_ms", "replay_mode", "replay_authoritative"}
)


class RiskTier(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ExecutionMode(str, Enum):
    READ_ONLY = "read_only"
    IDEMPOTENT = "idempotent"
    MUTATING = "mutating"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    ALLOWED = "allowed"
    DENIED = "denied"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


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
        object.__setattr__(self, "args", tuple(_freeze(item) for item in self.args))
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
        "execution_mode",
        "idempotency_key",
        "deadline",
        "bound_action",
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
    execution_mode: ExecutionMode = ExecutionMode.MUTATING
    idempotency_key: str | None = None
    deadline: datetime | None = None
    bound_action: BoundAction | None = None
    risk_tier: RiskTier = RiskTier.LOW
    risk_score: float = 0.0
    requires_approval: bool = False
    approval_granted: bool = False
    approval_request_id: str | None = None
    approval_decision_id: str | None = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    decision: DecisionRecord | None = None
    history: tuple[HistoryEntry, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.bound_action is not None:
            from .action_contracts import BoundAction

            if not isinstance(self.bound_action, BoundAction):
                raise TypeError("bound_action must be a BoundAction")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0")
        if self.idempotency_key is not None and not self.idempotency_key.strip():
            raise ValueError("idempotency_key cannot be empty")
        if self.deadline is not None and (
            self.deadline.tzinfo is None or self.deadline.utcoffset() is None
        ):
            raise ValueError("deadline must be timezone-aware")
        approval_ids = (self.approval_request_id, self.approval_decision_id)
        if self.approval_granted and any(not value for value in approval_ids):
            raise ValueError("granted approval requires request and decision IDs")
        if not self.approval_granted and any(value is not None for value in approval_ids):
            raise ValueError("approval IDs require a granted approval")
        if self.approval_granted and (
            self.decision is None
            or self.decision.outcome is not DecisionOutcome.ALLOW
            or self.approval_request_id != self.request_id
            or self.approval_decision_id != self.decision.decision_id
        ):
            raise ValueError("granted approval must match an allow decision")
        object.__setattr__(self, "permissions", frozenset(self.permissions))
        object.__setattr__(self, "history", tuple(self.history))
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))
        object.__setattr__(self, "result", _freeze(self.result))

    @classmethod
    def create(
        cls,
        tool_call: ToolCall,
        *,
        request_id: str | None = None,
        input_text: str = "",
        user: str | None = None,
        tenant: str | None = None,
        permissions: frozenset[str] | set[str] = frozenset(),
        task_id: str | None = None,
        conversation_id: str | None = None,
        parent_span_id: str | None = None,
        execution_mode: ExecutionMode = ExecutionMode.MUTATING,
        idempotency_key: str | None = None,
        deadline: datetime | None = None,
        risk_tier: RiskTier = RiskTier.LOW,
        requires_approval: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> "ExecutionContext":
        return cls(
            trace_id=uuid4().hex,
            span_id=uuid4().hex[:16],
            request_id=request_id or uuid4().hex,
            parent_span_id=parent_span_id,
            task_id=task_id,
            conversation_id=conversation_id,
            user=user,
            tenant=tenant,
            permissions=frozenset(permissions),
            input_text=input_text,
            execution_mode=execution_mode,
            idempotency_key=idempotency_key,
            deadline=deadline,
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
        if self.requires_approval and changes.get("requires_approval") is False:
            raise ContextMutationError("an approval requirement cannot be removed")
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

    def bind_action(self, action: BoundAction) -> "ExecutionContext":
        """Attach the runtime-created action identity exactly once."""
        from .action_contracts import BoundAction

        if not isinstance(action, BoundAction):
            raise TypeError("action must be a BoundAction")
        if self.bound_action is not None:
            if self.bound_action == action:
                return self
            raise ContextMutationError("bound action cannot be replaced")
        return replace(self, bound_action=action)

    def with_decision(self, decision: DecisionRecord) -> "ExecutionContext":
        status = (
            ExecutionStatus.DENIED
            if decision.outcome is DecisionOutcome.DENY
            else self.status
        )
        changes: dict[str, Any] = {"decision": decision, "status": status}
        if decision.outcome is not DecisionOutcome.ALLOW:
            changes.update(
                approval_granted=False,
                approval_request_id=None,
                approval_decision_id=None,
            )
        return self.evolve(**changes)

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
            "execution_mode": self.execution_mode.value,
            "idempotency_key": self.idempotency_key,
            "deadline": self.deadline.isoformat() if self.deadline else None,
            "bound_action": (
                self.bound_action.to_dict() if self.bound_action is not None else None
            ),
            "tool_call": self.tool_call.to_dict(),
            "risk_tier": self.risk_tier.name,
            "risk_score": self.risk_score,
            "requires_approval": self.requires_approval,
            "approval_granted": self.approval_granted,
            "approval_request_id": self.approval_request_id,
            "approval_decision_id": self.approval_decision_id,
            "status": self.status.value,
            "decision": self.decision.to_dict() if self.decision else None,
            "history": [entry.to_dict() for entry in self.history],
            "metadata": _thaw(self.metadata),
            "result": _json_safe(self.result),
            "error": self.error,
        }

    def reset_for_replay(
        self,
        *,
        risk_tier: RiskTier | None = None,
        requires_approval: bool | None = None,
        execution_mode: ExecutionMode | None = None,
    ) -> "ExecutionContext":
        """Return the original request identity with governance state cleared."""
        return ExecutionContext(
            trace_id=self.trace_id,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            request_id=self.request_id,
            task_id=self.task_id,
            conversation_id=self.conversation_id,
            user=self.user,
            tenant=self.tenant,
            permissions=self.permissions,
            input_text=self.input_text,
            execution_mode=execution_mode or self.execution_mode,
            idempotency_key=self.idempotency_key,
            # A recorded wall-clock deadline is historical state. Reapplying it
            # would make deterministic policy replay expire merely because time
            # has passed since the original request.
            deadline=None,
            tool_call=self.tool_call,
            risk_tier=risk_tier or self.risk_tier,
            requires_approval=(
                self.requires_approval
                if requires_approval is None
                else requires_approval
            ),
            metadata={
                key: value
                for key, value in self.metadata.items()
                if key.lower() not in _REPLAY_RUNTIME_METADATA_KEYS
                and not key.lower().startswith(_GOVERNANCE_METADATA_PREFIXES)
            },
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionContext":
        decision_data = data.get("decision")
        decision = (
            DecisionRecord.from_dict(decision_data)
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
            execution_mode=ExecutionMode(data.get("execution_mode", "mutating")),
            idempotency_key=data.get("idempotency_key"),
            deadline=(
                datetime.fromisoformat(
                    str(data["deadline"]).replace("Z", "+00:00")
                )
                if data.get("deadline")
                else None
            ),
            bound_action=(
                _bound_action_from_dict(data["bound_action"])
                if data.get("bound_action") is not None
                else None
            ),
            tool_call=ToolCall(
                name=tool_data["name"],
                args=tuple(tool_data.get("args", [])),
                kwargs=tool_data.get("kwargs", {}),
            ),
            risk_tier=RiskTier[data.get("risk_tier", "LOW")],
            risk_score=float(data.get("risk_score", 0.0)),
            requires_approval=bool(data.get("requires_approval", False)),
            approval_granted=bool(data.get("approval_granted", False)),
            approval_request_id=data.get("approval_request_id"),
            approval_decision_id=data.get("approval_decision_id"),
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


def _bound_action_from_dict(value: Any) -> BoundAction:
    from .action_contracts import BoundAction

    if not isinstance(value, Mapping):
        raise TypeError("bound_action must be an object")
    return BoundAction.from_dict(value)
