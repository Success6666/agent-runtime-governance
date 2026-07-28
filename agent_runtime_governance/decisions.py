from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Mapping, Protocol, TypeAlias
from uuid import uuid4

from ._blocking import invoke_extension
from ._serialization import freeze_mapping as _freeze_mapping
from ._serialization import thaw as _thaw
from .contracts import canonical_json_bytes

if TYPE_CHECKING:
    from .context import ExecutionContext


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_HUMAN = "require_human"


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    outcome: DecisionOutcome
    reason: str
    source: str
    decision_id: str = field(default_factory=lambda: uuid4().hex)
    request_id: str | None = None
    approver: str | None = None
    issued_at: str = field(default_factory=lambda: _utc_now())
    expires_at: str | None = None
    tool_name: str | None = None
    arguments_digest: str | None = None
    policy_version: str | None = None
    subject: str | None = None
    tenant: str | None = None
    identity_issuer: str | None = None
    risk_tier: str | None = None
    policy_digest: str | None = None
    action_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, DecisionOutcome):
            raise TypeError("outcome must be a DecisionOutcome")
        _validate_identifier("decision_id", self.decision_id)
        _validate_optional_identifier("request_id", self.request_id)
        _validate_text("reason", self.reason, maximum=2048)
        _validate_identifier("source", self.source)
        _validate_optional_identifier("approver", self.approver)
        _validate_optional_identifier("tool_name", self.tool_name)
        _validate_optional_risk_tier(self.risk_tier)
        _validate_optional_identifier("policy_version", self.policy_version)
        _validate_optional_identifier("policy_digest", self.policy_digest)
        _validate_optional_identifier("subject", self.subject)
        _validate_optional_identifier("tenant", self.tenant)
        _validate_optional_identifier("identity_issuer", self.identity_issuer)
        issued = _parse_datetime(self.issued_at)
        if self.expires_at is not None:
            expires = _parse_datetime(self.expires_at)
            if expires <= issued:
                raise ValueError("approval decision expiry must follow issuance")
        if self.arguments_digest is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.arguments_digest
        ):
            raise ValueError("arguments_digest must be a SHA-256 hex digest")
        _validate_optional_digest("action_digest", self.action_digest)

    def bind_to(
        self,
        request: "ApprovalRequest",
        *,
        approver: str | None = None,
    ) -> "DecisionRecord":
        _reject_mismatch("request_id", self.request_id, request.request_id)
        _reject_mismatch("tool_name", self.tool_name, request.tool_name)
        _reject_mismatch(
            "arguments_digest", self.arguments_digest, request.arguments_digest
        )
        _reject_mismatch("risk_tier", self.risk_tier, request.risk_tier)
        _reject_mismatch("policy_version", self.policy_version, request.policy_version)
        _reject_mismatch("policy_digest", self.policy_digest, request.policy_digest)
        _reject_mismatch("subject", self.subject, request.subject)
        _reject_mismatch("tenant", self.tenant, request.tenant)
        _reject_mismatch(
            "identity_issuer", self.identity_issuer, request.identity_issuer
        )
        _reject_mismatch("action_digest", self.action_digest, request.action_digest)
        if self.expires_at and request.expires_at:
            if _parse_datetime(self.expires_at) > _parse_datetime(request.expires_at):
                raise ValueError("approval decision outlives its request")
        return DecisionRecord(
            outcome=self.outcome,
            reason=self.reason,
            source=self.source,
            decision_id=self.decision_id,
            request_id=request.request_id,
            approver=self.approver or approver,
            issued_at=self.issued_at,
            expires_at=(
                self.expires_at
                or (
                    None
                    if self.outcome is DecisionOutcome.DENY and request.is_expired()
                    else request.expires_at
                )
            ),
            tool_name=request.tool_name,
            arguments_digest=request.arguments_digest,
            risk_tier=request.risk_tier,
            policy_version=request.policy_version,
            policy_digest=request.policy_digest,
            subject=request.subject,
            tenant=request.tenant,
            identity_issuer=request.identity_issuer,
            action_digest=request.action_digest,
        )

    def is_expired(self, now: datetime | None = None) -> bool:
        return _is_expired(self.expires_at, now)

    def validate_for(
        self, request: "ApprovalRequest", *, now: datetime | None = None
    ) -> None:
        if request.is_expired(now):
            raise ValueError("approval request expired")
        if self.is_expired(now):
            raise ValueError("approval decision expired")
        self.bind_to(request)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "reason": self.reason,
            "source": self.source,
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "approver": self.approver,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "tool_name": self.tool_name,
            "arguments_digest": self.arguments_digest,
            "risk_tier": self.risk_tier,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "subject": self.subject,
            "tenant": self.tenant,
            "identity_issuer": self.identity_issuer,
            "action_digest": self.action_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DecisionRecord":
        return cls(
            outcome=DecisionOutcome(data["outcome"]),
            reason=str(data["reason"]),
            source=str(data["source"]),
            decision_id=str(data.get("decision_id") or uuid4().hex),
            request_id=_optional_str(data.get("request_id")),
            approver=_optional_str(data.get("approver")),
            issued_at=str(data.get("issued_at") or _utc_now()),
            expires_at=_optional_str(data.get("expires_at")),
            tool_name=_optional_str(data.get("tool_name")),
            arguments_digest=_optional_str(data.get("arguments_digest")),
            risk_tier=_optional_str(data.get("risk_tier")),
            policy_version=_optional_str(data.get("policy_version")),
            policy_digest=_optional_str(data.get("policy_digest")),
            subject=_optional_str(data.get("subject")),
            tenant=_optional_str(data.get("tenant")),
            identity_issuer=_optional_str(data.get("identity_issuer")),
            action_digest=_optional_str(data.get("action_digest")),
        )


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    trace_id: str
    tool_name: str
    arguments: Mapping[str, object]
    risk_tier: str
    reason: str
    request_id: str = field(default_factory=lambda: uuid4().hex)
    issued_at: str = field(default_factory=lambda: _utc_now())
    expires_at: str | None = None
    arguments_digest: str = ""
    policy_version: str | None = None
    subject: str | None = None
    tenant: str | None = None
    identity_issuer: str | None = None
    arguments_redacted: bool = False
    policy_digest: str | None = None
    action_digest: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier("trace_id", self.trace_id)
        _validate_identifier("request_id", self.request_id)
        _validate_identifier("tool_name", self.tool_name)
        _validate_text("reason", self.reason, maximum=2048)
        if self.risk_tier not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("risk_tier must be LOW, MEDIUM, HIGH, or CRITICAL")
        _validate_optional_identifier("policy_version", self.policy_version)
        _validate_optional_identifier("policy_digest", self.policy_digest)
        _validate_optional_identifier("subject", self.subject)
        _validate_optional_identifier("tenant", self.tenant)
        _validate_optional_identifier("identity_issuer", self.identity_issuer)
        _validate_optional_digest("action_digest", self.action_digest)
        issued = _parse_datetime(self.issued_at)
        if self.expires_at is not None:
            expires = _parse_datetime(self.expires_at)
            if expires <= issued:
                raise ValueError("approval request expiry must follow issuance")
        frozen = _freeze_mapping(self.arguments)
        object.__setattr__(self, "arguments", frozen)
        computed_digest = digest_arguments(frozen)
        if not self.arguments_digest:
            object.__setattr__(self, "arguments_digest", computed_digest)
        elif not re.fullmatch(r"[0-9a-f]{64}", self.arguments_digest):
            raise ValueError("arguments_digest must be a SHA-256 hex digest")
        elif not self.arguments_redacted and self.arguments_digest != computed_digest:
            raise ValueError("arguments_digest does not match approval arguments")

    def is_expired(self, now: datetime | None = None) -> bool:
        return _is_expired(self.expires_at, now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "tool_name": self.tool_name,
            "arguments": _thaw(self.arguments),
            "risk_tier": self.risk_tier,
            "reason": self.reason,
            "request_id": self.request_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "arguments_digest": self.arguments_digest,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "subject": self.subject,
            "tenant": self.tenant,
            "identity_issuer": self.identity_issuer,
            "arguments_redacted": self.arguments_redacted,
            "action_digest": self.action_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ApprovalRequest":
        return cls(
            trace_id=str(data["trace_id"]),
            tool_name=str(data["tool_name"]),
            arguments=dict(data.get("arguments", {})),
            risk_tier=str(data["risk_tier"]),
            reason=str(data["reason"]),
            request_id=str(data.get("request_id") or uuid4().hex),
            issued_at=str(data.get("issued_at") or _utc_now()),
            expires_at=_optional_str(data.get("expires_at")),
            arguments_digest=str(data.get("arguments_digest") or ""),
            policy_version=_optional_str(data.get("policy_version")),
            policy_digest=_optional_str(data.get("policy_digest")),
            subject=_optional_str(data.get("subject")),
            tenant=_optional_str(data.get("tenant")),
            identity_issuer=_optional_str(data.get("identity_issuer")),
            arguments_redacted=bool(data.get("arguments_redacted", False)),
            action_digest=_optional_str(data.get("action_digest")),
        )


class DecisionProvider(Protocol):
    async def decide(
        self, context: "ExecutionContext", request: ApprovalRequest
    ) -> DecisionRecord: ...


DecisionCallbackResult: TypeAlias = DecisionRecord | DecisionOutcome | bool
DecisionCallback: TypeAlias = Callable[
    ["ExecutionContext", ApprovalRequest],
    DecisionCallbackResult | Awaitable[DecisionCallbackResult],
]


class HumanDecisionProvider:
    """Delegates a decision to a user-supplied CLI, chat, or HTTP callback."""

    def __init__(
        self, callback: DecisionCallback, *, approver: str = "human_callback"
    ) -> None:
        if not approver:
            raise ValueError("approver is required")
        self._callback = callback
        self._approver = approver

    async def decide(
        self, context: "ExecutionContext", request: ApprovalRequest
    ) -> DecisionRecord:
        value = await invoke_extension(self._callback, context, request)
        if isinstance(value, DecisionRecord):
            return value if value.approver else replace(value, approver=self._approver)
        if isinstance(value, bool):
            outcome = DecisionOutcome.ALLOW if value else DecisionOutcome.DENY
        elif isinstance(value, DecisionOutcome):
            outcome = value
        else:
            raise TypeError("decision callback must return bool, DecisionOutcome, or DecisionRecord")
        return DecisionRecord(
            outcome=outcome,
            reason="human decision",
            source="human",
            approver=self._approver,
        )


def digest_arguments(arguments: Mapping[str, object]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(arguments, label="approval arguments")
    ).hexdigest()


def denial_for_request(
    request: ApprovalRequest, reason: str, *, source: str = "approval_store"
) -> DecisionRecord:
    return DecisionRecord(
        outcome=DecisionOutcome.DENY,
        reason=reason,
        source=source,
    ).bind_to(request)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_expired(value: str | None, now: datetime | None = None) -> bool:
    if not value:
        return False
    instant = _parse_datetime(value)
    current = now or datetime.now(timezone.utc)
    return instant <= current


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("approval timestamps must be timezone-aware")
    return parsed.astimezone(timezone.utc)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")


def _validate_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a stable 1-256 character identifier")


def _validate_optional_identifier(name: str, value: str | None) -> None:
    if value is not None:
        _validate_identifier(name, value)


def _validate_optional_risk_tier(value: str | None) -> None:
    if value is not None and value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError("risk_tier must be LOW, MEDIUM, HIGH, or CRITICAL")


def _validate_optional_digest(name: str, value: str | None) -> None:
    if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{name} must be a SHA-256 hex digest")


def _validate_text(name: str, value: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{name} must contain 1-{maximum} characters")


def _reject_mismatch(name: str, decision_value: str | None, request_value: str | None) -> None:
    if decision_value is not None and decision_value != request_value:
        raise ValueError(f"approval decision {name} mismatch")


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)
