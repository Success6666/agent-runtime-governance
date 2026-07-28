from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import secrets
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, Protocol

import rfc8785

from ._canonical import CanonicalJsonError, rfc8785_json_bytes, rfc8785_json_text
from ._serialization import freeze_mapping, thaw
from ._sqlite import (
    connect_sqlite,
    initialize_sqlite,
    sqlite_journal_capabilities,
)
from .contracts import canonical_json_bytes, validate_instance, validate_schema
from .errors import ContractValidationError, RegistryError

if TYPE_CHECKING:
    from .registry import IdempotencyClaim

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EXECUTION_RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_MAX_REASON_BYTES = 2048
_MAX_ERROR_BYTES = 2048
_MAX_METADATA_BYTES = 16_384
_MAX_EVIDENCE_BYTES = 65_536
_MAX_RESULT_BYTES = 1_048_576
_MAX_SCHEMA_BYTES = 1_048_576
_MAX_VALUE_DEPTH = 32
_MAX_VALUE_NODES = 10_000
_MAX_SAFE_INTEGER = (1 << 53) - 1
_AUDIT_DELIVERY_ALERT_ATTEMPTS = 3
_AUDIT_DELIVERY_ALERT_AGE_SECONDS = 300.0
_RECONCILIATION_SCHEMA_VERSION = 5
_RECONCILIATION_CORE_TABLES = frozenset(
    {
        "reconciliation_heads",
        "reconciliation_events",
        "reconciliation_prepared_actions",
        "reconciliation_audit_outbox",
    }
)
_RECONCILIATION_AUTHORITY_TABLES = _RECONCILIATION_CORE_TABLES | frozenset(
    {"reconciliation_schema"}
)
_RECONCILIATION_LEGACY_CORE_TABLES = {
    1: frozenset({"reconciliation_heads", "reconciliation_events"}),
    2: frozenset(
        {
            "reconciliation_heads",
            "reconciliation_events",
            "reconciliation_prepared_actions",
        }
    ),
    3: frozenset(
        {
            "reconciliation_heads",
            "reconciliation_events",
            "reconciliation_prepared_actions",
        }
    ),
}
_RECONCILIATION_TABLE_DDL = {
    "reconciliation_schema": """
        CREATE TABLE reconciliation_schema (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            version INTEGER NOT NULL
        )
    """,
    "reconciliation_heads": """
        CREATE TABLE reconciliation_heads (
            execution_record_id TEXT PRIMARY KEY NOT NULL,
            action_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'UNKNOWN', 'CONFIRMED_SUCCEEDED',
                'CONFIRMED_NOT_APPLIED', 'MANUAL_REVIEW'
            )),
            revision INTEGER NOT NULL CHECK(revision >= 0),
            disposition TEXT NOT NULL CHECK(disposition IN (
                'blocked_unknown', 'blocked_manual_review', 'completed',
                'applied_no_result', 'retry_allowed'
            )),
            resolved_result_available INTEGER NOT NULL
                CHECK(resolved_result_available IN (0, 1)),
            resolved_result_json TEXT,
            updated_at TEXT NOT NULL,
            CHECK(
                (resolved_result_available = 1 AND resolved_result_json IS NOT NULL)
                OR (resolved_result_available = 0 AND resolved_result_json IS NULL)
            )
        )
    """,
    "reconciliation_events": """
        CREATE TABLE reconciliation_events (
            event_id TEXT PRIMARY KEY NOT NULL,
            execution_record_id TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 1),
            kind TEXT NOT NULL CHECK(kind IN (
                'ATTEMPT_STARTED', 'ATTEMPT_FINISHED', 'STATE_TRANSITION'
            )),
            state_before TEXT NOT NULL,
            state_after TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            UNIQUE(execution_record_id, revision),
            FOREIGN KEY(execution_record_id)
                REFERENCES reconciliation_heads(execution_record_id)
        )
    """,
    "reconciliation_prepared_actions": """
        CREATE TABLE reconciliation_prepared_actions (
            execution_record_id TEXT PRIMARY KEY NOT NULL,
            action_json TEXT NOT NULL,
            prepared_at TEXT NOT NULL
        )
    """,
    "reconciliation_audit_outbox": """
        CREATE TABLE reconciliation_audit_outbox (
            outbox_id TEXT PRIMARY KEY NOT NULL,
            execution_record_id TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0),
            event_type TEXT NOT NULL,
            event_json TEXT NOT NULL,
            event_digest TEXT NOT NULL,
            created_at TEXT NOT NULL,
            delivery_attempts INTEGER NOT NULL DEFAULT 0
                CHECK(delivery_attempts >= 0),
            delivered_at TEXT,
            last_error_class TEXT,
            alerted_at TEXT,
            UNIQUE(execution_record_id, revision, event_type),
            FOREIGN KEY(execution_record_id)
                REFERENCES reconciliation_heads(execution_record_id)
        )
    """,
}
_RECONCILIATION_V4_AUDIT_OUTBOX_DDL = """
    CREATE TABLE reconciliation_audit_outbox (
        outbox_id TEXT PRIMARY KEY NOT NULL,
        execution_record_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK(revision >= 0),
        event_type TEXT NOT NULL,
        event_json TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        created_at TEXT NOT NULL,
        delivery_attempts INTEGER NOT NULL DEFAULT 0
            CHECK(delivery_attempts >= 0),
        delivered_at TEXT,
        last_error_class TEXT,
        UNIQUE(execution_record_id, revision, event_type),
        FOREIGN KEY(execution_record_id)
            REFERENCES reconciliation_heads(execution_record_id)
    )
"""
_RECONCILIATION_PENDING_INDEX_DDL = """
    CREATE INDEX idx_reconciliation_audit_outbox_pending
    ON reconciliation_audit_outbox(delivered_at, execution_record_id, revision)
"""
_RECONCILIATION_TRIGGER_DDL = {
    "reconciliation_events_no_update": """
        CREATE TRIGGER reconciliation_events_no_update
        BEFORE UPDATE ON reconciliation_events
        BEGIN
            SELECT RAISE(ABORT, 'reconciliation events are append-only');
        END
    """,
    "reconciliation_events_no_delete": """
        CREATE TRIGGER reconciliation_events_no_delete
        BEFORE DELETE ON reconciliation_events
        BEGIN
            SELECT RAISE(ABORT, 'reconciliation events are append-only');
        END
    """,
    "reconciliation_prepared_actions_no_update": """
        CREATE TRIGGER reconciliation_prepared_actions_no_update
        BEFORE UPDATE ON reconciliation_prepared_actions
        BEGIN
            SELECT RAISE(ABORT, 'prepared reconciliation actions are immutable');
        END
    """,
    "reconciliation_prepared_actions_delete_guard": """
        CREATE TRIGGER reconciliation_prepared_actions_delete_guard
        BEFORE DELETE ON reconciliation_prepared_actions
        WHEN EXISTS (
            SELECT 1 FROM reconciliation_heads
            WHERE reconciliation_heads.execution_record_id =
                  OLD.execution_record_id
        ) OR EXISTS (
            SELECT 1 FROM idempotency_records
            WHERE idempotency_records.execution_record_id =
                  OLD.execution_record_id
              AND idempotency_records.state != 'completed'
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'prepared reconciliation action cannot be deleted before retention is safe'
            );
        END
    """,
    "reconciliation_audit_outbox_immutable": """
        CREATE TRIGGER reconciliation_audit_outbox_immutable
        BEFORE UPDATE OF outbox_id, execution_record_id, revision, event_type,
                         event_json, event_digest, created_at
        ON reconciliation_audit_outbox
        BEGIN
            SELECT RAISE(
                ABORT,
                'reconciliation audit outbox payload is immutable'
            );
        END
    """,
    "reconciliation_audit_outbox_no_delete": """
        CREATE TRIGGER reconciliation_audit_outbox_no_delete
        BEFORE DELETE ON reconciliation_audit_outbox
        BEGIN
            SELECT RAISE(
                ABORT,
                'reconciliation audit outbox retention requires an explicit migration'
            );
        END
    """,
}
_FORBIDDEN_EVIDENCE_KEYS = {
    "api_key",
    "access_token",
    "authorization",
    "cookie",
    "credential",
    "idempotency_key",
    "identity",
    "namespace",
    "operator_identity_digest",
    "password",
    "principal",
    "provider_id",
    "raw_identity",
    "raw_key",
    "raw_principal",
    "refresh_token",
    "secret",
    "subject",
    "tenant",
}

_LOGGER = logging.getLogger(__name__)


def _create_reconciliation_table(
    connection: sqlite3.Connection,
    table_name: str,
) -> None:
    """Install one exact reconciliation table when it is absent."""

    try:
        definition = _RECONCILIATION_TABLE_DDL[table_name]
    except KeyError as exc:  # pragma: no cover - internal misuse guard
        raise ValueError(f"unknown reconciliation table {table_name!r}") from exc
    connection.execute(
        definition.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
    )


def _create_reconciliation_trigger(
    connection: sqlite3.Connection,
    trigger_name: str,
) -> None:
    """Install one exact reconciliation guard when it is absent."""

    try:
        definition = _RECONCILIATION_TRIGGER_DDL[trigger_name]
    except KeyError as exc:  # pragma: no cover - internal misuse guard
        raise ValueError(f"unknown reconciliation trigger {trigger_name!r}") from exc
    connection.execute(
        definition.replace("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1)
    )


def _create_reconciliation_pending_index(connection: sqlite3.Connection) -> None:
    """Install the canonical pending-delivery index when it is absent."""

    connection.execute(
        _RECONCILIATION_PENDING_INDEX_DDL.replace(
            "CREATE INDEX ",
            "CREATE INDEX IF NOT EXISTS ",
            1,
        )
    )


def _normalize_schema_sql(value: str) -> str:
    """Remove layout-only whitespace without changing quoted SQL semantics."""

    normalized: list[str] = []
    quote_terminator: str | None = None
    line_comment = False
    block_comment = False
    index = 0
    while index < len(value):
        character = value[index]
        following = value[index + 1] if index + 1 < len(value) else ""
        if line_comment:
            normalized.append(character)
            if character in "\r\n":
                line_comment = False
        elif block_comment:
            normalized.append(character)
            if character == "*" and following == "/":
                normalized.append(following)
                index += 1
                block_comment = False
        elif quote_terminator is not None:
            normalized.append(character)
            if character == quote_terminator:
                if following == quote_terminator and quote_terminator != "]":
                    normalized.append(following)
                    index += 1
                else:
                    quote_terminator = None
        elif character == "-" and following == "-":
            normalized.extend((character, following))
            index += 1
            line_comment = True
        elif character == "/" and following == "*":
            normalized.extend((character, following))
            index += 1
            block_comment = True
        elif character in {"'", '"', "`"}:
            normalized.append(character)
            quote_terminator = character
        elif character == "[":
            normalized.append(character)
            quote_terminator = "]"
        elif not character.isspace():
            normalized.append(character)
        index += 1
    return "".join(normalized).rstrip(";")


class ReconciliationState(str, Enum):
    UNKNOWN = "UNKNOWN"
    CONFIRMED_SUCCEEDED = "CONFIRMED_SUCCEEDED"
    CONFIRMED_NOT_APPLIED = "CONFIRMED_NOT_APPLIED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class ReconciliationEventKind(str, Enum):
    ATTEMPT_STARTED = "ATTEMPT_STARTED"
    ATTEMPT_FINISHED = "ATTEMPT_FINISHED"
    STATE_TRANSITION = "STATE_TRANSITION"


class ReconciliationAttemptOutcome(str, Enum):
    SUCCESS = "success"
    INCONCLUSIVE = "inconclusive"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RECOVERY_REQUIRED = "recovery_required"


class ReconciliationDisposition(str, Enum):
    BLOCKED_UNKNOWN = "blocked_unknown"
    BLOCKED_MANUAL_REVIEW = "blocked_manual_review"
    COMPLETED = "completed"
    APPLIED_NO_RESULT = "applied_no_result"
    RETRY_ALLOWED = "retry_allowed"


class ReconciliationTransitionSource(str, Enum):
    PROVIDER = "provider"
    MANUAL = "manual"
    RECOVERY = "recovery"


class ReconciliationError(RuntimeError):
    """Base error for reconciliation protocol failures."""


class ReconciliationConflictError(ReconciliationError):
    """Raised when an append loses its expected-state or revision CAS."""


class ReconciliationNotFoundError(ReconciliationError):
    """Raised when an execution record has no reconciliation head."""


class InvalidReconciliationTransitionError(ReconciliationError):
    """Raised when a requested state transition is not legal."""


class ReconciliationValidationError(ReconciliationError, ValueError):
    """Raised when a bounded protocol value fails closed validation."""


class ReconciliationProvider(Protocol):
    """Read-only receipt/probe provider contract."""

    def reconcile(
        self, context: ReconciliationAttemptContext
    ) -> Awaitable[ReconciliationFinding]: ...


@dataclass(frozen=True, slots=True, repr=False)
class UnknownAction:
    execution_record_id: str
    action_digest: str
    tool_name: str
    contract_id: str
    contract_version: int
    idempotency_namespace_digest: str
    uncertainty_reason: str
    attempted_at: datetime
    tenant_partition_digest: str | None = None
    receipt_schema: Mapping[str, Any] | None = field(default=None, repr=False)
    probe_schema: Mapping[str, Any] | None = field(default=None, repr=False)
    result_schema: Mapping[str, Any] | None = field(default=None, repr=False)
    reconciliation_provider_id: str | None = None
    reconciliation_protocol_version: str | int | None = None
    reconciliation_supported_evidence_kinds: tuple[str, ...] | frozenset[str] = ()
    max_evidence_bytes: int = _MAX_EVIDENCE_BYTES
    max_result_bytes: int = _MAX_RESULT_BYTES
    metadata: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        _require_execution_record_id(self.execution_record_id)
        _require_digest("action_digest", self.action_digest)
        _require_identifier("tool_name", self.tool_name)
        _require_identifier("contract_id", self.contract_id)
        if type(self.contract_version) is not int or self.contract_version < 1:
            raise ReconciliationValidationError(
                "contract_version must be a positive integer"
            )
        _require_digest(
            "idempotency_namespace_digest", self.idempotency_namespace_digest
        )
        if self.tenant_partition_digest is not None:
            _require_digest("tenant_partition_digest", self.tenant_partition_digest)
        _require_bounded_text(
            "uncertainty_reason", self.uncertainty_reason, _MAX_REASON_BYTES
        )
        object.__setattr__(self, "attempted_at", _require_timestamp(self.attempted_at))
        for name in ("max_evidence_bytes", "max_result_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value < 1 or value > _MAX_RESULT_BYTES:
                raise ReconciliationValidationError(
                    f"{name} must be between 1 and {_MAX_RESULT_BYTES}"
                )
        for name in ("receipt_schema", "probe_schema", "result_schema"):
            schema = getattr(self, name)
            if schema is not None:
                object.__setattr__(self, name, _bounded_schema(schema, label=name))
        provider_id = self.reconciliation_provider_id
        provider_version = self.reconciliation_protocol_version
        evidence_kinds = self.reconciliation_supported_evidence_kinds
        if not isinstance(evidence_kinds, tuple | frozenset):
            raise TypeError(
                "reconciliation_supported_evidence_kinds must be a tuple or frozenset"
            )
        if provider_id is None:
            if provider_version is not None or evidence_kinds:
                raise ReconciliationValidationError(
                    "reconciliation provider metadata requires a provider ID"
                )
        else:
            _require_identifier("reconciliation_provider_id", provider_id)
            if provider_version is None:
                raise ReconciliationValidationError(
                    "reconciliation provider metadata requires a protocol version"
                )
            _require_protocol_version(provider_version)
            for kind in evidence_kinds:
                _require_identifier("supported reconciliation evidence kind", kind)
            if not evidence_kinds:
                raise ReconciliationValidationError(
                    "reconciliation provider metadata requires supported evidence kinds"
                )
            if len(set(evidence_kinds)) != len(evidence_kinds):
                raise ReconciliationValidationError(
                    "reconciliation provider metadata cannot contain duplicate evidence kinds"
                )
            object.__setattr__(
                self,
                "reconciliation_supported_evidence_kinds",
                tuple(sorted(evidence_kinds)),
            )
        object.__setattr__(
            self,
            "metadata",
            _bounded_mapping(
                self.metadata,
                label="unknown action metadata",
                max_bytes=_MAX_METADATA_BYTES,
                allow_empty=True,
            ),
        )

    def __repr__(self) -> str:
        return (
            f"UnknownAction(execution_record_id={self.execution_record_id!r}, "
            f"action_digest={self.action_digest!r}, tool_name={self.tool_name!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "execution_record_id": self.execution_record_id,
            "action_digest": self.action_digest,
            "tool_name": self.tool_name,
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "idempotency_namespace_digest": self.idempotency_namespace_digest,
            "uncertainty_reason": self.uncertainty_reason,
            "attempted_at": _timestamp_text(self.attempted_at),
            "receipt_schema": None
            if self.receipt_schema is None
            else thaw(self.receipt_schema),
            "probe_schema": None
            if self.probe_schema is None
            else thaw(self.probe_schema),
            "result_schema": None
            if self.result_schema is None
            else thaw(self.result_schema),
            "max_evidence_bytes": self.max_evidence_bytes,
            "max_result_bytes": self.max_result_bytes,
            "metadata": thaw(self.metadata),
        }
        if self.tenant_partition_digest is not None:
            value["tenant_partition_digest"] = self.tenant_partition_digest
        if self.reconciliation_provider_id is not None:
            value.update(
                {
                    "reconciliation_provider_id": self.reconciliation_provider_id,
                    "reconciliation_protocol_version": self.reconciliation_protocol_version,
                    "reconciliation_supported_evidence_kinds": list(
                        self.reconciliation_supported_evidence_kinds
                    ),
                }
            )
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> UnknownAction:
        data = dict(value)
        data["attempted_at"] = _parse_timestamp(data["attempted_at"])
        if "reconciliation_supported_evidence_kinds" in data:
            kinds = data["reconciliation_supported_evidence_kinds"]
            if not isinstance(kinds, list):
                raise ReconciliationValidationError(
                    "serialized reconciliation provider evidence kinds must be an array"
                )
            data["reconciliation_supported_evidence_kinds"] = tuple(kinds)
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ReconciliationAttemptContext:
    attempt_id: str
    deadline: datetime
    protocol_version: str | int
    action: UnknownAction

    def __post_init__(self) -> None:
        _require_identifier("attempt_id", self.attempt_id)
        object.__setattr__(self, "deadline", _require_timestamp(self.deadline))
        _require_protocol_version(self.protocol_version)
        if not isinstance(self.action, UnknownAction):
            raise TypeError("action must be an UnknownAction")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "deadline": _timestamp_text(self.deadline),
            "protocol_version": self.protocol_version,
            "action": self.action.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReconciliationAttemptContext:
        data = dict(value)
        data["deadline"] = _parse_timestamp(data["deadline"])
        data["action"] = UnknownAction.from_dict(data["action"])
        return cls(**data)


@dataclass(frozen=True, slots=True, repr=False)
class ReconciliationFinding:
    proposed_state: ReconciliationState
    evidence_kind: str
    evidence: Mapping[str, Any]
    observed_at: datetime
    retry_safe: bool = False
    resolved_result_available: bool = False
    resolved_result: Any | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.proposed_state, ReconciliationState):
            raise TypeError("proposed_state must be a ReconciliationState")
        if self.proposed_state is ReconciliationState.UNKNOWN:
            raise ReconciliationValidationError(
                "an inconclusive finding is an attempt outcome, not a state transition"
            )
        _require_identifier("evidence_kind", self.evidence_kind)
        object.__setattr__(
            self,
            "evidence",
            _bounded_mapping(
                self.evidence,
                label="reconciliation evidence",
                max_bytes=_MAX_EVIDENCE_BYTES,
                allow_empty=False,
            ),
        )
        object.__setattr__(self, "observed_at", _require_timestamp(self.observed_at))
        if type(self.retry_safe) is not bool:
            raise TypeError("retry_safe must be a bool")
        if type(self.resolved_result_available) is not bool:
            raise TypeError("resolved_result_available must be a bool")
        if self.resolved_result is not None and not self.resolved_result_available:
            object.__setattr__(self, "resolved_result_available", True)
        if (
            self.proposed_state is ReconciliationState.CONFIRMED_NOT_APPLIED
            and not self.retry_safe
        ):
            raise ReconciliationValidationError(
                "CONFIRMED_NOT_APPLIED requires an explicit retry-safe assertion"
            )
        if (
            self.retry_safe
            and self.proposed_state is not ReconciliationState.CONFIRMED_NOT_APPLIED
        ):
            raise ReconciliationValidationError(
                "retry_safe is valid only for CONFIRMED_NOT_APPLIED"
            )
        if self.resolved_result_available:
            if self.proposed_state is not ReconciliationState.CONFIRMED_SUCCEEDED:
                raise ReconciliationValidationError(
                    "resolved_result is valid only for CONFIRMED_SUCCEEDED"
                )
            object.__setattr__(
                self,
                "resolved_result",
                _bounded_value(
                    self.resolved_result,
                    label="resolved result",
                    max_bytes=_MAX_RESULT_BYTES,
                ),
            )

    @property
    def state(self) -> ReconciliationState:
        return self.proposed_state

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposed_state": self.proposed_state.value,
            "evidence_kind": self.evidence_kind,
            "evidence": thaw(self.evidence),
            "observed_at": _timestamp_text(self.observed_at),
            "retry_safe": self.retry_safe,
            "resolved_result_available": self.resolved_result_available,
            "resolved_result": thaw(self.resolved_result),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReconciliationFinding:
        data = dict(value)
        data["proposed_state"] = ReconciliationState(data["proposed_state"])
        data["observed_at"] = _parse_timestamp(data["observed_at"])
        return cls(**data)


@dataclass(frozen=True, slots=True, repr=False)
class ProviderDescriptor:
    provider_id: str
    protocol_version: str | int
    supported_evidence_kinds: tuple[str, ...] | frozenset[str]
    provider: (
        ReconciliationProvider
        | Callable[[ReconciliationAttemptContext], Awaitable[ReconciliationFinding]]
    ) = field(repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        _require_identifier("provider_id", self.provider_id)
        _require_protocol_version(self.protocol_version)
        if not isinstance(self.supported_evidence_kinds, tuple | frozenset):
            raise TypeError("supported_evidence_kinds must be a tuple or frozenset")
        for kind in self.supported_evidence_kinds:
            _require_identifier("supported evidence kind", kind)
        if not self.supported_evidence_kinds:
            raise ReconciliationValidationError(
                "supported_evidence_kinds cannot be empty"
            )
        if len(set(self.supported_evidence_kinds)) != len(
            self.supported_evidence_kinds
        ):
            raise ReconciliationValidationError(
                "supported_evidence_kinds cannot contain duplicates"
            )
        object.__setattr__(
            self,
            "supported_evidence_kinds",
            tuple(sorted(self.supported_evidence_kinds)),
        )
        if not callable(self.provider) and not callable(
            getattr(self.provider, "reconcile", None)
        ):
            raise TypeError("provider must be callable or expose reconcile(context)")


@dataclass(frozen=True, slots=True, repr=False)
class ManualResolution:
    execution_record_id: str
    operator_identity_digest: str
    reason: str
    expected_state: ReconciliationState
    expected_revision: int
    new_state: ReconciliationState
    resolved_at: datetime
    evidence_kind: str
    evidence: Mapping[str, Any]
    retry_safe: bool = False
    resolved_result_available: bool = False
    resolved_result: Any | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _require_execution_record_id(self.execution_record_id)
        _require_digest("operator_identity_digest", self.operator_identity_digest)
        _require_bounded_text(
            "manual resolution reason", self.reason, _MAX_REASON_BYTES
        )
        if self.expected_state is not ReconciliationState.MANUAL_REVIEW:
            raise ReconciliationValidationError(
                "manual resolution requires expected_state MANUAL_REVIEW"
            )
        if type(self.expected_revision) is not int or self.expected_revision < 0:
            raise ReconciliationValidationError(
                "expected_revision must be a non-negative integer"
            )
        if self.new_state not in {
            ReconciliationState.CONFIRMED_SUCCEEDED,
            ReconciliationState.CONFIRMED_NOT_APPLIED,
        }:
            raise InvalidReconciliationTransitionError(
                "manual resolution must select a confirmed terminal state"
            )
        object.__setattr__(self, "resolved_at", _require_timestamp(self.resolved_at))
        _require_identifier("evidence_kind", self.evidence_kind)
        object.__setattr__(
            self,
            "evidence",
            _bounded_mapping(
                self.evidence,
                label="manual resolution evidence",
                max_bytes=_MAX_EVIDENCE_BYTES,
                allow_empty=False,
            ),
        )
        if type(self.retry_safe) is not bool:
            raise TypeError("retry_safe must be a bool")
        if type(self.resolved_result_available) is not bool:
            raise TypeError("resolved_result_available must be a bool")
        if self.resolved_result is not None and not self.resolved_result_available:
            object.__setattr__(self, "resolved_result_available", True)
        if (
            self.new_state is ReconciliationState.CONFIRMED_NOT_APPLIED
            and not self.retry_safe
        ):
            raise ReconciliationValidationError(
                "CONFIRMED_NOT_APPLIED requires an explicit retry-safe assertion"
            )
        if (
            self.retry_safe
            and self.new_state is not ReconciliationState.CONFIRMED_NOT_APPLIED
        ):
            raise ReconciliationValidationError(
                "retry_safe is valid only for CONFIRMED_NOT_APPLIED"
            )
        if self.resolved_result_available:
            if self.new_state is not ReconciliationState.CONFIRMED_SUCCEEDED:
                raise ReconciliationValidationError(
                    "resolved_result is valid only for CONFIRMED_SUCCEEDED"
                )
            object.__setattr__(
                self,
                "resolved_result",
                _bounded_value(
                    self.resolved_result,
                    label="resolved result",
                    max_bytes=_MAX_RESULT_BYTES,
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_record_id": self.execution_record_id,
            "operator_identity_digest": self.operator_identity_digest,
            "reason": self.reason,
            "expected_state": self.expected_state.value,
            "expected_revision": self.expected_revision,
            "new_state": self.new_state.value,
            "resolved_at": _timestamp_text(self.resolved_at),
            "evidence_kind": self.evidence_kind,
            "evidence": thaw(self.evidence),
            "retry_safe": self.retry_safe,
            "resolved_result_available": self.resolved_result_available,
            "resolved_result": thaw(self.resolved_result),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ManualResolution:
        data = dict(value)
        data["expected_state"] = ReconciliationState(data["expected_state"])
        data["new_state"] = ReconciliationState(data["new_state"])
        data["resolved_at"] = _parse_timestamp(data["resolved_at"])
        return cls(**data)


@dataclass(frozen=True, slots=True, repr=False)
class ReconciliationTransition:
    execution_record_id: str
    expected_state: ReconciliationState
    expected_revision: int
    new_state: ReconciliationState
    source: ReconciliationTransitionSource
    evidence_kind: str
    evidence: Mapping[str, Any]
    occurred_at: datetime
    retry_safe: bool
    resolved_result_available: bool
    provider_id: str | None = None
    attempt_id: str | None = None
    operator_identity_digest: str | None = None
    reason: str | None = None
    resolved_result: Any | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _require_execution_record_id(self.execution_record_id)
        if not isinstance(self.expected_state, ReconciliationState):
            raise TypeError("expected_state must be a ReconciliationState")
        if not isinstance(self.new_state, ReconciliationState):
            raise TypeError("new_state must be a ReconciliationState")
        if not isinstance(self.source, ReconciliationTransitionSource):
            raise TypeError("source must be a ReconciliationTransitionSource")
        if type(self.expected_revision) is not int or self.expected_revision < 0:
            raise ReconciliationValidationError(
                "expected_revision must be a non-negative integer"
            )
        object.__setattr__(self, "occurred_at", _require_timestamp(self.occurred_at))
        _require_identifier("evidence_kind", self.evidence_kind)
        object.__setattr__(
            self,
            "evidence",
            _bounded_mapping(
                self.evidence,
                label="transition evidence",
                max_bytes=_MAX_EVIDENCE_BYTES,
                allow_empty=False,
            ),
        )
        if self.provider_id is not None:
            _require_identifier("provider_id", self.provider_id)
        if self.attempt_id is not None:
            _require_identifier("attempt_id", self.attempt_id)
        if self.operator_identity_digest is not None:
            _require_digest("operator_identity_digest", self.operator_identity_digest)
        if self.reason is not None:
            _require_bounded_text("transition reason", self.reason, _MAX_REASON_BYTES)
        if type(self.retry_safe) is not bool:
            raise TypeError("retry_safe must be a bool")
        if type(self.resolved_result_available) is not bool:
            raise TypeError("resolved_result_available must be a bool")
        if self.resolved_result is not None and not self.resolved_result_available:
            raise ReconciliationValidationError(
                "resolved_result requires resolved_result_available"
            )
        if self.resolved_result_available:
            object.__setattr__(
                self,
                "resolved_result",
                _bounded_value(
                    self.resolved_result,
                    label="resolved result",
                    max_bytes=_MAX_RESULT_BYTES,
                ),
            )
        if self.source is ReconciliationTransitionSource.PROVIDER:
            if self.provider_id is None or self.attempt_id is None:
                raise ReconciliationValidationError(
                    "provider transition requires provider_id and attempt_id"
                )
            if self.operator_identity_digest is not None:
                raise ReconciliationValidationError(
                    "provider transition cannot carry operator identity"
                )
        elif self.source is ReconciliationTransitionSource.RECOVERY:
            if (
                self.provider_id is not None
                or self.attempt_id is not None
                or self.operator_identity_digest is not None
            ):
                raise ReconciliationValidationError(
                    "recovery transition cannot carry provider or operator identity"
                )
            if self.reason is None:
                raise ReconciliationValidationError(
                    "recovery transition requires a reason"
                )
            if self.new_state is not ReconciliationState.MANUAL_REVIEW:
                raise ReconciliationValidationError(
                    "recovery transition must enter MANUAL_REVIEW"
                )
        elif self.operator_identity_digest is None or self.reason is None:
            raise ReconciliationValidationError(
                "manual transition requires operator identity and reason"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_record_id": self.execution_record_id,
            "expected_state": self.expected_state.value,
            "expected_revision": self.expected_revision,
            "new_state": self.new_state.value,
            "source": self.source.value,
            "evidence_kind": self.evidence_kind,
            "evidence": thaw(self.evidence),
            "occurred_at": _timestamp_text(self.occurred_at),
            "retry_safe": self.retry_safe,
            "resolved_result_available": self.resolved_result_available,
            "provider_id": self.provider_id,
            "attempt_id": self.attempt_id,
            "operator_identity_digest": self.operator_identity_digest,
            "reason": self.reason,
            "resolved_result": thaw(self.resolved_result),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReconciliationTransition:
        data = dict(value)
        data["expected_state"] = ReconciliationState(data["expected_state"])
        data["new_state"] = ReconciliationState(data["new_state"])
        data["source"] = ReconciliationTransitionSource(data["source"])
        data["occurred_at"] = _parse_timestamp(data["occurred_at"])
        return cls(**data)


@dataclass(frozen=True, slots=True, repr=False)
class ReconciliationRecord:
    event_id: str
    execution_record_id: str
    revision: int
    kind: ReconciliationEventKind
    state_before: ReconciliationState
    state_after: ReconciliationState
    occurred_at: datetime
    payload: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        _require_execution_record_id(self.event_id)
        _require_execution_record_id(self.execution_record_id)
        if not isinstance(self.kind, ReconciliationEventKind):
            raise TypeError("kind must be a ReconciliationEventKind")
        if not isinstance(self.state_before, ReconciliationState) or not isinstance(
            self.state_after, ReconciliationState
        ):
            raise TypeError("record states must be ReconciliationState values")
        if type(self.revision) is not int or self.revision < 1:
            raise ReconciliationValidationError("record revision must be positive")
        object.__setattr__(self, "occurred_at", _require_timestamp(self.occurred_at))
        object.__setattr__(
            self,
            "payload",
            _bounded_mapping(
                self.payload,
                label="reconciliation record payload",
                max_bytes=_MAX_RESULT_BYTES,
                allow_empty=True,
                reject_sensitive_keys=False,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "execution_record_id": self.execution_record_id,
            "revision": self.revision,
            "kind": self.kind.value,
            "state_before": self.state_before.value,
            "state_after": self.state_after.value,
            "occurred_at": _timestamp_text(self.occurred_at),
            "payload": thaw(self.payload),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReconciliationRecord:
        data = dict(value)
        data["kind"] = ReconciliationEventKind(data["kind"])
        data["state_before"] = ReconciliationState(data["state_before"])
        data["state_after"] = ReconciliationState(data["state_after"])
        data["occurred_at"] = _parse_timestamp(data["occurred_at"])
        return cls(**data)


@dataclass(frozen=True, slots=True, repr=False)
class ReconciliationAuditEnvelope:
    """An immutable, redacted reconciliation audit event awaiting delivery."""

    outbox_id: str
    execution_record_id: str
    revision: int
    event_type: str
    event: Mapping[str, Any] = field(repr=False)
    created_at: datetime
    delivery_attempts: int = 0

    def __post_init__(self) -> None:
        _require_execution_record_id(self.outbox_id)
        _require_execution_record_id(self.execution_record_id)
        if type(self.revision) is not int or self.revision < 0:
            raise ReconciliationValidationError(
                "reconciliation audit revision must be non-negative"
            )
        _require_identifier("reconciliation audit event type", self.event_type)
        object.__setattr__(self, "created_at", _require_timestamp(self.created_at))
        if type(self.delivery_attempts) is not int or self.delivery_attempts < 0:
            raise ReconciliationValidationError(
                "reconciliation audit delivery attempts must be non-negative"
            )
        object.__setattr__(
            self,
            "event",
            _bounded_mapping(
                self.event,
                label="reconciliation audit envelope",
                max_bytes=_MAX_METADATA_BYTES,
                allow_empty=False,
                reject_sensitive_keys=False,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "outbox_id": self.outbox_id,
            "execution_record_id": self.execution_record_id,
            "revision": self.revision,
            "event_type": self.event_type,
            "event": thaw(self.event),
            "created_at": _timestamp_text(self.created_at),
            "delivery_attempts": self.delivery_attempts,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ReconciliationHead:
    action: UnknownAction
    state: ReconciliationState
    revision: int
    disposition: ReconciliationDisposition
    updated_at: datetime
    resolved_result_available: bool = False
    resolved_result: Any | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.action, UnknownAction):
            raise TypeError("action must be an UnknownAction")
        if not isinstance(self.state, ReconciliationState):
            raise TypeError("state must be a ReconciliationState")
        if type(self.revision) is not int or self.revision < 0:
            raise ReconciliationValidationError(
                "head revision must be a non-negative integer"
            )
        if not isinstance(self.disposition, ReconciliationDisposition):
            raise TypeError("disposition must be a ReconciliationDisposition")
        object.__setattr__(self, "updated_at", _require_timestamp(self.updated_at))
        if type(self.resolved_result_available) is not bool:
            raise TypeError("resolved_result_available must be a bool")
        if self.resolved_result is not None and not self.resolved_result_available:
            raise ReconciliationValidationError(
                "resolved_result requires resolved_result_available"
            )
        if self.resolved_result_available:
            object.__setattr__(
                self,
                "resolved_result",
                _bounded_value(
                    self.resolved_result,
                    label="resolved result",
                    max_bytes=self.action.max_result_bytes,
                ),
            )

    @property
    def execution_record_id(self) -> str:
        return self.action.execution_record_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "state": self.state.value,
            "revision": self.revision,
            "disposition": self.disposition.value,
            "updated_at": _timestamp_text(self.updated_at),
            "resolved_result_available": self.resolved_result_available,
            "resolved_result": thaw(self.resolved_result),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReconciliationHead:
        data = dict(value)
        data["action"] = UnknownAction.from_dict(data["action"])
        data["state"] = ReconciliationState(data["state"])
        data["disposition"] = ReconciliationDisposition(data["disposition"])
        data["updated_at"] = _parse_timestamp(data["updated_at"])
        return cls(**data)


class ReconciliationLedger(Protocol):
    def prepare_action(
        self, claim: "IdempotencyClaim", action: UnknownAction
    ) -> None: ...

    def create_unknown(self, action: UnknownAction) -> ReconciliationHead: ...

    def start_attempt(
        self,
        context: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        expected_revision: int,
    ) -> ReconciliationRecord: ...

    def finish_attempt(
        self,
        context: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        outcome: ReconciliationAttemptOutcome,
        expected_revision: int,
        *,
        finding: ReconciliationFinding | None = None,
        error: str | None = None,
        finished_at: datetime | None = None,
    ) -> ReconciliationRecord: ...

    def recover_unfinished_attempts(
        self,
        execution_record_id: str,
        *,
        now: datetime | None = None,
    ) -> ReconciliationHead | None: ...

    def compare_and_append_transition(
        self,
        execution_record_id: str,
        expected_state: ReconciliationState,
        expected_revision: int,
        decision: ReconciliationFinding | ManualResolution,
        *,
        provider: ProviderDescriptor | None = None,
        attempt_id: str | None = None,
    ) -> ReconciliationHead: ...

    def current(self, execution_record_id: str) -> ReconciliationHead: ...

    def history(self, execution_record_id: str) -> tuple[ReconciliationRecord, ...]: ...

    def attempts(
        self, execution_record_id: str
    ) -> tuple[ReconciliationRecord, ...]: ...


class InMemoryReconciliationLedger:
    production_durable = False

    def __init__(self) -> None:
        self._heads: dict[str, ReconciliationHead] = {}
        self._events: dict[str, list[ReconciliationRecord]] = {}
        self._prepared_actions: dict[str, UnknownAction] = {}
        self._lock = Lock()

    def prepare_action(
        self, claim: "IdempotencyClaim", action: UnknownAction
    ) -> None:
        if not isinstance(action, UnknownAction):
            raise TypeError("action must be an UnknownAction")
        if not getattr(claim, "owner", False):
            raise ReconciliationConflictError(
                "only the current idempotency owner can prepare reconciliation"
            )
        if claim.execution_record_id != action.execution_record_id:
            raise ReconciliationValidationError(
                "prepared action execution record does not match the idempotency claim"
            )
        if claim.fingerprint != action.action_digest:
            raise ReconciliationValidationError(
                "prepared action digest does not match the idempotency claim"
            )
        if (
            idempotency_namespace_digest(claim.namespace)
            != action.idempotency_namespace_digest
        ):
            raise ReconciliationValidationError(
                "prepared action namespace does not match the idempotency claim"
            )
        with self._lock:
            existing = self._prepared_actions.get(action.execution_record_id)
            if existing is not None and existing != action:
                raise ReconciliationConflictError(
                    "a different reconciliation action is already prepared"
                )
            self._prepared_actions[action.execution_record_id] = action

    def create_unknown(self, action: UnknownAction) -> ReconciliationHead:
        if not isinstance(action, UnknownAction):
            raise TypeError("action must be an UnknownAction")
        with self._lock:
            if action.execution_record_id in self._heads:
                raise ReconciliationConflictError(
                    "a reconciliation head already exists for this execution record"
                )
            head = ReconciliationHead(
                action=action,
                state=ReconciliationState.UNKNOWN,
                revision=0,
                disposition=ReconciliationDisposition.BLOCKED_UNKNOWN,
                updated_at=action.attempted_at,
            )
            self._heads[action.execution_record_id] = head
            self._events[action.execution_record_id] = []
            return head

    def start_attempt(
        self,
        context: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        expected_revision: int,
    ) -> ReconciliationRecord:
        _validate_attempt(context, provider)
        payload = {
            "attempt_id": context.attempt_id,
            "deadline": _timestamp_text(context.deadline),
            "protocol_version": context.protocol_version,
            "provider_id": provider.provider_id,
        }
        with self._lock:
            return self._append_attempt_locked(
                context.action.execution_record_id,
                context.action,
                expected_revision,
                ReconciliationEventKind.ATTEMPT_STARTED,
                datetime.now(timezone.utc),
                payload,
            )

    def recover_unfinished_attempts(
        self,
        execution_record_id: str,
        *,
        now: datetime | None = None,
    ) -> ReconciliationHead | None:
        """Quarantine expired unclosed attempts before another probe can start.

        A start record is a durable claim that a read-only provider was invoked.
        While its deadline is still valid, a competing runtime must not start a
        second provider call. Once it expires without a terminal record, the
        only deterministic outcome is a terminal recovery event followed by
        MANUAL_REVIEW.
        """

        recovered_at = _require_timestamp(now or datetime.now(timezone.utc))
        with self._lock:
            head = self._head_locked(execution_record_id)
            records = self._events[execution_record_id]
            attempts = _unfinished_attempt_contexts(head.action, records)
            if not attempts:
                return None
            if head.state is not ReconciliationState.UNKNOWN:
                raise ReconciliationError(
                    "a non-UNKNOWN reconciliation head has an unfinished attempt"
                )
            if any(context.deadline > recovered_at for _, context, _ in attempts):
                return head

            for _start, context, provider in attempts:
                payload, occurred_at = _finish_payload(
                    context,
                    provider,
                    ReconciliationAttemptOutcome.RECOVERY_REQUIRED,
                    None,
                    "provider attempt expired before a terminal record was persisted",
                    recovered_at,
                )
                self._append_attempt_locked(
                    execution_record_id,
                    head.action,
                    self._heads[execution_record_id].revision,
                    ReconciliationEventKind.ATTEMPT_FINISHED,
                    occurred_at,
                    payload,
                )

            current = self._heads[execution_record_id]
            transition = _recovery_transition(current, len(attempts), recovered_at)
            _validate_transition_evidence(current.action, transition)
            record, updated = _transition_record(current, transition)
            self._events[execution_record_id].append(record)
            self._heads[execution_record_id] = updated
            return updated

    def finish_attempt(
        self,
        context: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        outcome: ReconciliationAttemptOutcome,
        expected_revision: int,
        *,
        finding: ReconciliationFinding | None = None,
        error: str | None = None,
        finished_at: datetime | None = None,
    ) -> ReconciliationRecord:
        _validate_attempt(context, provider)
        payload, occurred_at = _finish_payload(
            context, provider, outcome, finding, error, finished_at
        )
        with self._lock:
            return self._append_attempt_locked(
                context.action.execution_record_id,
                context.action,
                expected_revision,
                ReconciliationEventKind.ATTEMPT_FINISHED,
                occurred_at,
                payload,
            )

    def compare_and_append_transition(
        self,
        execution_record_id: str,
        expected_state: ReconciliationState,
        expected_revision: int,
        decision: ReconciliationFinding | ManualResolution,
        *,
        provider: ProviderDescriptor | None = None,
        attempt_id: str | None = None,
    ) -> ReconciliationHead:
        with self._lock:
            head = self._head_locked(execution_record_id)
            _require_cas(head, expected_state, expected_revision)
            transition = _build_transition(
                head, decision, provider=provider, attempt_id=attempt_id
            )
            if isinstance(decision, ReconciliationFinding):
                _require_finished_attempt(
                    self._events[execution_record_id],
                    attempt_id,
                    provider,
                    decision,
                )
            _validate_transition_evidence(head.action, transition)
            record, updated = _transition_record(head, transition)
            self._events[execution_record_id].append(record)
            self._heads[execution_record_id] = updated
            return updated

    def current(self, execution_record_id: str) -> ReconciliationHead:
        with self._lock:
            return self._head_locked(execution_record_id)

    def history(self, execution_record_id: str) -> tuple[ReconciliationRecord, ...]:
        with self._lock:
            self._head_locked(execution_record_id)
            return tuple(self._events[execution_record_id])

    def attempts(self, execution_record_id: str) -> tuple[ReconciliationRecord, ...]:
        return tuple(
            record
            for record in self.history(execution_record_id)
            if record.kind
            in {
                ReconciliationEventKind.ATTEMPT_STARTED,
                ReconciliationEventKind.ATTEMPT_FINISHED,
            }
        )

    def _append_attempt_locked(
        self,
        execution_record_id: str,
        action: UnknownAction,
        expected_revision: int,
        kind: ReconciliationEventKind,
        occurred_at: datetime,
        payload: Mapping[str, Any],
    ) -> ReconciliationRecord:
        head = self._head_locked(execution_record_id)
        if head.action != action:
            raise ReconciliationValidationError(
                "attempt context action does not match the persisted unknown action"
            )
        if (
            kind is ReconciliationEventKind.ATTEMPT_STARTED
            and head.state is not ReconciliationState.UNKNOWN
        ):
            raise InvalidReconciliationTransitionError(
                "provider attempts are valid only while state is UNKNOWN"
            )
        _require_cas(head, head.state, expected_revision)
        _validate_attempt_append(self._events[execution_record_id], kind, payload)
        record = ReconciliationRecord(
            event_id=_new_id(),
            execution_record_id=execution_record_id,
            revision=head.revision + 1,
            kind=kind,
            state_before=head.state,
            state_after=head.state,
            occurred_at=occurred_at,
            payload=payload,
        )
        self._events[execution_record_id].append(record)
        self._heads[execution_record_id] = ReconciliationHead(
            action=head.action,
            state=head.state,
            revision=record.revision,
            disposition=head.disposition,
            updated_at=record.occurred_at,
            resolved_result_available=head.resolved_result_available,
            resolved_result=head.resolved_result,
        )
        return record

    def _head_locked(self, execution_record_id: str) -> ReconciliationHead:
        _require_execution_record_id(execution_record_id)
        try:
            return self._heads[execution_record_id]
        except KeyError as exc:
            raise ReconciliationNotFoundError(
                f"unknown execution record {execution_record_id!r}"
            ) from exc


class SQLiteReconciliationLedger:
    production_durable = True

    def __init__(
        self,
        path: str | Path,
        *,
        timeout_seconds: float = 30.0,
        journal_mode: str = "auto",
        audit_delivery_alert_attempts: int = _AUDIT_DELIVERY_ALERT_ATTEMPTS,
        audit_delivery_alert_age_seconds: float = _AUDIT_DELIVERY_ALERT_AGE_SECONDS,
        _allow_legacy_schema_migration: bool = False,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if (
            type(audit_delivery_alert_attempts) is not int
            or audit_delivery_alert_attempts < 1
        ):
            raise ValueError("audit_delivery_alert_attempts must be a positive integer")
        if (
            isinstance(audit_delivery_alert_age_seconds, bool)
            or not isinstance(audit_delivery_alert_age_seconds, int | float)
            or not math.isfinite(audit_delivery_alert_age_seconds)
            or audit_delivery_alert_age_seconds <= 0
        ):
            raise ValueError(
                "audit_delivery_alert_age_seconds must be a positive finite number"
            )
        if type(_allow_legacy_schema_migration) is not bool:
            raise TypeError("_allow_legacy_schema_migration must be a bool")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self.journal_capabilities = sqlite_journal_capabilities(journal_mode)
        self._journal_mode = journal_mode
        self._audit_delivery_alert_attempts = audit_delivery_alert_attempts
        self._audit_delivery_alert_age_seconds = float(
            audit_delivery_alert_age_seconds
        )
        self._allow_legacy_schema_migration = _allow_legacy_schema_migration
        if self._allow_legacy_schema_migration:
            self._initialize_controlled_migration()
        else:
            self._preflight_reconciliation_schema()
            self._preflight_idempotency_schema()
            self._initialize()

    @classmethod
    def migrate_legacy(
        cls,
        path: str | Path,
        *,
        timeout_seconds: float = 30.0,
        journal_mode: str = "auto",
        audit_delivery_alert_attempts: int = _AUDIT_DELIVERY_ALERT_ATTEMPTS,
        audit_delivery_alert_age_seconds: float = _AUDIT_DELIVERY_ALERT_AGE_SECONDS,
    ) -> "SQLiteReconciliationLedger":
        """Upgrade a verified pre-outbox database in a dedicated migration process.

        Normal runtime construction never creates an outbox for a database that
        declares versions 1 through 3.  Calling this method is an explicit
        operator action and must be limited to an offline migration after a
        verified backup and restore drill.
        """

        return cls(
            path,
            timeout_seconds=timeout_seconds,
            journal_mode=journal_mode,
            audit_delivery_alert_attempts=audit_delivery_alert_attempts,
            audit_delivery_alert_age_seconds=audit_delivery_alert_age_seconds,
            _allow_legacy_schema_migration=True,
        )

    def _initialize_controlled_migration(self) -> None:
        """Upgrade colocated authorities atomically after validating both sides."""

        with initialize_sqlite(
            self.path,
            self.timeout_seconds,
            journal_mode=self._journal_mode,
        ) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_reconciliation_schema(connection)
            from .registry import SQLiteIdempotencyStore

            try:
                idempotency_state = SQLiteIdempotencyStore._preflight_schema(
                    connection,
                    allow_legacy_schema_migration=True,
                )
            except RuntimeError as exc:
                raise ReconciliationError(str(exc)) from exc

            self._initialize(connection)
            if idempotency_state != "absent":
                try:
                    SQLiteIdempotencyStore._initialize_schema(
                        connection,
                        allow_legacy_schema_migration=True,
                    )
                except RuntimeError as exc:
                    raise ReconciliationError(str(exc)) from exc
            self._assert_audit_outbox_integrity(
                connection,
                require_alert_marker=True,
            )
            connection.commit()

    @property
    def journal_mode(self) -> str:
        with self._connect() as connection:
            return str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def create_unknown(self, action: UnknownAction) -> ReconciliationHead:
        if not isinstance(action, UnknownAction):
            raise TypeError("action must be an UnknownAction")
        head = ReconciliationHead(
            action=action,
            state=ReconciliationState.UNKNOWN,
            revision=0,
            disposition=ReconciliationDisposition.BLOCKED_UNKNOWN,
            updated_at=action.attempted_at,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_idempotency_link(connection, action)
            try:
                connection.execute(
                    """
                    INSERT INTO reconciliation_heads(
                        execution_record_id, action_json, state, revision,
                        disposition, resolved_result_available,
                        resolved_result_json, updated_at
                    ) VALUES (?, ?, 'UNKNOWN', 0, 'blocked_unknown', 0, NULL, ?)
                    """,
                    (
                        action.execution_record_id,
                        _dump(action.to_dict()),
                        _timestamp_text(action.attempted_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ReconciliationConflictError(
                    "a reconciliation head already exists for this execution record"
                ) from exc
            enqueue_reconciliation_audit_outbox(
                connection, head, event_type="unknown_recorded"
            )
            connection.commit()
        return head

    def prepare_action(
        self, claim: "IdempotencyClaim", action: UnknownAction
    ) -> None:
        """Durably bind a pending idempotency execution to a safe probe descriptor.

        The action is persisted before the tool body can start.  A subsequent
        process crash can therefore turn an expired lease into an explicit
        UNKNOWN reconciliation record without retaining a caller idempotency key
        or any raw identity material.
        """

        self._validate_prepared_claim(claim, action)
        encoded = _dump(action.to_dict())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT action_json FROM reconciliation_prepared_actions
                WHERE execution_record_id = ?
                """,
                (claim.execution_record_id,),
            ).fetchone()
            if row is None:
                cursor = connection.execute(
                    """
                    INSERT INTO reconciliation_prepared_actions(
                        execution_record_id, action_json, prepared_at
                    )
                    SELECT ?, ?, ?
                    WHERE EXISTS (
                        SELECT 1 FROM idempotency_records
                        WHERE execution_record_id = ?
                          AND namespace = ? AND key = ? AND fingerprint = ?
                          AND owner_token = ? AND state = 'pending'
                    )
                    """,
                    (
                        claim.execution_record_id,
                        encoded,
                        _timestamp_text(action.attempted_at),
                        claim.execution_record_id,
                        claim.namespace,
                        claim.key,
                        claim.fingerprint,
                        claim.owner_token,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ReconciliationConflictError(
                        "idempotency ownership was lost before reconciliation preparation"
                    )
            elif row[0] != encoded:
                raise ReconciliationConflictError(
                    "a different reconciliation action is already prepared"
                )
            connection.commit()

    def record_unknown(
        self,
        claim: "IdempotencyClaim",
        action: UnknownAction,
        error: BaseException,
    ) -> ReconciliationHead:
        """Atomically persist an UNKNOWN idempotency outcome and its head.

        This boundary is intentionally owned by the co-located SQLite ledger.
        A caller cannot first commit an UNKNOWN authority row and then lose the
        reconciliation head during a process crash.
        """

        if not isinstance(action, UnknownAction):
            raise TypeError("action must be an UnknownAction")
        if not getattr(claim, "owner", False):
            raise ReconciliationConflictError(
                "only the current idempotency owner can record UNKNOWN"
            )
        if claim.execution_record_id != action.execution_record_id:
            raise ReconciliationValidationError(
                "unknown action execution record does not match the idempotency claim"
            )
        if claim.fingerprint != action.action_digest:
            raise ReconciliationValidationError(
                "unknown action digest does not match the idempotency claim"
            )
        if idempotency_namespace_digest(claim.namespace) != action.idempotency_namespace_digest:
            raise ReconciliationValidationError(
                "unknown action namespace does not match the idempotency claim"
            )
        if not claim.owner_token:
            raise ReconciliationValidationError(
                "durable idempotency claim must include an owner token"
            )

        now = datetime.now(timezone.utc)
        stored_error = f"{type(error).__name__}: execution outcome is unknown"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prepared = connection.execute(
                """
                SELECT action_json FROM reconciliation_prepared_actions
                WHERE execution_record_id = ?
                """,
                (claim.execution_record_id,),
            ).fetchone()
            if prepared is not None:
                persisted_action = UnknownAction.from_dict(json.loads(prepared[0]))
                self._validate_prepared_action_identity(persisted_action, action)
                action = persisted_action
            cursor = connection.execute(
                """
                UPDATE idempotency_records
                SET state = 'unknown', result_json = NULL, error = ?,
                    owner_token = NULL, lease_expires_at = NULL, updated_at = ?
                WHERE execution_record_id = ?
                  AND namespace = ? AND key = ? AND fingerprint = ?
                  AND owner_token = ? AND state = 'pending'
                """,
                (
                    stored_error,
                    _timestamp_text(now),
                    claim.execution_record_id,
                    claim.namespace,
                    claim.key,
                    claim.fingerprint,
                    claim.owner_token,
                ),
            )
            if cursor.rowcount != 1:
                raise ReconciliationConflictError(
                    "idempotency ownership was lost before UNKNOWN could be recorded"
                )
            try:
                connection.execute(
                    """
                    INSERT INTO reconciliation_heads(
                        execution_record_id, action_json, state, revision,
                        disposition, resolved_result_available,
                        resolved_result_json, updated_at
                    ) VALUES (?, ?, 'UNKNOWN', 0, 'blocked_unknown', 0, NULL, ?)
                    """,
                    (
                        action.execution_record_id,
                        _dump(action.to_dict()),
                        _timestamp_text(now),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ReconciliationConflictError(
                    "a reconciliation head already exists for this execution record"
                ) from exc
            head = ReconciliationHead(
                action=action,
                state=ReconciliationState.UNKNOWN,
                revision=0,
                disposition=ReconciliationDisposition.BLOCKED_UNKNOWN,
                updated_at=now,
            )
            enqueue_reconciliation_audit_outbox(
                connection, head, event_type="unknown_recorded"
            )
            connection.commit()

        from .registry import IdempotencyOutcomeUnknownError

        if not claim.future.done():
            claim.future.set_exception(
                IdempotencyOutcomeUnknownError(
                    stored_error, execution_record_id=claim.execution_record_id
                )
            )
            claim.future.exception()
        return head

    @staticmethod
    def _validate_prepared_claim(
        claim: "IdempotencyClaim", action: UnknownAction
    ) -> None:
        if not isinstance(action, UnknownAction):
            raise TypeError("action must be an UnknownAction")
        if not getattr(claim, "owner", False):
            raise ReconciliationConflictError(
                "only the current idempotency owner can prepare reconciliation"
            )
        if claim.execution_record_id != action.execution_record_id:
            raise ReconciliationValidationError(
                "prepared action execution record does not match the idempotency claim"
            )
        if claim.fingerprint != action.action_digest:
            raise ReconciliationValidationError(
                "prepared action digest does not match the idempotency claim"
            )
        if idempotency_namespace_digest(claim.namespace) != action.idempotency_namespace_digest:
            raise ReconciliationValidationError(
                "prepared action namespace does not match the idempotency claim"
            )
        if not claim.owner_token:
            raise ReconciliationValidationError(
                "durable idempotency claim must include an owner token"
            )

    @staticmethod
    def _validate_prepared_action_identity(
        prepared: UnknownAction, supplied: UnknownAction
    ) -> None:
        if (
            prepared.execution_record_id != supplied.execution_record_id
            or prepared.action_digest != supplied.action_digest
            or prepared.tool_name != supplied.tool_name
            or prepared.contract_id != supplied.contract_id
            or prepared.contract_version != supplied.contract_version
            or prepared.idempotency_namespace_digest
            != supplied.idempotency_namespace_digest
            or prepared.tenant_partition_digest != supplied.tenant_partition_digest
        ):
            raise ReconciliationValidationError(
                "prepared action identity does not match the UNKNOWN transition"
            )

    @staticmethod
    def _validate_idempotency_link(
        connection: sqlite3.Connection, action: UnknownAction
    ) -> None:
        table_exists = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'idempotency_records' COLLATE NOCASE
            """
        ).fetchone()
        if table_exists is None:
            return
        row = connection.execute(
            """
            SELECT namespace, fingerprint, state
            FROM idempotency_records
            WHERE execution_record_id = ?
            """,
            (action.execution_record_id,),
        ).fetchone()
        if row is None:
            raise ReconciliationConflictError(
                "execution record is absent from the colocated idempotency authority"
            )
        namespace, fingerprint, state = row
        if fingerprint != action.action_digest:
            raise ReconciliationValidationError(
                "unknown action digest does not match the idempotency authority"
            )
        if (
            idempotency_namespace_digest(namespace)
            != action.idempotency_namespace_digest
        ):
            raise ReconciliationValidationError(
                "unknown action namespace does not match the idempotency authority"
            )
        if state != "unknown":
            raise ReconciliationConflictError(
                "idempotency execution must be UNKNOWN before reconciliation starts"
            )

    def start_attempt(
        self,
        context: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        expected_revision: int,
    ) -> ReconciliationRecord:
        _validate_attempt(context, provider)
        return self._append_attempt(
            context.action.execution_record_id,
            context.action,
            expected_revision,
            ReconciliationEventKind.ATTEMPT_STARTED,
            datetime.now(timezone.utc),
            {
                "attempt_id": context.attempt_id,
                "deadline": _timestamp_text(context.deadline),
                "protocol_version": context.protocol_version,
                "provider_id": provider.provider_id,
            },
            audit_event_type="attempt_started",
            provider=provider,
        )

    def finish_attempt(
        self,
        context: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        outcome: ReconciliationAttemptOutcome,
        expected_revision: int,
        *,
        finding: ReconciliationFinding | None = None,
        error: str | None = None,
        finished_at: datetime | None = None,
    ) -> ReconciliationRecord:
        _validate_attempt(context, provider)
        payload, occurred_at = _finish_payload(
            context, provider, outcome, finding, error, finished_at
        )
        return self._append_attempt(
            context.action.execution_record_id,
            context.action,
            expected_revision,
            ReconciliationEventKind.ATTEMPT_FINISHED,
            occurred_at,
            payload,
            audit_event_type="attempt_finished",
            provider=provider,
            outcome=outcome,
            finding=finding,
        )

    def recover_unfinished_attempts(
        self,
        execution_record_id: str,
        *,
        now: datetime | None = None,
    ) -> ReconciliationHead | None:
        """Close only expired unmatched attempts, then quarantine the action.

        The provider deadline is a durable lease for the recorded read-only
        attempt. A concurrent or restarted runtime observes that lease and
        must not issue another probe while it remains valid. After expiry, a
        synthetic terminal outcome plus a RECOVERY transition preserves a
        complete evidence chain without inferring the external side effect.
        """

        recovered_at = _require_timestamp(now or datetime.now(timezone.utc))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            head = self._current(connection, execution_record_id)
            attempts = _unfinished_attempt_contexts(
                head.action,
                self._attempt_records(connection, execution_record_id),
            )
            if not attempts:
                connection.commit()
                return None
            if head.state is not ReconciliationState.UNKNOWN:
                raise ReconciliationError(
                    "a non-UNKNOWN reconciliation head has an unfinished attempt"
                )
            if any(context.deadline > recovered_at for _, context, _ in attempts):
                connection.commit()
                return head

            for _start, context, provider in attempts:
                payload, occurred_at = _finish_payload(
                    context,
                    provider,
                    ReconciliationAttemptOutcome.RECOVERY_REQUIRED,
                    None,
                    "provider attempt expired before a terminal record was persisted",
                    recovered_at,
                )
                _record, head = self._append_attempt_in_transaction(
                    connection,
                    head,
                    ReconciliationEventKind.ATTEMPT_FINISHED,
                    occurred_at,
                    payload,
                    audit_event_type="attempt_recovery_recorded",
                    provider=provider,
                    outcome=ReconciliationAttemptOutcome.RECOVERY_REQUIRED,
                )

            transition = _recovery_transition(head, len(attempts), recovered_at)
            _validate_transition_evidence(head.action, transition)
            record, updated = _transition_record(head, transition)
            cursor = connection.execute(
                """
                UPDATE reconciliation_heads
                SET state = ?, revision = ?, disposition = ?,
                    resolved_result_available = ?, resolved_result_json = ?,
                    updated_at = ?
                WHERE execution_record_id = ? AND state = ? AND revision = ?
                """,
                (
                    updated.state.value,
                    updated.revision,
                    updated.disposition.value,
                    int(updated.resolved_result_available),
                    _optional_dump(
                        updated.resolved_result, updated.resolved_result_available
                    ),
                    _timestamp_text(updated.updated_at),
                    execution_record_id,
                    head.state.value,
                    head.revision,
                ),
            )
            if cursor.rowcount != 1:
                raise ReconciliationConflictError(
                    "reconciliation revision changed before recovery transition"
                )
            self._insert_event(connection, record)
            self._update_idempotency_disposition(connection, updated)
            enqueue_reconciliation_audit_outbox(
                connection,
                updated,
                event_type="recovery_transition_recorded",
                evidence_kind=transition.evidence_kind,
                evidence=transition.evidence,
            )
            connection.commit()
            return updated

    def compare_and_append_transition(
        self,
        execution_record_id: str,
        expected_state: ReconciliationState,
        expected_revision: int,
        decision: ReconciliationFinding | ManualResolution,
        *,
        provider: ProviderDescriptor | None = None,
        attempt_id: str | None = None,
    ) -> ReconciliationHead:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            head = self._current(connection, execution_record_id)
            _require_cas(head, expected_state, expected_revision)
            transition = _build_transition(
                head, decision, provider=provider, attempt_id=attempt_id
            )
            if isinstance(decision, ReconciliationFinding):
                _require_finished_attempt(
                    self._attempt_records(connection, execution_record_id),
                    attempt_id,
                    provider,
                    decision,
                )
            _validate_transition_evidence(head.action, transition)
            record, updated = _transition_record(head, transition)
            cursor = connection.execute(
                """
                UPDATE reconciliation_heads
                SET state = ?, revision = ?, disposition = ?,
                    resolved_result_available = ?, resolved_result_json = ?,
                    updated_at = ?
                WHERE execution_record_id = ? AND state = ? AND revision = ?
                """,
                (
                    updated.state.value,
                    updated.revision,
                    updated.disposition.value,
                    int(updated.resolved_result_available),
                    _optional_dump(
                        updated.resolved_result, updated.resolved_result_available
                    ),
                    _timestamp_text(updated.updated_at),
                    execution_record_id,
                    expected_state.value,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise ReconciliationConflictError(
                    "reconciliation state or revision changed before append"
                )
            self._insert_event(connection, record)
            self._update_idempotency_disposition(connection, updated)
            enqueue_reconciliation_audit_outbox(
                connection,
                updated,
                event_type=(
                    "manual_transition_recorded"
                    if transition.source is ReconciliationTransitionSource.MANUAL
                    else (
                        "recovery_transition_recorded"
                        if transition.source is ReconciliationTransitionSource.RECOVERY
                        else "transition_recorded"
                    )
                ),
                provider=provider,
                attempt_id=attempt_id,
                outcome=(
                    ReconciliationAttemptOutcome.SUCCESS
                    if transition.source is ReconciliationTransitionSource.PROVIDER
                    else None
                ),
                evidence_kind=transition.evidence_kind,
                evidence=transition.evidence,
                operator_identity_digest=transition.operator_identity_digest,
            )
            connection.commit()
        return updated

    def current(self, execution_record_id: str) -> ReconciliationHead:
        with self._connect() as connection:
            return self._current(connection, execution_record_id)

    def history(self, execution_record_id: str) -> tuple[ReconciliationRecord, ...]:
        with self._connect() as connection:
            connection.execute("BEGIN DEFERRED")
            self._current(connection, execution_record_id)
            rows = connection.execute(
                """
                SELECT event_id, execution_record_id, revision, kind, state_before,
                       state_after, occurred_at, payload_json
                FROM reconciliation_events
                WHERE execution_record_id = ?
                ORDER BY revision
                """,
                (execution_record_id,),
            ).fetchall()
            connection.commit()
        return tuple(_record_from_row(row) for row in rows)

    def attempts(self, execution_record_id: str) -> tuple[ReconciliationRecord, ...]:
        return tuple(
            record
            for record in self.history(execution_record_id)
            if record.kind
            in {
                ReconciliationEventKind.ATTEMPT_STARTED,
                ReconciliationEventKind.ATTEMPT_FINISHED,
            }
        )

    def pending_audit_events(
        self,
        *,
        execution_record_id: str | None = None,
        limit: int = 128,
    ) -> tuple[ReconciliationAuditEnvelope, ...]:
        """Return immutable, not-yet-acknowledged audit envelopes in order."""

        if execution_record_id is not None:
            _require_execution_record_id(execution_record_id)
        if type(limit) is not int or not 1 <= limit <= 1_000:
            raise ValueError("audit outbox limit must be between 1 and 1000")
        where = """
            current.delivered_at IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM reconciliation_audit_outbox AS earlier
                WHERE earlier.execution_record_id = current.execution_record_id
                  AND earlier.delivered_at IS NULL
                  AND earlier.revision < current.revision
            )
        """
        parameters: list[Any] = []
        if execution_record_id is not None:
            where += " AND current.execution_record_id = ?"
            parameters.append(execution_record_id)
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT outbox_id, execution_record_id, revision, event_type,
                       event_json, event_digest, created_at, delivery_attempts
                FROM reconciliation_audit_outbox AS current
                WHERE {where}
                ORDER BY execution_record_id, revision, event_type
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            for row in rows:
                if self._audit_delivery_alert_candidate(
                    created_at=str(row[6]),
                    delivery_attempts=int(row[7]),
                ):
                    try:
                        self._warn_if_audit_delivery_is_stalled(
                            connection,
                            str(row[1]),
                        )
                    except sqlite3.DatabaseError:
                        # The marker is best-effort observability. A competing
                        # writer must not make durable outbox reads unavailable;
                        # the next poll can claim and emit the warning instead.
                        _LOGGER.warning(
                            "reconciliation audit stall alert could not be recorded",
                            exc_info=True,
                        )
        return tuple(_audit_envelope_from_row(row) for row in rows)

    def mark_audit_event_delivered(self, outbox_id: str) -> None:
        _require_execution_record_id(outbox_id)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE reconciliation_audit_outbox
                SET delivered_at = ?, last_error_class = NULL
                WHERE outbox_id = ? AND delivered_at IS NULL
                """,
                (_timestamp_text(datetime.now(timezone.utc)), outbox_id),
            )
            if cursor.rowcount == 0:
                exists = connection.execute(
                    "SELECT 1 FROM reconciliation_audit_outbox WHERE outbox_id = ?",
                    (outbox_id,),
                ).fetchone()
                if exists is None:
                    raise ReconciliationNotFoundError(
                        "reconciliation audit outbox event is not present"
                    )
            connection.commit()

    def _audit_delivery_alert_candidate(
        self,
        *,
        created_at: str,
        delivery_attempts: int,
    ) -> bool:
        if delivery_attempts >= self._audit_delivery_alert_attempts:
            return True
        oldest_pending_at = _parse_timestamp(created_at)
        oldest_age_seconds = max(
            0.0,
            (datetime.now(timezone.utc) - oldest_pending_at).total_seconds(),
        )
        return oldest_age_seconds >= self._audit_delivery_alert_age_seconds

    def _warn_if_audit_delivery_is_stalled(
        self, connection: sqlite3.Connection, execution_record_id: str
    ) -> None:
        """Warn once per execution while a durable delivery outage is pending.

        The ledger never discards an outbox obligation because a sink is down.
        Operations still need an observable signal before retention pressure turns
        a recoverable delivery outage into an incident, so only lineage-safe
        counters and timestamps are emitted here.
        """

        row = connection.execute(
            """
            SELECT COUNT(*), MAX(delivery_attempts), MIN(created_at),
                   MAX(CASE WHEN alerted_at IS NOT NULL THEN 1 ELSE 0 END)
            FROM reconciliation_audit_outbox
            WHERE execution_record_id = ? AND delivered_at IS NULL
            """,
            (execution_record_id,),
        ).fetchone()
        assert row is not None
        pending_count = int(row[0])
        if pending_count == 0:
            return
        max_attempts = int(row[1])
        oldest_pending_at = _parse_timestamp(str(row[2]))
        oldest_age_seconds = max(
            0.0,
            (datetime.now(timezone.utc) - oldest_pending_at).total_seconds(),
        )
        if not self._audit_delivery_alert_candidate(
            created_at=str(row[2]),
            delivery_attempts=max_attempts,
        ):
            return
        if bool(row[3]):
            return
        alerted_at = _timestamp_text(datetime.now(timezone.utc))
        claimed = connection.execute(
            """
            UPDATE reconciliation_audit_outbox
            SET alerted_at = ?
            WHERE execution_record_id = ?
              AND delivered_at IS NULL
              AND alerted_at IS NULL
            """,
            (alerted_at, execution_record_id),
        )
        if claimed.rowcount == 0:
            return
        _LOGGER.warning(
            "reconciliation audit delivery is stalled: "
            "execution_record_id=%s pending_events=%s max_delivery_attempts=%s "
            "oldest_pending_age_seconds=%.3f",
            execution_record_id,
            pending_count,
            max_attempts,
            oldest_age_seconds,
        )

    def record_audit_delivery_failure(
        self, outbox_id: str, error: BaseException
    ) -> None:
        _require_execution_record_id(outbox_id)
        error_class = type(error).__name__
        _require_identifier("reconciliation audit delivery error class", error_class)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE reconciliation_audit_outbox
                SET delivery_attempts = delivery_attempts + 1,
                    last_error_class = ?
                WHERE outbox_id = ? AND delivered_at IS NULL
                """,
                (error_class, outbox_id),
            )
            if cursor.rowcount == 0:
                exists = connection.execute(
                    "SELECT 1 FROM reconciliation_audit_outbox WHERE outbox_id = ?",
                    (outbox_id,),
                ).fetchone()
                if exists is None:
                    raise ReconciliationNotFoundError(
                        "reconciliation audit outbox event is not present"
                    )
            record = connection.execute(
                """
                SELECT execution_record_id, delivery_attempts, created_at
                FROM reconciliation_audit_outbox
                WHERE outbox_id = ?
                """,
                (outbox_id,),
            ).fetchone()
            assert record is not None
            if self._audit_delivery_alert_candidate(
                created_at=str(record[2]),
                delivery_attempts=int(record[1]),
            ):
                self._warn_if_audit_delivery_is_stalled(connection, str(record[0]))
            connection.commit()

    def _append_attempt(
        self,
        execution_record_id: str,
        action: UnknownAction,
        expected_revision: int,
        kind: ReconciliationEventKind,
        occurred_at: datetime,
        payload: Mapping[str, Any],
        *,
        audit_event_type: str | None = None,
        provider: ProviderDescriptor | None = None,
        outcome: ReconciliationAttemptOutcome | None = None,
        finding: ReconciliationFinding | None = None,
    ) -> ReconciliationRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            head = self._current(connection, execution_record_id)
            if head.action != action:
                raise ReconciliationValidationError(
                    "attempt context action does not match the persisted unknown action"
                )
            if (
                kind is ReconciliationEventKind.ATTEMPT_STARTED
                and head.state is not ReconciliationState.UNKNOWN
            ):
                raise InvalidReconciliationTransitionError(
                    "provider attempts are valid only while state is UNKNOWN"
                )
            _require_cas(head, head.state, expected_revision)
            _validate_attempt_append(
                self._attempt_records(connection, execution_record_id), kind, payload
            )
            record = ReconciliationRecord(
                event_id=_new_id(),
                execution_record_id=execution_record_id,
                revision=head.revision + 1,
                kind=kind,
                state_before=head.state,
                state_after=head.state,
                occurred_at=occurred_at,
                payload=payload,
            )
            cursor = connection.execute(
                """
                UPDATE reconciliation_heads
                SET revision = ?, updated_at = ?
                WHERE execution_record_id = ? AND state = ? AND revision = ?
                """,
                (
                    record.revision,
                    _timestamp_text(record.occurred_at),
                    execution_record_id,
                    head.state.value,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise ReconciliationConflictError(
                    "reconciliation revision changed before attempt append"
                )
            self._insert_event(connection, record)
            if audit_event_type is not None:
                updated = ReconciliationHead(
                    action=head.action,
                    state=head.state,
                    revision=record.revision,
                    disposition=head.disposition,
                    updated_at=record.occurred_at,
                    resolved_result_available=head.resolved_result_available,
                    resolved_result=head.resolved_result,
                )
                enqueue_reconciliation_audit_outbox(
                    connection,
                    updated,
                    event_type=audit_event_type,
                    provider=provider,
                    attempt_id=payload.get("attempt_id"),
                    outcome=outcome,
                    finding=finding,
                )
            connection.commit()
            return record

    def _append_attempt_in_transaction(
        self,
        connection: sqlite3.Connection,
        head: ReconciliationHead,
        kind: ReconciliationEventKind,
        occurred_at: datetime,
        payload: Mapping[str, Any],
        *,
        audit_event_type: str | None = None,
        provider: ProviderDescriptor | None = None,
        outcome: ReconciliationAttemptOutcome | None = None,
        finding: ReconciliationFinding | None = None,
    ) -> tuple[ReconciliationRecord, ReconciliationHead]:
        """Append one attempt event inside the caller's existing transaction."""

        if (
            kind is ReconciliationEventKind.ATTEMPT_STARTED
            and head.state is not ReconciliationState.UNKNOWN
        ):
            raise InvalidReconciliationTransitionError(
                "provider attempts are valid only while state is UNKNOWN"
            )
        _validate_attempt_append(
            self._attempt_records(connection, head.execution_record_id), kind, payload
        )
        record = ReconciliationRecord(
            event_id=_new_id(),
            execution_record_id=head.execution_record_id,
            revision=head.revision + 1,
            kind=kind,
            state_before=head.state,
            state_after=head.state,
            occurred_at=occurred_at,
            payload=payload,
        )
        cursor = connection.execute(
            """
            UPDATE reconciliation_heads
            SET revision = ?, updated_at = ?
            WHERE execution_record_id = ? AND state = ? AND revision = ?
            """,
            (
                record.revision,
                _timestamp_text(record.occurred_at),
                head.execution_record_id,
                head.state.value,
                head.revision,
            ),
        )
        if cursor.rowcount != 1:
            raise ReconciliationConflictError(
                "reconciliation revision changed before attempt append"
            )
        self._insert_event(connection, record)
        updated = ReconciliationHead(
            action=head.action,
            state=head.state,
            revision=record.revision,
            disposition=head.disposition,
            updated_at=record.occurred_at,
            resolved_result_available=head.resolved_result_available,
            resolved_result=head.resolved_result,
        )
        if audit_event_type is not None:
            enqueue_reconciliation_audit_outbox(
                connection,
                updated,
                event_type=audit_event_type,
                provider=provider,
                attempt_id=payload.get("attempt_id"),
                outcome=outcome,
                finding=finding,
            )
        return record, updated

    @staticmethod
    def _attempt_records(
        connection: sqlite3.Connection, execution_record_id: str
    ) -> tuple[ReconciliationRecord, ...]:
        rows = connection.execute(
            """
            SELECT event_id, execution_record_id, revision, kind, state_before,
                   state_after, occurred_at, payload_json
            FROM reconciliation_events
            WHERE execution_record_id = ?
              AND kind IN ('ATTEMPT_STARTED', 'ATTEMPT_FINISHED')
            ORDER BY revision
            """,
            (execution_record_id,),
        ).fetchall()
        return tuple(_record_from_row(row) for row in rows)

    def _current(
        self, connection: sqlite3.Connection, execution_record_id: str
    ) -> ReconciliationHead:
        _require_execution_record_id(execution_record_id)
        row = connection.execute(
            """
            SELECT action_json, state, revision, disposition,
                   resolved_result_available, resolved_result_json, updated_at
            FROM reconciliation_heads WHERE execution_record_id = ?
            """,
            (execution_record_id,),
        ).fetchone()
        if row is None:
            raise ReconciliationNotFoundError(
                f"unknown execution record {execution_record_id!r}"
            )
        (
            action_json,
            state,
            revision,
            disposition,
            result_available,
            result_json,
            updated_at,
        ) = row
        return ReconciliationHead(
            action=UnknownAction.from_dict(json.loads(action_json)),
            state=ReconciliationState(state),
            revision=revision,
            disposition=ReconciliationDisposition(disposition),
            updated_at=_parse_timestamp(updated_at),
            resolved_result_available=bool(result_available),
            resolved_result=(None if not result_available else json.loads(result_json)),
        )

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection, record: ReconciliationRecord
    ) -> None:
        connection.execute(
            """
            INSERT INTO reconciliation_events(
                event_id, execution_record_id, revision, kind, state_before,
                state_after, occurred_at, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.event_id,
                record.execution_record_id,
                record.revision,
                record.kind.value,
                record.state_before.value,
                record.state_after.value,
                _timestamp_text(record.occurred_at),
                _dump(thaw(record.payload)),
            ),
        )

    @staticmethod
    def _update_idempotency_disposition(
        connection: sqlite3.Connection, head: ReconciliationHead
    ) -> None:
        table_exists = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'idempotency_records' COLLATE NOCASE
            """
        ).fetchone()
        if table_exists is None:
            return
        state, result_json, error = _idempotency_disposition(head)
        cursor = connection.execute(
            """
            UPDATE idempotency_records
            SET state = ?, result_json = ?, error = ?, owner_token = NULL,
                lease_expires_at = NULL, updated_at = ?
            WHERE execution_record_id = ? AND state IN ('unknown', 'manual_review')
            """,
            (
                state,
                result_json,
                error,
                _timestamp_text(head.updated_at),
                head.execution_record_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ReconciliationConflictError(
                "idempotency authority did not match the reconciliation execution"
            )

    def _preflight_reconciliation_schema(self) -> None:
        """Validate an existing reconciliation authority before any schema write."""

        with self._connect() as connection:
            self._validate_reconciliation_schema(connection)

    def _validate_reconciliation_schema(self, connection: sqlite3.Connection) -> None:
        """Validate the pre-existing reconciliation authority without writing."""

        schema_exists = (
            connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'reconciliation_schema' COLLATE NOCASE
                """
            ).fetchone()
            is not None
        )
        existing_core_tables = self._existing_core_tables(connection)
        if not schema_exists:
            if existing_core_tables:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: version table is missing "
                    f"while core tables exist {sorted(existing_core_tables)!r}"
                )
            return

        self._assert_version_table_integrity(connection)
        version_row = connection.execute(
            "SELECT version FROM reconciliation_schema WHERE singleton = 1"
        ).fetchone()
        if version_row is None:
            raise ReconciliationError(
                "reconciliation schema integrity failure: version row is missing"
            )
        version = version_row[0]
        if version not in {0, 1, 2, 3, 4, _RECONCILIATION_SCHEMA_VERSION}:
            raise ReconciliationError(f"unsupported reconciliation schema version {version}")
        if version == 0 and existing_core_tables:
            raise ReconciliationError(
                "reconciliation schema integrity failure: version 0 is inconsistent "
                f"with existing core tables {sorted(existing_core_tables)!r}"
            )
        if version < 4 and "reconciliation_audit_outbox" in existing_core_tables:
            raise ReconciliationError(
                "reconciliation schema integrity failure: pre-outbox schema version "
                "cannot declare a transactional audit outbox"
            )
        if version in _RECONCILIATION_LEGACY_CORE_TABLES:
            if not self._allow_legacy_schema_migration:
                raise ReconciliationError(
                    "pre-outbox reconciliation schema requires an explicit "
                    "controlled migration via SQLiteReconciliationLedger.migrate_legacy"
                )
            self._assert_legacy_schema_integrity(
                connection,
                version=version,
                existing_core_tables=existing_core_tables,
            )
        if version >= 4:
            self._assert_audit_outbox_integrity(
                connection,
                require_alert_marker=version >= 5,
            )

    def _preflight_idempotency_schema(self) -> bool:
        """Return whether a validated legacy idempotency upgrade is required."""

        with self._connect() as connection:
            state = self._validate_idempotency_schema(connection)
        return state == "legacy"

    def _validate_idempotency_schema(self, connection: sqlite3.Connection) -> str:
        """Validate the colocated idempotency authority without writing to it."""

        from .registry import SQLiteIdempotencyStore

        try:
            return SQLiteIdempotencyStore._preflight_schema(
                connection,
                allow_legacy_schema_migration=self._allow_legacy_schema_migration,
            )
        except RuntimeError as exc:
            raise ReconciliationError(str(exc)) from exc

    def _initialize(self, connection: sqlite3.Connection | None = None) -> None:
        owns_transaction = connection is None
        initialization = (
            initialize_sqlite(
                self.path,
                self.timeout_seconds,
                journal_mode=self._journal_mode,
            )
            if owns_transaction
            else nullcontext(connection)
        )
        with initialization as connection:
            if owns_transaction:
                connection.execute("BEGIN IMMEDIATE")
            # The initial read-only preflight is intentionally repeated after
            # acquiring the initializer lock and transaction.  This closes the
            # gap in which another process could introduce a legacy or corrupt
            # idempotency authority between normal construction's preflight and
            # the first reconciliation schema write.
            self._validate_idempotency_schema(connection)
            schema_exists = (
                connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'reconciliation_schema' COLLATE NOCASE
                    """
                ).fetchone()
                is not None
            )
            existing_core_tables = self._existing_core_tables(connection)
            if not schema_exists and existing_core_tables:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: version table is missing "
                    f"while core tables exist {sorted(existing_core_tables)!r}"
                )
            if schema_exists:
                self._assert_version_table_integrity(connection)
            _create_reconciliation_table(connection, "reconciliation_schema")
            self._assert_version_table_integrity(connection)
            version_row = connection.execute(
                "SELECT version FROM reconciliation_schema WHERE singleton = 1"
            ).fetchone()
            if version_row is None and schema_exists:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: version row is missing"
                )
            version = 0 if version_row is None else version_row[0]
            if version not in {0, 1, 2, 3, 4, _RECONCILIATION_SCHEMA_VERSION}:
                raise ReconciliationError(
                    f"unsupported reconciliation schema version {version}"
                )
            if version == 0 and existing_core_tables:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: version 0 is inconsistent "
                    f"with existing core tables {sorted(existing_core_tables)!r}"
                )
            if version < 4 and "reconciliation_audit_outbox" in existing_core_tables:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: pre-outbox schema version "
                    "cannot declare a transactional audit outbox"
                )
            if version in _RECONCILIATION_LEGACY_CORE_TABLES:
                if not self._allow_legacy_schema_migration:
                    raise ReconciliationError(
                        "pre-outbox reconciliation schema requires an explicit "
                        "controlled migration via SQLiteReconciliationLedger.migrate_legacy"
                    )
                self._assert_legacy_schema_integrity(
                    connection,
                    version=version,
                    existing_core_tables=existing_core_tables,
                )
            if version >= 4:
                self._assert_audit_outbox_integrity(
                    connection,
                    require_alert_marker=version >= 5,
                )
            for table_name in (
                "reconciliation_heads",
                "reconciliation_events",
                "reconciliation_prepared_actions",
                "reconciliation_audit_outbox",
            ):
                _create_reconciliation_table(connection, table_name)
            outbox_columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(reconciliation_audit_outbox)"
                )
            }
            if "alerted_at" not in outbox_columns:
                self._suspend_unbound_prepared_action_guard_for_schema_ddl(connection)
                connection.execute(
                    "ALTER TABLE reconciliation_audit_outbox ADD COLUMN alerted_at TEXT"
                )
            if version == 4:
                self._normalize_legacy_snapshot_enqueue_times(connection)
            for trigger_name in (
                "reconciliation_events_no_update",
                "reconciliation_events_no_delete",
                "reconciliation_prepared_actions_no_update",
                "reconciliation_audit_outbox_immutable",
                "reconciliation_audit_outbox_no_delete",
            ):
                _create_reconciliation_trigger(connection, trigger_name)
            connection.execute(
                """
                DROP TRIGGER IF EXISTS reconciliation_prepared_actions_no_delete
                """
            )
            _create_reconciliation_trigger(
                connection,
                "reconciliation_prepared_actions_delete_guard",
            )
            _create_reconciliation_pending_index(connection)
            if version < 4:
                self._backfill_legacy_audit_outbox(connection)
            connection.execute(
                """
                INSERT INTO reconciliation_schema(singleton, version)
                VALUES (1, ?)
                ON CONFLICT(singleton) DO UPDATE SET version = excluded.version
                """,
                (_RECONCILIATION_SCHEMA_VERSION,),
            )
            stored_version = connection.execute(
                "SELECT version FROM reconciliation_schema WHERE singleton = 1"
            ).fetchone()
            if (
                stored_version is None
                or stored_version[0] != _RECONCILIATION_SCHEMA_VERSION
            ):
                raise ReconciliationError(
                    "reconciliation schema integrity failure: version update did not "
                    "persist the released schema version"
                )
            self._assert_audit_outbox_integrity(
                connection,
                require_alert_marker=True,
            )
            if owns_transaction:
                connection.commit()

    @staticmethod
    def _existing_core_tables(connection: sqlite3.Connection) -> set[str]:
        return {
            str(row[0]).lower()
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND lower(name) IN (
                    'reconciliation_heads',
                    'reconciliation_events',
                    'reconciliation_prepared_actions',
                    'reconciliation_audit_outbox'
                )
                """
            )
        }

    @staticmethod
    def _assert_version_table_integrity(connection: sqlite3.Connection) -> None:
        table = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table'
              AND name = 'reconciliation_schema' COLLATE NOCASE
            """
        ).fetchone()
        if table is None or table[0] is None:
            raise ReconciliationError(
                "reconciliation schema integrity failure: version table definition is missing"
            )
        columns = {
            str(row[1]): row
            for row in connection.execute("PRAGMA table_info(reconciliation_schema)")
        }
        if {"singleton", "version"} - set(columns):
            raise ReconciliationError(
                "reconciliation schema integrity failure: version table columns are invalid"
            )
        if int(columns["singleton"][5]) != 1 or int(columns["version"][3]) != 1:
            raise ReconciliationError(
                "reconciliation schema integrity failure: version table constraints are invalid"
            )
        if _normalize_schema_sql(str(table[0])) != _normalize_schema_sql(
            _RECONCILIATION_TABLE_DDL["reconciliation_schema"]
        ):
            raise ReconciliationError(
                "reconciliation schema integrity failure: version table definition is invalid"
            )

    @staticmethod
    def _persistent_triggers_for_tables(
        connection: sqlite3.Connection,
        table_names: frozenset[str] | set[str],
    ) -> dict[str, tuple[str, str]]:
        normalized_tables = tuple(sorted(name.lower() for name in table_names))
        placeholders = ", ".join("?" for _ in normalized_tables)
        return {
            str(row[0]).lower(): (str(row[1]), str(row[2]))
            for row in connection.execute(
                """
                SELECT name, type, sql FROM sqlite_master
                WHERE type = 'trigger' AND lower(tbl_name) IN (%s)
                """
                % placeholders,
                normalized_tables,
            )
        }

    @staticmethod
    def _explicit_indexes_for_tables(
        connection: sqlite3.Connection,
        table_names: frozenset[str] | set[str],
    ) -> dict[str, str]:
        normalized_tables = tuple(sorted(name.lower() for name in table_names))
        placeholders = ", ".join("?" for _ in normalized_tables)
        return {
            str(row[0]).lower(): str(row[1])
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'index'
                  AND sql IS NOT NULL
                  AND lower(tbl_name) IN (%s)
                """
                % placeholders,
                normalized_tables,
            )
        }

    @staticmethod
    def _assert_legacy_schema_integrity(
        connection: sqlite3.Connection,
        *,
        version: int,
        existing_core_tables: set[str],
    ) -> None:
        """Verify the complete pre-outbox authority set before an opt-in upgrade."""

        expected_tables = _RECONCILIATION_LEGACY_CORE_TABLES[version]
        if existing_core_tables != expected_tables:
            raise ReconciliationError(
                "reconciliation schema integrity failure: pre-outbox authority "
                f"tables are invalid for version {version}: "
                f"expected {sorted(expected_tables)!r}, found "
                f"{sorted(existing_core_tables)!r}"
            )
        for table_name in expected_tables:
            table = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'table' AND name = ? COLLATE NOCASE
                """,
                (table_name,),
            ).fetchone()
            if table is None or table[0] is None or _normalize_schema_sql(
                str(table[0])
            ) != _normalize_schema_sql(_RECONCILIATION_TABLE_DDL[table_name]):
                raise ReconciliationError(
                    "reconciliation schema integrity failure: pre-outbox table "
                    f"definition differs for {table_name!r}"
                )

        expected_triggers = {
            "reconciliation_events_no_update",
            "reconciliation_events_no_delete",
        }
        if version >= 2:
            expected_triggers.update(
                {
                    "reconciliation_prepared_actions_no_update",
                    "reconciliation_prepared_actions_delete_guard",
                }
            )
        objects = SQLiteReconciliationLedger._persistent_triggers_for_tables(
            connection,
            expected_tables | {"reconciliation_schema"},
        )
        if set(objects) != expected_triggers or any(
            kind != "trigger" for kind, _ in objects.values()
        ):
            raise ReconciliationError(
                "reconciliation schema integrity failure: pre-outbox guards are invalid"
            )
        for trigger_name in expected_triggers:
            SQLiteReconciliationLedger._assert_trigger_contract(
                objects,
                trigger_name,
                expected_definition=_RECONCILIATION_TRIGGER_DDL[trigger_name],
            )
        if connection.execute("PRAGMA foreign_key_check(reconciliation_events)").fetchone():
            raise ReconciliationError(
                "reconciliation schema integrity failure: foreign-key check failed "
                "for 'reconciliation_events'"
            )

    @staticmethod
    def _normalize_legacy_snapshot_enqueue_times(
        connection: sqlite3.Connection,
    ) -> None:
        """Correct v4 snapshot enqueue metadata during the controlled v5 upgrade.

        v4 used the lineage timestamp for ``created_at``.  A migration snapshot
        did not exist at that historical time, so an unattempted snapshot could
        immediately satisfy the delivery-age alert threshold on upgrade.  Its
        payload retains the historical lineage timestamp; only the mutable
        delivery-queue enqueue timestamp is corrected here.
        """

        pending_snapshots = connection.execute(
            """
            SELECT 1 FROM reconciliation_audit_outbox
            WHERE event_type = 'migration_snapshot_recorded'
              AND delivered_at IS NULL
              AND delivery_attempts = 0
              AND last_error_class IS NULL
            LIMIT 1
            """
        ).fetchone()
        if pending_snapshots is None:
            return
        # The immutable trigger is restored in this same BEGIN IMMEDIATE
        # transaction. SQLite rolls back both DDL and the metadata rewrite if
        # initialization fails before commit.
        connection.execute(
            "DROP TRIGGER IF EXISTS reconciliation_audit_outbox_immutable"
        )
        connection.execute(
            """
            UPDATE reconciliation_audit_outbox
            SET created_at = ?
            WHERE event_type = 'migration_snapshot_recorded'
              AND delivered_at IS NULL
              AND delivery_attempts = 0
              AND last_error_class IS NULL
            """,
            (_timestamp_text(datetime.now(timezone.utc)),),
        )

    @staticmethod
    def _suspend_unbound_prepared_action_guard_for_schema_ddl(
        connection: sqlite3.Connection,
    ) -> None:
        """Avoid SQLite reparsing an optional authority table during an upgrade.

        A standalone ledger is valid before it is paired with an idempotency
        store. SQLite allows the retention trigger to be created in that state,
        but reparses its optional ``idempotency_records`` reference while an
        unrelated ``ALTER TABLE`` runs. The initializer recreates this exact
        guard later in the same exclusive transaction.
        """

        idempotency_table = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'idempotency_records' COLLATE NOCASE
            """
        ).fetchone()
        if idempotency_table is None:
            connection.execute(
                "DROP TRIGGER IF EXISTS reconciliation_prepared_actions_delete_guard"
            )

    @staticmethod
    def _assert_audit_outbox_integrity(
        connection: sqlite3.Connection,
        *,
        require_alert_marker: bool,
    ) -> None:
        """Refuse a partially restored versioned reconciliation schema.

        Version 4 made the outbox part of the authoritative recovery record.
        Its surrounding heads, append-only events, and prepared actions are
        equally authoritative.  A declared version 4 or 5 database must not be
        "healed" by ``CREATE IF NOT EXISTS`` because that can conceal a lost
        recovery or delivery obligation.
        """

        tables = SQLiteReconciliationLedger._existing_core_tables(connection)
        if "reconciliation_audit_outbox" not in tables:
            raise ReconciliationError(
                "reconciliation schema integrity failure: audit outbox table is missing"
            )
        if missing_tables := _RECONCILIATION_CORE_TABLES - tables:
            raise ReconciliationError(
                "reconciliation schema integrity failure: core tables are missing "
                f"{sorted(missing_tables)!r}"
            )

        outbox_columns = (
            "outbox_id",
            "execution_record_id",
            "revision",
            "event_type",
            "event_json",
            "event_digest",
            "created_at",
            "delivery_attempts",
            "delivered_at",
            "last_error_class",
        )
        if require_alert_marker:
            outbox_columns += ("alerted_at",)
        outbox_definition = (
            _RECONCILIATION_TABLE_DDL["reconciliation_audit_outbox"]
            if require_alert_marker
            else _RECONCILIATION_V4_AUDIT_OUTBOX_DDL
        )
        table_contracts = {
            "reconciliation_heads": (
                _RECONCILIATION_TABLE_DDL["reconciliation_heads"],
                (
                    "execution_record_id",
                    "action_json",
                    "state",
                    "revision",
                    "disposition",
                    "resolved_result_available",
                    "resolved_result_json",
                    "updated_at",
                ),
                ("execution_record_id",),
                (
                    "execution_record_id",
                    "action_json",
                    "state",
                    "revision",
                    "disposition",
                    "resolved_result_available",
                    "updated_at",
                ),
            ),
            "reconciliation_events": (
                _RECONCILIATION_TABLE_DDL["reconciliation_events"],
                (
                    "event_id",
                    "execution_record_id",
                    "revision",
                    "kind",
                    "state_before",
                    "state_after",
                    "occurred_at",
                    "payload_json",
                ),
                ("event_id",),
                (
                    "event_id",
                    "execution_record_id",
                    "revision",
                    "kind",
                    "state_before",
                    "state_after",
                    "occurred_at",
                    "payload_json",
                ),
            ),
            "reconciliation_prepared_actions": (
                _RECONCILIATION_TABLE_DDL["reconciliation_prepared_actions"],
                ("execution_record_id", "action_json", "prepared_at"),
                ("execution_record_id",),
                ("execution_record_id", "action_json", "prepared_at"),
            ),
            "reconciliation_audit_outbox": (
                outbox_definition,
                outbox_columns,
                ("outbox_id",),
                (
                    "outbox_id",
                    "execution_record_id",
                    "revision",
                    "event_type",
                    "event_json",
                    "event_digest",
                    "created_at",
                    "delivery_attempts",
                ),
            ),
        }
        for (
            table_name,
            (
                expected_definition,
                columns,
                primary_key,
                required_not_null_columns,
            ),
        ) in table_contracts.items():
            SQLiteReconciliationLedger._assert_table_contract(
                connection,
                table_name,
                expected_definition=expected_definition,
                required_columns=columns,
                primary_key=primary_key,
                required_not_null_columns=required_not_null_columns,
            )
        SQLiteReconciliationLedger._assert_unique_constraint(
            connection,
            "reconciliation_events",
            ("execution_record_id", "revision"),
        )
        SQLiteReconciliationLedger._assert_unique_constraint(
            connection,
            "reconciliation_audit_outbox",
            ("execution_record_id", "revision", "event_type"),
        )
        SQLiteReconciliationLedger._assert_foreign_key(
            connection,
            "reconciliation_events",
            from_column="execution_record_id",
            target_table="reconciliation_heads",
            target_column="execution_record_id",
        )
        SQLiteReconciliationLedger._assert_foreign_key(
            connection,
            "reconciliation_audit_outbox",
            from_column="execution_record_id",
            target_table="reconciliation_heads",
            target_column="execution_record_id",
        )
        SQLiteReconciliationLedger._assert_reconciliation_foreign_keys(connection)

        trigger_objects = SQLiteReconciliationLedger._persistent_triggers_for_tables(
            connection,
            _RECONCILIATION_AUTHORITY_TABLES,
        )
        if set(trigger_objects) != set(_RECONCILIATION_TRIGGER_DDL) or any(
            kind != "trigger" for kind, _ in trigger_objects.values()
        ):
            raise ReconciliationError(
                "reconciliation schema integrity failure: reconciliation guards are "
                "incomplete or unexpected"
            )
        for trigger_name, expected_definition in _RECONCILIATION_TRIGGER_DDL.items():
            SQLiteReconciliationLedger._assert_trigger_contract(
                trigger_objects,
                trigger_name,
                expected_definition=expected_definition,
            )
        pending_indexes = tuple(
            index
            for index in connection.execute(
                "PRAGMA index_list(reconciliation_audit_outbox)"
            )
            if str(index[1]).lower() == "idx_reconciliation_audit_outbox_pending"
        )
        if (
            len(pending_indexes) != 1
            or int(pending_indexes[0][2]) != 0
            or int(pending_indexes[0][4]) != 0
        ):
            raise ReconciliationError(
                "reconciliation schema integrity failure: audit outbox pending "
                "index is invalid"
            )
        index_columns = tuple(
            str(row[2])
            for row in connection.execute(
                "PRAGMA index_info(idx_reconciliation_audit_outbox_pending)"
            )
        )
        if index_columns != ("delivered_at", "execution_record_id", "revision"):
            raise ReconciliationError(
                "reconciliation schema integrity failure: audit outbox pending "
                "index is invalid"
            )
        explicit_indexes = SQLiteReconciliationLedger._explicit_indexes_for_tables(
            connection,
            _RECONCILIATION_AUTHORITY_TABLES,
        )
        if set(explicit_indexes) != {"idx_reconciliation_audit_outbox_pending"}:
            raise ReconciliationError(
                "reconciliation schema integrity failure: reconciliation indexes are "
                "invalid or unexpected"
            )
        if _normalize_schema_sql(
            explicit_indexes["idx_reconciliation_audit_outbox_pending"]
        ) != _normalize_schema_sql(_RECONCILIATION_PENDING_INDEX_DDL):
            raise ReconciliationError(
                "reconciliation schema integrity failure: audit outbox pending "
                "index definition is invalid"
            )
        SQLiteReconciliationLedger._assert_audit_outbox_guards_enforced(
            connection,
            include_alert_marker=require_alert_marker,
        )

    @staticmethod
    def _assert_table_contract(
        connection: sqlite3.Connection,
        table_name: str,
        *,
        expected_definition: str,
        required_columns: tuple[str, ...],
        primary_key: tuple[str, ...],
        required_not_null_columns: tuple[str, ...],
    ) -> None:
        table = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = ? COLLATE NOCASE
            """,
            (table_name,),
        ).fetchone()
        if table is None or table[0] is None:
            raise ReconciliationError(
                "reconciliation schema integrity failure: core table definition is "
                f"missing for {table_name!r}"
            )
        if _normalize_schema_sql(str(table[0])) != _normalize_schema_sql(
            expected_definition
        ):
            raise ReconciliationError(
                "reconciliation schema integrity failure: core table definition differs "
                f"for {table_name!r}"
            )
        columns = {
            str(row[1]): row
            for row in connection.execute(f"PRAGMA table_info({table_name})")
        }
        if missing_columns := set(required_columns) - set(columns):
            raise ReconciliationError(
                "reconciliation schema integrity failure: core table columns are "
                f"missing from {table_name!r}: {sorted(missing_columns)!r}"
            )
        primary_key_columns = tuple(
            str(row[1])
            for row in sorted(
                columns.values(),
                key=lambda row: int(row[5]),
            )
            if int(row[5]) > 0
        )
        if primary_key_columns != primary_key:
            raise ReconciliationError(
                "reconciliation schema integrity failure: core table primary key is "
                f"invalid for {table_name!r}"
            )
        nullable_columns = [
            column
            for column in required_not_null_columns
            if int(columns[column][3]) != 1
        ]
        if nullable_columns:
            raise ReconciliationError(
                "reconciliation schema integrity failure: core table non-null "
                f"constraints are invalid for {table_name!r}: {nullable_columns!r}"
            )

    @staticmethod
    def _assert_unique_constraint(
        connection: sqlite3.Connection,
        table_name: str,
        expected_columns: tuple[str, ...],
    ) -> None:
        for index in connection.execute(f"PRAGMA index_list({table_name})"):
            if int(index[2]) != 1 or int(index[4]) != 0:
                continue
            index_name = str(index[1])
            columns = tuple(
                str(row[2])
                for row in connection.execute(f"PRAGMA index_info({index_name})")
            )
            if columns == expected_columns:
                return
        raise ReconciliationError(
            "reconciliation schema integrity failure: required unique constraint is "
            f"missing from {table_name!r}"
        )

    @staticmethod
    def _assert_foreign_key(
        connection: sqlite3.Connection,
        table_name: str,
        *,
        from_column: str,
        target_table: str,
        target_column: str,
    ) -> None:
        for foreign_key in connection.execute(f"PRAGMA foreign_key_list({table_name})"):
            if (
                str(foreign_key[2]) == target_table
                and str(foreign_key[3]) == from_column
                and str(foreign_key[4]) == target_column
            ):
                return
        raise ReconciliationError(
            "reconciliation schema integrity failure: required foreign key is "
            f"missing from {table_name!r}"
        )

    @staticmethod
    def _assert_reconciliation_foreign_keys(connection: sqlite3.Connection) -> None:
        for table_name in (
            "reconciliation_events",
            "reconciliation_audit_outbox",
        ):
            if connection.execute(
                f"PRAGMA foreign_key_check({table_name})"
            ).fetchone() is not None:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: foreign-key check failed "
                    f"for {table_name!r}"
                )

    @staticmethod
    def _assert_trigger_contract(
        objects: Mapping[str, tuple[str, str]],
        trigger_name: str,
        *,
        expected_definition: str,
    ) -> None:
        if _normalize_schema_sql(objects[trigger_name][1]) != _normalize_schema_sql(
            expected_definition
        ):
            raise ReconciliationError(
                "reconciliation schema integrity failure: guard definition differs "
                f"for {trigger_name!r}"
            )

    @staticmethod
    def _assert_audit_outbox_guards_enforced(
        connection: sqlite3.Connection,
        *,
        include_alert_marker: bool,
    ) -> None:
        """Probe immutable and retention guards without retaining a test row."""

        execution_record_id = f"schema-probe-{secrets.token_hex(16)}"
        outbox_id = f"schema-probe-{secrets.token_hex(16)}"
        now = _timestamp_text(datetime.now(timezone.utc))
        connection.execute("SAVEPOINT reconciliation_schema_guard_probe")
        try:
            connection.execute(
                """
                INSERT INTO reconciliation_heads(
                    execution_record_id, action_json, state, revision, disposition,
                    resolved_result_available, resolved_result_json, updated_at
                ) VALUES (?, '{}', 'UNKNOWN', 0, 'blocked_unknown', 0, NULL, ?)
                """,
                (execution_record_id, now),
            )
            alert_columns = ", alerted_at" if include_alert_marker else ""
            alert_values = ", NULL" if include_alert_marker else ""
            connection.execute(
                """
                INSERT INTO reconciliation_audit_outbox(
                    outbox_id, execution_record_id, revision, event_type, event_json,
                    event_digest, created_at, delivery_attempts, delivered_at,
                    last_error_class%s
                ) VALUES (?, ?, 0, 'schema_probe', '{}', ?, ?, 0, NULL, NULL%s)
                """
                % (alert_columns, alert_values),
                (
                    outbox_id,
                    execution_record_id,
                    hashlib.sha256(b"{}").hexdigest(),
                    now,
                ),
            )
            try:
                connection.execute(
                    "UPDATE reconciliation_audit_outbox SET event_json = '{\"x\":1}' "
                    "WHERE outbox_id = ?",
                    (outbox_id,),
                )
            except sqlite3.DatabaseError:
                pass
            else:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: audit outbox immutable "
                    "guard does not reject payload mutation"
                )
            try:
                connection.execute(
                    "DELETE FROM reconciliation_audit_outbox WHERE outbox_id = ?",
                    (outbox_id,),
                )
            except sqlite3.DatabaseError:
                pass
            else:
                raise ReconciliationError(
                    "reconciliation schema integrity failure: audit outbox retention "
                    "guard does not reject deletion"
                )
        except sqlite3.DatabaseError as exc:
            raise ReconciliationError(
                "reconciliation schema integrity failure: audit outbox guard probe failed"
            ) from exc
        finally:
            connection.execute("ROLLBACK TO reconciliation_schema_guard_probe")
            connection.execute("RELEASE reconciliation_schema_guard_probe")

    def _backfill_legacy_audit_outbox(self, connection: sqlite3.Connection) -> None:
        """Establish an auditable migration boundary for pre-outbox records.

        Earlier ledger versions had durable heads and events but no transactional
        audit outbox.  Reconstructing historical provider evidence would be
        misleading, so each entirely untracked execution receives one explicit
        current-state snapshot.  The snapshot is committed with the v4 schema
        upgrade and makes lease recovery before the upgrade visible to future
        audit delivery without inventing historical event semantics.
        """

        rows = connection.execute(
            "SELECT execution_record_id FROM reconciliation_heads"
        ).fetchall()
        for (execution_record_id,) in rows:
            existing = connection.execute(
                """
                SELECT 1 FROM reconciliation_audit_outbox
                WHERE execution_record_id = ?
                LIMIT 1
                """,
                (execution_record_id,),
            ).fetchone()
            if existing is not None:
                continue
            head = self._current(connection, execution_record_id)
            enqueue_reconciliation_audit_outbox(
                connection,
                head,
                event_type="migration_snapshot_recorded",
            )

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.path, self.timeout_seconds)


def idempotency_namespace_digest(namespace: str) -> str:
    _require_identifier("idempotency namespace", namespace)
    import hashlib

    return hashlib.sha256(
        canonical_json_bytes(
            {
                "domain": "arg.idempotency-namespace",
                "version": 1,
                "namespace": namespace,
            },
            label="idempotency namespace",
        )
    ).hexdigest()


def tenant_partition_digest(tenant: str) -> str:
    """Return a domain-separated non-reversible tenant partition identifier."""

    if type(tenant) is not str or not tenant:
        raise ReconciliationValidationError("tenant must be a non-empty string")
    import hashlib

    return hashlib.sha256(
        canonical_json_bytes(
            {
                "domain": "arg.reconciliation-tenant-partition",
                "version": 1,
                "tenant": tenant,
            },
            label="reconciliation tenant partition",
        )
    ).hexdigest()


def enqueue_reconciliation_audit_outbox(
    connection: sqlite3.Connection,
    head: ReconciliationHead,
    *,
    event_type: str,
    provider: ProviderDescriptor | None = None,
    attempt_id: str | None = None,
    outcome: ReconciliationAttemptOutcome | None = None,
    finding: ReconciliationFinding | None = None,
    evidence_kind: str | None = None,
    evidence: Mapping[str, Any] | None = None,
    operator_identity_digest: str | None = None,
) -> str:
    """Atomically enqueue a lineage-only audit event for a ledger mutation.

    Callers must use the same SQLite transaction that mutates the reconciliation
    state.  The payload is deliberately constructed from fixed allowlisted
    fields; raw provider evidence, raw tenant identities, and idempotency keys
    never enter the delivery queue.
    """

    if not isinstance(head, ReconciliationHead):
        raise TypeError("head must be a ReconciliationHead")
    _require_identifier("reconciliation audit event type", event_type)
    if provider is not None and not isinstance(provider, ProviderDescriptor):
        raise TypeError("provider must be a ProviderDescriptor")
    if outcome is not None and not isinstance(outcome, ReconciliationAttemptOutcome):
        raise TypeError("outcome must be a ReconciliationAttemptOutcome")
    if finding is not None and not isinstance(finding, ReconciliationFinding):
        raise TypeError("finding must be a ReconciliationFinding")
    if finding is not None:
        evidence_kind = finding.evidence_kind
        evidence = finding.evidence
    if evidence is not None and not isinstance(evidence, Mapping):
        raise TypeError("evidence must be a mapping")
    if operator_identity_digest is not None:
        _require_digest("operator_identity_digest", operator_identity_digest)

    payload = _reconciliation_audit_payload(
        head,
        event_type=event_type,
        provider=provider,
        attempt_id=attempt_id,
        outcome=outcome,
        evidence_kind=evidence_kind,
        evidence=evidence,
        operator_identity_digest=operator_identity_digest,
    )
    encoded = _dump(payload)
    payload_digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    existing = connection.execute(
        """
        SELECT outbox_id, event_digest
        FROM reconciliation_audit_outbox
        WHERE execution_record_id = ? AND revision = ? AND event_type = ?
        """,
        (head.execution_record_id, head.revision, event_type),
    ).fetchone()
    if existing is not None:
        if existing[1] != payload_digest:
            raise ReconciliationConflictError(
                "reconciliation audit outbox event identity was reused with different content"
            )
        return str(existing[0])

    outbox_id = _new_id()
    connection.execute(
        """
        INSERT INTO reconciliation_audit_outbox(
            outbox_id, execution_record_id, revision, event_type, event_json,
            event_digest, created_at, delivery_attempts, delivered_at,
            last_error_class
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL)
        """,
        (
            outbox_id,
            head.execution_record_id,
            head.revision,
            event_type,
            encoded,
            payload_digest,
            _timestamp_text(datetime.now(timezone.utc)),
        ),
    )
    return outbox_id


def _reconciliation_audit_payload(
    head: ReconciliationHead,
    *,
    event_type: str,
    provider: ProviderDescriptor | None,
    attempt_id: str | None,
    outcome: ReconciliationAttemptOutcome | None,
    evidence_kind: str | None,
    evidence: Mapping[str, Any] | None,
    operator_identity_digest: str | None,
) -> dict[str, Any]:
    action = head.action
    provider_data = None
    if provider is not None:
        provider_data = {
            "provider_id": provider.provider_id,
            "protocol_version": str(provider.protocol_version),
            "supported_evidence_kinds": list(provider.supported_evidence_kinds),
        }
    evidence_digest = None
    if evidence is not None:
        evidence_digest = hashlib.sha256(
            canonical_json_bytes(
                {"evidence": thaw(evidence)},
                label="reconciliation audit evidence digest",
            )
        ).hexdigest()
    metadata = action.metadata
    trace_id = metadata.get("trace_id")
    request_id = metadata.get("request_id")
    return {
        "schema_version": 1,
        "timestamp": _timestamp_text(head.updated_at),
        "stage": "reconciliation",
        "event_type": event_type,
        "trace_id": trace_id if type(trace_id) is str else None,
        "request_id": request_id if type(request_id) is str else None,
        "execution_record_id": head.execution_record_id,
        "tool_name": action.tool_name,
        "contract_id": action.contract_id,
        "contract_version": action.contract_version,
        "action_digest": action.action_digest,
        "idempotency_namespace_digest": action.idempotency_namespace_digest,
        "tenant_partition_digest": action.tenant_partition_digest,
        "state": head.state.value,
        "revision": head.revision,
        "disposition": head.disposition.value,
        "provider": provider_data,
        "attempt_id": attempt_id,
        "outcome": None if outcome is None else outcome.value,
        "evidence_kind": evidence_kind,
        "evidence_digest": evidence_digest,
        "operator_identity_digest": operator_identity_digest,
    }


def new_execution_record_id() -> str:
    return _new_id()


def _validate_attempt(
    context: ReconciliationAttemptContext, provider: ProviderDescriptor
) -> None:
    if not isinstance(context, ReconciliationAttemptContext):
        raise TypeError("context must be a ReconciliationAttemptContext")
    if not isinstance(provider, ProviderDescriptor):
        raise TypeError("provider must be a ProviderDescriptor")
    if context.protocol_version != provider.protocol_version:
        raise ReconciliationValidationError(
            "provider and attempt protocol versions do not match"
        )


def _finish_payload(
    context: ReconciliationAttemptContext,
    provider: ProviderDescriptor,
    outcome: ReconciliationAttemptOutcome,
    finding: ReconciliationFinding | None,
    error: str | None,
    finished_at: datetime | None,
) -> tuple[dict[str, Any], datetime]:
    if not isinstance(outcome, ReconciliationAttemptOutcome):
        raise TypeError("outcome must be a ReconciliationAttemptOutcome")
    if finding is not None:
        if not isinstance(finding, ReconciliationFinding):
            raise TypeError("finding must be a ReconciliationFinding")
        if finding.evidence_kind not in provider.supported_evidence_kinds:
            raise ReconciliationValidationError(
                "provider does not support the finding evidence kind"
            )
    if outcome is ReconciliationAttemptOutcome.SUCCESS and finding is None:
        raise ReconciliationValidationError("successful attempt requires a finding")
    if outcome is not ReconciliationAttemptOutcome.SUCCESS and finding is not None:
        raise ReconciliationValidationError(
            "only a successful attempt may carry a conclusive finding"
        )
    if error is not None:
        _require_bounded_text("attempt error", error, _MAX_ERROR_BYTES)
    occurred_at = _require_timestamp(finished_at or datetime.now(timezone.utc))
    return (
        {
            "attempt_id": context.attempt_id,
            "provider_id": provider.provider_id,
            "outcome": outcome.value,
            "finding": None if finding is None else finding.to_dict(),
            "error": error,
        },
        occurred_at,
    )


def _validate_attempt_append(
    records: list[ReconciliationRecord] | tuple[ReconciliationRecord, ...],
    kind: ReconciliationEventKind,
    payload: Mapping[str, Any],
) -> None:
    attempt_id = payload["attempt_id"]
    matching = [
        record for record in records if record.payload.get("attempt_id") == attempt_id
    ]
    if kind is ReconciliationEventKind.ATTEMPT_STARTED:
        if matching:
            raise ReconciliationConflictError("attempt_id has already been persisted")
        if _unmatched_attempt_start_records(records):
            raise ReconciliationConflictError(
                "a previous reconciliation attempt is still unfinished"
            )
        return
    starts = [
        record
        for record in matching
        if record.kind is ReconciliationEventKind.ATTEMPT_STARTED
    ]
    finishes = [
        record
        for record in matching
        if record.kind is ReconciliationEventKind.ATTEMPT_FINISHED
    ]
    if len(starts) != 1 or finishes:
        raise ReconciliationConflictError(
            "attempt finish requires one unmatched persisted start"
        )
    if starts[0].payload.get("provider_id") != payload.get("provider_id"):
        raise ReconciliationValidationError(
            "attempt finish provider does not match the persisted start"
        )


def _unmatched_attempt_start_records(
    records: list[ReconciliationRecord] | tuple[ReconciliationRecord, ...],
) -> tuple[ReconciliationRecord, ...]:
    """Return durable starts that do not yet have a matching terminal record."""

    starts: dict[str, ReconciliationRecord] = {}
    finished: set[str] = set()
    for record in records:
        attempt_id = record.payload.get("attempt_id")
        if not isinstance(attempt_id, str):
            raise ReconciliationError("persisted reconciliation attempt lacks attempt_id")
        if record.kind is ReconciliationEventKind.ATTEMPT_STARTED:
            if attempt_id in starts:
                raise ReconciliationError("persisted reconciliation attempt_id is duplicated")
            starts[attempt_id] = record
        elif record.kind is ReconciliationEventKind.ATTEMPT_FINISHED:
            if attempt_id not in starts or attempt_id in finished:
                raise ReconciliationError(
                    "persisted reconciliation attempt finish has no unique start"
                )
            finished.add(attempt_id)
    return tuple(
        record for attempt_id, record in starts.items() if attempt_id not in finished
    )


async def _recovery_provider_sentinel(
    _context: ReconciliationAttemptContext,
) -> ReconciliationFinding:
    raise RuntimeError("recovery provider sentinel must not be invoked")


def _unfinished_attempt_contexts(
    action: UnknownAction,
    records: list[ReconciliationRecord] | tuple[ReconciliationRecord, ...],
) -> tuple[
    tuple[ReconciliationRecord, ReconciliationAttemptContext, ProviderDescriptor], ...
]:
    """Reconstruct only enough durable metadata to close expired attempts."""

    contexts: list[
        tuple[ReconciliationRecord, ReconciliationAttemptContext, ProviderDescriptor]
    ] = []
    for record in _unmatched_attempt_start_records(records):
        payload = record.payload
        try:
            context = ReconciliationAttemptContext(
                attempt_id=payload["attempt_id"],
                deadline=_parse_timestamp(payload["deadline"]),
                protocol_version=payload["protocol_version"],
                action=action,
            )
            evidence_kinds = action.reconciliation_supported_evidence_kinds or (
                "runtime",
            )
            provider = ProviderDescriptor(
                provider_id=payload["provider_id"],
                protocol_version=context.protocol_version,
                supported_evidence_kinds=evidence_kinds,
                provider=_recovery_provider_sentinel,
            )
        except (KeyError, TypeError, ValueError, ReconciliationError) as exc:
            raise ReconciliationError(
                "persisted unfinished reconciliation attempt is invalid"
            ) from exc
        contexts.append((record, context, provider))
    return tuple(contexts)


def _recovery_transition(
    head: ReconciliationHead,
    unfinished_attempt_count: int,
    recovered_at: datetime,
) -> ReconciliationTransition:
    if type(unfinished_attempt_count) is not int or unfinished_attempt_count < 1:
        raise ReconciliationValidationError(
            "unfinished_attempt_count must be a positive integer"
        )
    return ReconciliationTransition(
        execution_record_id=head.execution_record_id,
        expected_state=head.state,
        expected_revision=head.revision,
        new_state=ReconciliationState.MANUAL_REVIEW,
        source=ReconciliationTransitionSource.RECOVERY,
        evidence_kind="runtime",
        evidence={
            "reason_code": "expired_unfinished_reconciliation_attempt",
            "unfinished_attempt_count": unfinished_attempt_count,
        },
        occurred_at=recovered_at,
        retry_safe=False,
        resolved_result_available=False,
        reason="expired reconciliation attempt requires manual review",
    )


def _require_finished_attempt(
    records: list[ReconciliationRecord] | tuple[ReconciliationRecord, ...],
    attempt_id: str | None,
    provider: ProviderDescriptor | None,
    finding: ReconciliationFinding,
) -> None:
    if attempt_id is None or provider is None:
        return
    expected_finding = finding.to_dict()
    for record in records:
        if record.kind is not ReconciliationEventKind.ATTEMPT_FINISHED:
            continue
        if (
            record.payload.get("attempt_id") == attempt_id
            and record.payload.get("provider_id") == provider.provider_id
            and record.payload.get("outcome")
            == ReconciliationAttemptOutcome.SUCCESS.value
            and thaw(record.payload.get("finding")) == expected_finding
        ):
            return
    raise ReconciliationConflictError(
        "provider transition has no matching successful attempt finish"
    )


def _build_transition(
    head: ReconciliationHead,
    decision: ReconciliationFinding | ManualResolution,
    *,
    provider: ProviderDescriptor | None,
    attempt_id: str | None,
) -> ReconciliationTransition:
    if isinstance(decision, ReconciliationFinding):
        if provider is None:
            raise ReconciliationValidationError(
                "provider findings require a trusted ProviderDescriptor"
            )
        if head.state is ReconciliationState.MANUAL_REVIEW:
            raise InvalidReconciliationTransitionError(
                "MANUAL_REVIEW can be resolved only by ManualResolution"
            )
        if decision.evidence_kind not in provider.supported_evidence_kinds:
            raise ReconciliationValidationError(
                "provider does not support the finding evidence kind"
            )
        if attempt_id is None:
            raise ReconciliationValidationError(
                "provider transition requires the persisted attempt_id"
            )
        return ReconciliationTransition(
            execution_record_id=head.execution_record_id,
            expected_state=head.state,
            expected_revision=head.revision,
            new_state=decision.proposed_state,
            source=ReconciliationTransitionSource.PROVIDER,
            evidence_kind=decision.evidence_kind,
            evidence=decision.evidence,
            occurred_at=decision.observed_at,
            retry_safe=decision.retry_safe,
            resolved_result_available=decision.resolved_result_available,
            provider_id=provider.provider_id,
            attempt_id=attempt_id,
            resolved_result=decision.resolved_result,
        )
    if not isinstance(decision, ManualResolution):
        raise TypeError("decision must be a ReconciliationFinding or ManualResolution")
    if provider is not None or attempt_id is not None:
        raise ReconciliationValidationError(
            "manual resolution cannot carry provider attempt identity"
        )
    if decision.execution_record_id != head.execution_record_id:
        raise ReconciliationValidationError(
            "manual resolution targets a different execution record"
        )
    if (
        decision.expected_state is not head.state
        or decision.expected_revision != head.revision
    ):
        raise ReconciliationConflictError(
            "manual resolution expected state or revision is stale"
        )
    return ReconciliationTransition(
        execution_record_id=head.execution_record_id,
        expected_state=head.state,
        expected_revision=head.revision,
        new_state=decision.new_state,
        source=ReconciliationTransitionSource.MANUAL,
        evidence_kind=decision.evidence_kind,
        evidence=decision.evidence,
        occurred_at=decision.resolved_at,
        retry_safe=decision.retry_safe,
        resolved_result_available=decision.resolved_result_available,
        operator_identity_digest=decision.operator_identity_digest,
        reason=decision.reason,
        resolved_result=decision.resolved_result,
    )


def _validate_transition_evidence(
    action: UnknownAction, transition: ReconciliationTransition
) -> None:
    evidence = thaw(transition.evidence)
    encoded = _dump(evidence).encode("utf-8")
    if len(encoded) > action.max_evidence_bytes:
        raise ReconciliationValidationError(
            f"reconciliation evidence exceeds {action.max_evidence_bytes} bytes"
        )
    schema: Mapping[str, Any] | None = None
    if transition.evidence_kind == "receipt":
        schema = action.receipt_schema
    elif transition.evidence_kind == "probe":
        schema = action.probe_schema
    if schema is not None:
        try:
            validate_instance(evidence, schema, label="reconciliation evidence")
        except ContractValidationError as exc:
            raise ReconciliationValidationError(str(exc)) from exc
    if transition.resolved_result_available:
        result = thaw(transition.resolved_result)
        encoded_result = _dump(result).encode("utf-8")
        if len(encoded_result) > action.max_result_bytes:
            raise ReconciliationValidationError(
                f"resolved result exceeds {action.max_result_bytes} bytes"
            )
        if action.result_schema is not None:
            try:
                validate_instance(result, action.result_schema, label="resolved result")
            except ContractValidationError as exc:
                raise ReconciliationValidationError(str(exc)) from exc


def _transition_record(
    head: ReconciliationHead, transition: ReconciliationTransition
) -> tuple[ReconciliationRecord, ReconciliationHead]:
    _require_legal_transition(head.state, transition.new_state)
    disposition = _disposition(
        transition.new_state, transition.resolved_result_available
    )
    record = ReconciliationRecord(
        event_id=_new_id(),
        execution_record_id=head.execution_record_id,
        revision=head.revision + 1,
        kind=ReconciliationEventKind.STATE_TRANSITION,
        state_before=head.state,
        state_after=transition.new_state,
        occurred_at=transition.occurred_at,
        payload={"transition": transition.to_dict()},
    )
    updated = ReconciliationHead(
        action=head.action,
        state=transition.new_state,
        revision=record.revision,
        disposition=disposition,
        updated_at=record.occurred_at,
        resolved_result_available=transition.resolved_result_available,
        resolved_result=transition.resolved_result,
    )
    return record, updated


def _require_legal_transition(
    current: ReconciliationState, new: ReconciliationState
) -> None:
    legal = {
        ReconciliationState.UNKNOWN: {
            ReconciliationState.CONFIRMED_SUCCEEDED,
            ReconciliationState.CONFIRMED_NOT_APPLIED,
            ReconciliationState.MANUAL_REVIEW,
        },
        ReconciliationState.MANUAL_REVIEW: {
            ReconciliationState.CONFIRMED_SUCCEEDED,
            ReconciliationState.CONFIRMED_NOT_APPLIED,
        },
    }
    if new not in legal.get(current, set()):
        raise InvalidReconciliationTransitionError(
            f"illegal reconciliation transition {current.value} -> {new.value}"
        )


def _require_cas(
    head: ReconciliationHead,
    expected_state: ReconciliationState,
    expected_revision: int,
) -> None:
    if not isinstance(expected_state, ReconciliationState):
        raise TypeError("expected_state must be a ReconciliationState")
    if type(expected_revision) is not int or expected_revision < 0:
        raise ReconciliationValidationError(
            "expected_revision must be a non-negative integer"
        )
    if head.state is not expected_state or head.revision != expected_revision:
        raise ReconciliationConflictError(
            "reconciliation state or revision does not match the expected CAS value"
        )


def _disposition(
    state: ReconciliationState, resolved_result_available: bool
) -> ReconciliationDisposition:
    if state is ReconciliationState.UNKNOWN:
        return ReconciliationDisposition.BLOCKED_UNKNOWN
    if state is ReconciliationState.MANUAL_REVIEW:
        return ReconciliationDisposition.BLOCKED_MANUAL_REVIEW
    if state is ReconciliationState.CONFIRMED_NOT_APPLIED:
        return ReconciliationDisposition.RETRY_ALLOWED
    if not resolved_result_available:
        return ReconciliationDisposition.APPLIED_NO_RESULT
    return ReconciliationDisposition.COMPLETED


def _idempotency_disposition(
    head: ReconciliationHead,
) -> tuple[str, str | None, str | None]:
    if head.disposition is ReconciliationDisposition.BLOCKED_MANUAL_REVIEW:
        return "manual_review", None, "manual reconciliation required"
    if head.disposition is ReconciliationDisposition.RETRY_ALLOWED:
        return "not_applied", None, "confirmed not applied"
    if head.disposition is ReconciliationDisposition.APPLIED_NO_RESULT:
        return (
            "applied_no_result",
            None,
            "side effect applied but no result can be reconstructed",
        )
    if head.disposition is ReconciliationDisposition.COMPLETED:
        return "completed", _dump(thaw(head.resolved_result)), None
    return "unknown", None, "outcome is unknown"


def _record_from_row(row: tuple[Any, ...]) -> ReconciliationRecord:
    event_id, execution_id, revision, kind, before, after, occurred_at, payload = row
    return ReconciliationRecord(
        event_id=event_id,
        execution_record_id=execution_id,
        revision=revision,
        kind=ReconciliationEventKind(kind),
        state_before=ReconciliationState(before),
        state_after=ReconciliationState(after),
        occurred_at=_parse_timestamp(occurred_at),
        payload=json.loads(payload),
    )


def _audit_envelope_from_row(
    row: tuple[Any, ...],
) -> ReconciliationAuditEnvelope:
    (
        outbox_id,
        execution_record_id,
        revision,
        event_type,
        event_json,
        stored_digest,
        created_at,
        delivery_attempts,
    ) = row
    actual_digest = hashlib.sha256(event_json.encode("utf-8")).hexdigest()
    if not isinstance(stored_digest, str) or not hmac.compare_digest(
        stored_digest, actual_digest
    ):
        raise ReconciliationError("reconciliation audit outbox payload digest mismatch")
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError as exc:
        raise ReconciliationError("reconciliation audit outbox payload is invalid") from exc
    return ReconciliationAuditEnvelope(
        outbox_id=outbox_id,
        execution_record_id=execution_record_id,
        revision=revision,
        event_type=event_type,
        event=event,
        created_at=_parse_timestamp(created_at),
        delivery_attempts=delivery_attempts,
    )


def _bounded_schema(value: Mapping[str, Any], *, label: str) -> Mapping[str, Any]:
    plain = thaw(value)
    try:
        validate_schema(plain, label=label)
    except RegistryError as exc:
        raise ReconciliationValidationError(str(exc)) from exc
    return _bounded_mapping(
        plain,
        label=label,
        max_bytes=_MAX_SCHEMA_BYTES,
        allow_empty=True,
        reject_sensitive_keys=False,
    )


def _bounded_mapping(
    value: Mapping[str, Any],
    *,
    label: str,
    max_bytes: int,
    allow_empty: bool,
    reject_sensitive_keys: bool = True,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReconciliationValidationError(f"{label} must be an object")
    normalized = _bounded_value(value, label=label, max_bytes=max_bytes)
    if not isinstance(normalized, Mapping):
        raise ReconciliationValidationError(f"{label} must be an object")
    plain = thaw(normalized)
    if not allow_empty and not plain:
        raise ReconciliationValidationError(f"{label} cannot be empty")
    if reject_sensitive_keys:
        _reject_sensitive_keys(plain, label)
    return freeze_mapping(plain)


def _bounded_value(value: Any, *, label: str, max_bytes: int) -> Any:
    try:
        normalized = _normalize_reconciliation_json(
            value,
            path=label,
            depth=0,
            active=set(),
            budget=[_MAX_VALUE_NODES],
        )
        encoded = rfc8785_json_bytes(normalized, encoder=rfc8785.dumps)
    except CanonicalJsonError as exc:
        raise ReconciliationValidationError(str(exc)) from exc
    if len(encoded) > max_bytes:
        raise ReconciliationValidationError(f"{label} exceeds {max_bytes} bytes")
    if isinstance(normalized, Mapping):
        return freeze_mapping(normalized)
    if isinstance(normalized, list):
        return tuple(_freeze_value(item) for item in normalized)
    return normalized


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return freeze_mapping(value)
    if isinstance(value, list):
        return tuple(_freeze_value(item) for item in value)
    return value


def _normalize_reconciliation_json(
    value: Any,
    *,
    path: str,
    depth: int,
    active: set[int],
    budget: list[int],
) -> Any:
    if depth > _MAX_VALUE_DEPTH:
        raise ReconciliationValidationError(
            f"{path} exceeds maximum depth {_MAX_VALUE_DEPTH}"
        )
    budget[0] -= 1
    if budget[0] < 0:
        raise ReconciliationValidationError(
            f"{path} exceeds maximum node count {_MAX_VALUE_NODES}"
        )
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ReconciliationValidationError(
                f"{path} must contain valid Unicode scalar values"
            ) from exc
        return value
    if type(value) is int:
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise ReconciliationValidationError(
                f"{path} exceeds the interoperable integer range"
            )
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ReconciliationValidationError(f"{path} contains a non-finite number")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise ReconciliationValidationError(
                f"{path} contains ambiguous negative zero"
            )
        return value
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise ReconciliationValidationError(f"{path} contains a cyclic object")
        active.add(identity)
        try:
            result: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise ReconciliationValidationError(
                        f"{path} object keys must be strings"
                    )
                result[key] = _normalize_reconciliation_json(
                    item,
                    path=f"{path}.{key}",
                    depth=depth + 1,
                    active=active,
                    budget=budget,
                )
            return result
        finally:
            active.remove(identity)
    if type(value) is list:
        identity = id(value)
        if identity in active:
            raise ReconciliationValidationError(f"{path} contains a cyclic array")
        active.add(identity)
        try:
            return [
                _normalize_reconciliation_json(
                    item,
                    path=f"{path}[{index}]",
                    depth=depth + 1,
                    active=active,
                    budget=budget,
                )
                for index, item in enumerate(value)
            ]
        finally:
            active.remove(identity)
    raise ReconciliationValidationError(
        f"{path} contains unsupported type "
        f"{type(value).__module__}.{type(value).__qualname__}"
    )


def _reject_sensitive_keys(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key.casefold() in _FORBIDDEN_EVIDENCE_KEYS:
                raise ReconciliationValidationError(
                    f"{label} contains forbidden sensitive field {key!r}"
                )
            _reject_sensitive_keys(item, label)
    elif isinstance(value, tuple | list):
        for item in value:
            _reject_sensitive_keys(item, label)


def _require_identifier(label: str, value: Any) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise ReconciliationValidationError(
            f"{label} must be a stable 1-256 character identifier"
        )


def _require_protocol_version(value: Any) -> None:
    if type(value) is int and value >= 1:
        return
    _require_identifier("protocol_version", value)


def _require_execution_record_id(value: Any) -> None:
    if type(value) is not str or not _EXECUTION_RECORD_ID.fullmatch(value):
        raise ReconciliationValidationError(
            "execution_record_id must be an opaque 1-256 character identifier"
        )


def _require_digest(label: str, value: Any) -> None:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise ReconciliationValidationError(
            f"{label} must be a lowercase SHA-256 hex digest"
        )


def _require_bounded_text(label: str, value: Any, max_bytes: int) -> None:
    if type(value) is not str or not value:
        raise ReconciliationValidationError(f"{label} must be a non-empty string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ReconciliationValidationError(
            f"{label} must contain valid Unicode scalar values"
        ) from exc
    if size > max_bytes:
        raise ReconciliationValidationError(
            f"{label} must not exceed {max_bytes} UTF-8 bytes"
        )


def _require_timestamp(value: Any) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ReconciliationValidationError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return _require_timestamp(value).isoformat()


def _parse_timestamp(value: Any) -> datetime:
    if type(value) is not str:
        raise ReconciliationValidationError("stored timestamp must be a string")
    try:
        return _require_timestamp(datetime.fromisoformat(value))
    except ValueError as exc:
        raise ReconciliationValidationError("stored timestamp is invalid") from exc


def _new_id() -> str:
    return secrets.token_hex(32)


def _dump(value: Any) -> str:
    try:
        normalized = _normalize_reconciliation_json(
            value,
            path="reconciliation storage",
            depth=0,
            active=set(),
            budget=[_MAX_VALUE_NODES],
        )
        return rfc8785_json_text(normalized, encoder=rfc8785.dumps)
    except CanonicalJsonError as exc:
        raise ReconciliationValidationError(str(exc)) from exc


def _optional_dump(value: Any | None, available: bool) -> str | None:
    return _dump(thaw(value)) if available else None


__all__ = [
    "InMemoryReconciliationLedger",
    "InvalidReconciliationTransitionError",
    "ManualResolution",
    "ProviderDescriptor",
    "ReconciliationAuditEnvelope",
    "ReconciliationAttemptContext",
    "ReconciliationAttemptOutcome",
    "ReconciliationConflictError",
    "ReconciliationDisposition",
    "ReconciliationError",
    "ReconciliationEventKind",
    "ReconciliationFinding",
    "ReconciliationHead",
    "ReconciliationLedger",
    "ReconciliationNotFoundError",
    "ReconciliationProvider",
    "ReconciliationRecord",
    "ReconciliationState",
    "ReconciliationTransition",
    "ReconciliationTransitionSource",
    "ReconciliationValidationError",
    "SQLiteReconciliationLedger",
    "UnknownAction",
    "enqueue_reconciliation_audit_outbox",
    "idempotency_namespace_digest",
    "new_execution_record_id",
    "tenant_partition_digest",
]
