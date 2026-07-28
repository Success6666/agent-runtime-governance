"""Privacy-safe unsigned evidence bundle values.

Evidence bundles intentionally project only stable, non-secret identifiers from
governance records.  They are not runtime snapshots: callers must provide the
small immutable DTOs in this module rather than audit sinks, contexts, or
reconciliation records containing provider payloads.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator

from ._canonical import CanonicalJsonError, rfc8785_json_bytes
from .action_contracts import BoundAction
from .decisions import ApprovalRequest, DecisionOutcome, DecisionRecord

_EVIDENCE_SCHEMA_VERSION = "1"
_EVIDENCE_DOMAIN = b"arg.evidence.v1\0"
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_REDACTION_PATH = re.compile(r"^/(?:[^~/\x00-\x1f]|~[01])+(?:/(?:[^~/\x00-\x1f]|~[01])+)*$")
_SAFE_REDACTION_PATHS = frozenset(
    {
        "/approval/arguments",
        "/approval/reason",
        "/execution/receipt",
        "/identity/issuer",
        "/identity/principal",
        "/identity/tenant",
        "/input",
        "/parameters",
        "/reconciliation/evidence",
        "/result",
    }
)
_EXECUTION_STATUSES = frozenset({"succeeded", "failed", "unknown"})
_RECONCILIATION_STATES = frozenset(
    {
        "UNKNOWN",
        "CONFIRMED_SUCCEEDED",
        "CONFIRMED_NOT_APPLIED",
        "MANUAL_REVIEW",
    }
)
_RECONCILIATION_TRANSITIONS = {
    "UNKNOWN": frozenset(
        {
            "CONFIRMED_SUCCEEDED",
            "CONFIRMED_NOT_APPLIED",
            "MANUAL_REVIEW",
        }
    ),
    "MANUAL_REVIEW": frozenset(
        {
            "CONFIRMED_SUCCEEDED",
            "CONFIRMED_NOT_APPLIED",
        }
    ),
}


class EvidenceBundleValidationError(ValueError):
    """Raised when a privacy-safe evidence value fails closed validation."""


EVIDENCE_BUNDLE_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "bundle_id",
        "created_at",
        "action",
        "identity",
        "policy",
        "approval",
        "execution",
        "reconciliation",
        "audit_anchor",
        "redactions",
        "signature",
    ],
    "properties": {
        "schema_version": {"const": _EVIDENCE_SCHEMA_VERSION},
        "bundle_id": {"type": "string", "pattern": _IDENTIFIER.pattern},
        "created_at": {"$ref": "#/$defs/timestamp"},
        "action": {"$ref": "#/$defs/action"},
        "identity": {"$ref": "#/$defs/identity"},
        "policy": {"$ref": "#/$defs/policy"},
        "approval": {
            "oneOf": [
                {"type": "null"},
                {"$ref": "#/$defs/approval"},
            ]
        },
        "execution": {"$ref": "#/$defs/execution"},
        "reconciliation": {
            "type": "array",
            "items": {"$ref": "#/$defs/reconciliation_entry"},
        },
        "audit_anchor": {
            "oneOf": [
                {"type": "null"},
                {"$ref": "#/$defs/audit_anchor"},
            ]
        },
        "redactions": {
            "type": "array",
            "items": {"type": "string", "enum": sorted(_SAFE_REDACTION_PATHS)},
            "uniqueItems": True,
        },
        "signature": {"type": "null"},
    },
    "$defs": {
        "digest": {"type": "string", "pattern": _SHA256_HEX.pattern},
        "timestamp": {"type": "string", "format": "date-time"},
        "action": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "action_digest",
                "contract_id",
                "contract_version",
                "tool_name",
                "contract_digest",
                "parameters_digest",
                "precondition_digest",
            ],
            "properties": {
                "action_digest": {"$ref": "#/$defs/digest"},
                "contract_id": {
                    "type": "string",
                    "pattern": _IDENTIFIER.pattern,
                },
                "contract_version": {"type": "integer", "minimum": 1},
                "tool_name": {"type": "string", "pattern": _IDENTIFIER.pattern},
                "contract_digest": {"$ref": "#/$defs/digest"},
                "parameters_digest": {"$ref": "#/$defs/digest"},
                "precondition_digest": {
                    "oneOf": [
                        {"type": "null"},
                        {"$ref": "#/$defs/digest"},
                    ]
                },
            },
        },
        "identity": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "principal_digest",
                "tenant_digest",
                "identity_digest_key_version",
            ],
            "properties": {
                "principal_digest": {"$ref": "#/$defs/digest"},
                "tenant_digest": {"$ref": "#/$defs/digest"},
                "identity_digest_key_version": {
                    "type": "string",
                    "pattern": _IDENTIFIER.pattern,
                },
            },
        },
        "policy": {
            "type": "object",
            "additionalProperties": False,
            "required": ["version", "digest"],
            "properties": {
                "version": {
                    "oneOf": [
                        {"type": "null"},
                        {"type": "string", "pattern": _IDENTIFIER.pattern},
                    ]
                },
                "digest": {
                    "oneOf": [
                        {"type": "null"},
                        {"$ref": "#/$defs/digest"},
                    ]
                },
            },
        },
        "approval": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "request_id",
                "decision_id",
                "outcome",
                "arguments_digest",
                "decided_at",
                "expires_at",
            ],
            "properties": {
                "request_id": {"type": "string", "pattern": _IDENTIFIER.pattern},
                "decision_id": {"type": "string", "pattern": _IDENTIFIER.pattern},
                "outcome": {
                    "enum": [
                        DecisionOutcome.ALLOW.value,
                        DecisionOutcome.DENY.value,
                        DecisionOutcome.REQUIRE_HUMAN.value,
                    ]
                },
                "arguments_digest": {"$ref": "#/$defs/digest"},
                "decided_at": {"$ref": "#/$defs/timestamp"},
                "expires_at": {
                    "oneOf": [
                        {"type": "null"},
                        {"$ref": "#/$defs/timestamp"},
                    ]
                },
            },
        },
        "execution": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "execution_record_id",
                "status",
                "started_at",
                "finished_at",
                "receipt",
            ],
            "properties": {
                "execution_record_id": {
                    "type": "string",
                    "pattern": _IDENTIFIER.pattern,
                },
                "status": {"enum": sorted(_EXECUTION_STATUSES)},
                "started_at": {"$ref": "#/$defs/timestamp"},
                "finished_at": {
                    "oneOf": [
                        {"type": "null"},
                        {"$ref": "#/$defs/timestamp"},
                    ]
                },
                "receipt": {"type": "null"},
            },
        },
        "reconciliation_entry": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "seq",
                "prior_state",
                "new_state",
                "provider_id",
                "evidence_kind",
                "created_at",
            ],
            "properties": {
                "seq": {"type": "integer", "minimum": 1},
                "prior_state": {"enum": sorted(_RECONCILIATION_STATES)},
                "new_state": {"enum": sorted(_RECONCILIATION_STATES)},
                "provider_id": {
                    "oneOf": [
                        {"type": "null"},
                        {"type": "string", "pattern": _IDENTIFIER.pattern},
                    ]
                },
                "evidence_kind": {
                    "type": "string",
                    "pattern": _IDENTIFIER.pattern,
                },
                "created_at": {"$ref": "#/$defs/timestamp"},
            },
        },
        "audit_anchor": {
            "type": "object",
            "additionalProperties": False,
            "required": ["chain_head_hash", "record_count"],
            "properties": {
                "chain_head_hash": {"$ref": "#/$defs/digest"},
                "record_count": {"type": "integer", "minimum": 0},
            },
        },
    },
}
Draft202012Validator.check_schema(EVIDENCE_BUNDLE_SCHEMA_V1)
if "date-time" not in Draft202012Validator.FORMAT_CHECKER.checkers:
    raise RuntimeError(
        "rfc3339-validator is required for fail-closed evidence timestamp validation"
    )
_SCHEMA_VALIDATOR = Draft202012Validator(
    EVIDENCE_BUNDLE_SCHEMA_V1,
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


@dataclass(frozen=True, slots=True)
class EvidenceExecution:
    """A receipt-free execution summary suitable for external evidence."""

    execution_record_id: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_identifier("execution_record_id", self.execution_record_id)
        status = _enum_value(self.status)
        if status not in _EXECUTION_STATUSES:
            raise EvidenceBundleValidationError(
                "execution status must be succeeded, failed, or unknown"
            )
        started_at = _require_timestamp("execution started_at", self.started_at)
        finished_at = (
            None
            if self.finished_at is None
            else _require_timestamp("execution finished_at", self.finished_at)
        )
        if finished_at is not None and finished_at < started_at:
            raise EvidenceBundleValidationError(
                "execution finished_at must not precede started_at"
            )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "finished_at", finished_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_record_id": self.execution_record_id,
            "status": self.status,
            "started_at": _timestamp_text(self.started_at),
            "finished_at": (
                None
                if self.finished_at is None
                else _timestamp_text(self.finished_at)
            ),
            "receipt": None,
        }


@dataclass(frozen=True, slots=True)
class ReconciliationEvidenceEntry:
    """A payload-free reconciliation lineage transition."""

    seq: int
    prior_state: str
    new_state: str
    evidence_kind: str
    created_at: datetime
    provider_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.seq) is not int or self.seq < 1:
            raise EvidenceBundleValidationError("reconciliation seq must be positive")
        prior_state = _enum_value(self.prior_state)
        new_state = _enum_value(self.new_state)
        if prior_state not in _RECONCILIATION_STATES:
            raise EvidenceBundleValidationError("unknown reconciliation prior_state")
        if new_state not in _RECONCILIATION_STATES:
            raise EvidenceBundleValidationError("unknown reconciliation new_state")
        _require_identifier("reconciliation evidence_kind", self.evidence_kind)
        if self.provider_id is not None:
            _require_identifier("reconciliation provider_id", self.provider_id)
        object.__setattr__(self, "prior_state", prior_state)
        object.__setattr__(self, "new_state", new_state)
        object.__setattr__(
            self,
            "created_at",
            _require_timestamp("reconciliation created_at", self.created_at),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "prior_state": self.prior_state,
            "new_state": self.new_state,
            "provider_id": self.provider_id,
            "evidence_kind": self.evidence_kind,
            "created_at": _timestamp_text(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class AuditAnchor:
    """A verified external audit-chain position without sink or record access."""

    chain_head_hash: str
    record_count: int

    def __post_init__(self) -> None:
        _require_digest("audit chain_head_hash", self.chain_head_hash)
        if type(self.record_count) is not int or self.record_count < 0:
            raise EvidenceBundleValidationError(
                "audit record_count must be a non-negative integer"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_head_hash": self.chain_head_hash,
            "record_count": self.record_count,
        }


@dataclass(frozen=True, slots=True, repr=False)
class _ActionEvidence:
    action_digest: str
    contract_id: str
    contract_version: int
    tool_name: str
    contract_digest: str
    parameters_digest: str
    precondition_digest: str | None

    def __post_init__(self) -> None:
        _require_digest("action_digest", self.action_digest)
        _require_identifier("contract_id", self.contract_id)
        if type(self.contract_version) is not int or self.contract_version < 1:
            raise EvidenceBundleValidationError("contract_version must be positive")
        _require_identifier("tool_name", self.tool_name)
        _require_digest("contract_digest", self.contract_digest)
        _require_digest("parameters_digest", self.parameters_digest)
        if self.precondition_digest is not None:
            _require_digest("precondition_digest", self.precondition_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_digest": self.action_digest,
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "tool_name": self.tool_name,
            "contract_digest": self.contract_digest,
            "parameters_digest": self.parameters_digest,
            "precondition_digest": self.precondition_digest,
        }


@dataclass(frozen=True, slots=True, repr=False)
class _IdentityEvidence:
    principal_digest: str
    tenant_digest: str
    identity_digest_key_version: str

    def __post_init__(self) -> None:
        _require_digest("principal_digest", self.principal_digest)
        _require_digest("tenant_digest", self.tenant_digest)
        _require_identifier(
            "identity_digest_key_version", self.identity_digest_key_version
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_digest": self.principal_digest,
            "tenant_digest": self.tenant_digest,
            "identity_digest_key_version": self.identity_digest_key_version,
        }


@dataclass(frozen=True, slots=True, repr=False)
class _PolicyEvidence:
    version: str | None
    digest: str | None

    def __post_init__(self) -> None:
        if (self.version is None) != (self.digest is None):
            raise EvidenceBundleValidationError(
                "policy version and digest must either both be set or both be null"
            )
        if self.version is not None:
            _require_identifier("policy version", self.version)
        if self.digest is not None:
            _require_digest("policy digest", self.digest)

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "digest": self.digest}


@dataclass(frozen=True, slots=True, repr=False)
class _ApprovalEvidence:
    request_id: str
    decision_id: str
    outcome: str
    arguments_digest: str
    decided_at: datetime
    expires_at: datetime | None

    def __post_init__(self) -> None:
        _require_identifier("approval request_id", self.request_id)
        _require_identifier("approval decision_id", self.decision_id)
        outcome = _enum_value(self.outcome)
        if outcome not in {item.value for item in DecisionOutcome}:
            raise EvidenceBundleValidationError("unknown approval outcome")
        _require_digest("approval arguments_digest", self.arguments_digest)
        decided_at = _require_timestamp("approval decided_at", self.decided_at)
        expires_at = (
            None
            if self.expires_at is None
            else _require_timestamp("approval expires_at", self.expires_at)
        )
        if expires_at is not None and expires_at <= decided_at:
            raise EvidenceBundleValidationError(
                "approval expires_at must follow decided_at"
            )
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "decided_at", decided_at)
        object.__setattr__(self, "expires_at", expires_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "outcome": self.outcome,
            "arguments_digest": self.arguments_digest,
            "decided_at": _timestamp_text(self.decided_at),
            "expires_at": (
                None if self.expires_at is None else _timestamp_text(self.expires_at)
            ),
        }


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceBundle:
    """Unsigned, schema-validated evidence projected from one ``BoundAction``."""

    bundle_id: str
    created_at: datetime
    action: _ActionEvidence = field(repr=False)
    identity: _IdentityEvidence = field(repr=False)
    policy: _PolicyEvidence = field(repr=False)
    execution: EvidenceExecution
    approval: _ApprovalEvidence | None = field(default=None, repr=False)
    reconciliation: tuple[ReconciliationEvidenceEntry, ...] = ()
    audit_anchor: AuditAnchor | None = None
    redactions: tuple[str, ...] = ()
    schema_version: str = field(default=_EVIDENCE_SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        _require_identifier("bundle_id", self.bundle_id)
        object.__setattr__(self, "created_at", _require_timestamp("created_at", self.created_at))
        if not isinstance(self.action, _ActionEvidence):
            raise TypeError("action must be projected from a BoundAction")
        if not isinstance(self.identity, _IdentityEvidence):
            raise TypeError("identity must be projected from a BoundAction")
        if not isinstance(self.policy, _PolicyEvidence):
            raise TypeError("policy must be projected from a BoundAction")
        if not isinstance(self.execution, EvidenceExecution):
            raise TypeError("execution must be an EvidenceExecution")
        if self.approval is not None and not isinstance(self.approval, _ApprovalEvidence):
            raise TypeError("approval must be projected from verified approval records")
        if self.audit_anchor is not None and not isinstance(self.audit_anchor, AuditAnchor):
            raise TypeError("audit_anchor must be an AuditAnchor")
        entries = _normalize_reconciliation(self.reconciliation)
        _validate_reconciliation_lineage(entries)
        object.__setattr__(self, "reconciliation", entries)
        object.__setattr__(self, "redactions", _normalize_redactions(self.redactions))
        self._validate_for_serialization()

    @classmethod
    def from_bound_action(
        cls,
        action: BoundAction,
        *,
        bundle_id: str,
        created_at: datetime,
        execution: EvidenceExecution,
        approval_request: ApprovalRequest | None = None,
        decision: DecisionRecord | None = None,
        reconciliation: Sequence[ReconciliationEvidenceEntry] = (),
        audit_anchor: AuditAnchor | None = None,
        redactions: Sequence[str] = (),
    ) -> "EvidenceBundle":
        """Project the explicit allowlist from a bound governed action.

        ``ApprovalRequest.arguments_digest`` belongs to the approval argument
        domain and is deliberately never compared with
        ``BoundAction.parameters_digest``.
        """

        if not isinstance(action, BoundAction):
            raise TypeError("action must be a BoundAction")
        if (approval_request is None) != (decision is None):
            raise EvidenceBundleValidationError(
                "approval_request and decision must be supplied together"
            )
        approval = (
            None
            if approval_request is None or decision is None
            else _approval_from_records(action, approval_request, decision)
        )
        return cls(
            bundle_id=bundle_id,
            created_at=created_at,
            action=_ActionEvidence(
                action_digest=action.action_digest,
                contract_id=action.contract.contract_id,
                contract_version=action.contract.contract_version,
                tool_name=action.contract.tool_name,
                contract_digest=action.contract_digest,
                parameters_digest=action.parameters_digest,
                precondition_digest=action.precondition_digest,
            ),
            identity=_IdentityEvidence(
                principal_digest=action.principal_digest,
                tenant_digest=action.tenant_digest,
                identity_digest_key_version=action.identity_digest_key_version,
            ),
            policy=_PolicyEvidence(
                version=action.policy_version,
                digest=action.policy_digest,
            ),
            execution=execution,
            approval=approval,
            reconciliation=reconciliation,  # type: ignore[arg-type]
            audit_anchor=audit_anchor,
            redactions=redactions,  # type: ignore[arg-type]
        )

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "EvidenceBundle":
        """Restore one strict, portable Evidence Bundle v1 document.

        The parser reconstructs the existing immutable value objects so an
        offline verifier applies the same schema, timestamp, and
        reconciliation-lineage invariants as a runtime-produced bundle.
        """

        if not isinstance(document, Mapping):
            raise EvidenceBundleValidationError("evidence bundle must be an object")
        data = dict(document)
        _validate_document(data)

        action = _require_document_object(data["action"], "action")
        identity = _require_document_object(data["identity"], "identity")
        policy = _require_document_object(data["policy"], "policy")
        execution = _require_document_object(data["execution"], "execution")
        approval_data = data["approval"]
        audit_anchor_data = data["audit_anchor"]

        approval = (
            None
            if approval_data is None
            else _approval_from_document(
                _require_document_object(approval_data, "approval")
            )
        )
        audit_anchor = (
            None
            if audit_anchor_data is None
            else AuditAnchor(
                **_require_document_object(audit_anchor_data, "audit_anchor")
            )
        )
        reconciliation = tuple(
            _reconciliation_from_document(
                _require_document_object(item, "reconciliation")
            )
            for item in _require_document_array(
                data["reconciliation"], "reconciliation"
            )
        )

        bundle = cls(
            bundle_id=data["bundle_id"],
            created_at=_parse_external_timestamp("created_at", data["created_at"]),
            action=_ActionEvidence(**action),
            identity=_IdentityEvidence(**identity),
            policy=_PolicyEvidence(**policy),
            execution=EvidenceExecution(
                execution_record_id=execution["execution_record_id"],
                status=execution["status"],
                started_at=_parse_external_timestamp(
                    "execution started_at", execution["started_at"]
                ),
                finished_at=(
                    None
                    if execution["finished_at"] is None
                    else _parse_external_timestamp(
                        "execution finished_at", execution["finished_at"]
                    )
                ),
            ),
            approval=approval,
            reconciliation=reconciliation,
            audit_anchor=audit_anchor,
            redactions=tuple(_require_document_array(data["redactions"], "redactions")),
        )
        if bundle.to_dict() != data:
            raise EvidenceBundleValidationError(
                "evidence bundle must use the canonical v1 representation"
            )
        return bundle

    @property
    def signature(self) -> None:
        """Evidence bundle v1 intentionally carries no signature material."""

        return None

    @property
    def bundle_digest(self) -> str:
        """Return the RFC 8785, domain-separated unsigned bundle digest."""

        return hashlib.sha256(self.commitment_bytes()).hexdigest()

    @property
    def digest(self) -> str:
        """Alias for :attr:`bundle_digest`."""

        return self.bundle_digest

    def canonical_unsigned_bytes(self) -> bytes:
        """Return the exact RFC 8785 bytes covered by :attr:`bundle_digest`."""

        self._validate_for_serialization()
        try:
            return rfc8785_json_bytes(self.unsigned_dict())
        except CanonicalJsonError as exc:
            raise EvidenceBundleValidationError(
                "evidence bundle is not RFC 8785 canonicalizable"
            ) from exc

    def commitment_bytes(self) -> bytes:
        """Return the domain-separated bytes committed by the bundle digest."""

        return _EVIDENCE_DOMAIN + self.canonical_unsigned_bytes()

    def unsigned_dict(self) -> dict[str, Any]:
        """Return the signature-free, privacy-safe evidence payload."""

        return self._document(include_signature=False)

    def to_dict(self) -> dict[str, Any]:
        """Return the closed schema v1 document with a fixed null signature."""

        document = self._document(include_signature=True)
        self._validate_for_serialization(document)
        return document

    def _validate_for_serialization(
        self, document: dict[str, Any] | None = None
    ) -> None:
        _validate_reconciliation_lineage(self.reconciliation)
        _validate_document(
            self._document(include_signature=True) if document is None else document
        )

    def _document(self, *, include_signature: bool) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "created_at": _timestamp_text(self.created_at),
            "action": self.action.to_dict(),
            "identity": self.identity.to_dict(),
            "policy": self.policy.to_dict(),
            "approval": None if self.approval is None else self.approval.to_dict(),
            "execution": self.execution.to_dict(),
            "reconciliation": [item.to_dict() for item in self.reconciliation],
            "audit_anchor": (
                None if self.audit_anchor is None else self.audit_anchor.to_dict()
            ),
            "redactions": list(self.redactions),
        }
        if include_signature:
            document["signature"] = None
        return document


def _approval_from_document(document: dict[str, Any]) -> _ApprovalEvidence:
    return _ApprovalEvidence(
        request_id=document["request_id"],
        decision_id=document["decision_id"],
        outcome=document["outcome"],
        arguments_digest=document["arguments_digest"],
        decided_at=_parse_external_timestamp(
            "approval decided_at", document["decided_at"]
        ),
        expires_at=(
            None
            if document["expires_at"] is None
            else _parse_external_timestamp(
                "approval expires_at", document["expires_at"]
            )
        ),
    )


def _reconciliation_from_document(
    document: dict[str, Any],
) -> ReconciliationEvidenceEntry:
    return ReconciliationEvidenceEntry(
        seq=document["seq"],
        prior_state=document["prior_state"],
        new_state=document["new_state"],
        provider_id=document["provider_id"],
        evidence_kind=document["evidence_kind"],
        created_at=_parse_external_timestamp(
            "reconciliation created_at", document["created_at"]
        ),
    )


def _approval_from_records(
    action: BoundAction,
    request: ApprovalRequest,
    decision: DecisionRecord,
) -> _ApprovalEvidence:
    if not isinstance(request, ApprovalRequest):
        raise TypeError("approval_request must be an ApprovalRequest")
    if not isinstance(decision, DecisionRecord):
        raise TypeError("decision must be a DecisionRecord")
    if request.tool_name != action.contract.tool_name:
        raise EvidenceBundleValidationError("approval request tool_name mismatch")
    if request.action_digest != action.action_digest:
        raise EvidenceBundleValidationError("approval request action_digest mismatch")
    if request.policy_version != action.policy_version:
        raise EvidenceBundleValidationError("approval request policy_version mismatch")
    if request.policy_digest != action.policy_digest:
        raise EvidenceBundleValidationError("approval request policy_digest mismatch")

    try:
        bound_decision = decision.bind_to(request)
    except (TypeError, ValueError) as exc:
        raise EvidenceBundleValidationError(
            f"approval decision binding failed: {exc}"
        ) from exc
    if bound_decision.action_digest != action.action_digest:
        raise EvidenceBundleValidationError("approval decision action_digest mismatch")
    if bound_decision.policy_version != action.policy_version:
        raise EvidenceBundleValidationError("approval decision policy_version mismatch")
    if bound_decision.policy_digest != action.policy_digest:
        raise EvidenceBundleValidationError("approval decision policy_digest mismatch")
    return _ApprovalEvidence(
        request_id=request.request_id,
        decision_id=bound_decision.decision_id,
        outcome=bound_decision.outcome.value,
        arguments_digest=request.arguments_digest,
        decided_at=_parse_external_timestamp(
            "approval decision issued_at", bound_decision.issued_at
        ),
        expires_at=(
            None
            if bound_decision.expires_at is None
            else _parse_external_timestamp(
                "approval decision expires_at", bound_decision.expires_at
            )
        ),
    )


def _normalize_reconciliation(
    value: Sequence[ReconciliationEvidenceEntry],
) -> tuple[ReconciliationEvidenceEntry, ...]:
    if isinstance(value, str | bytes) or not isinstance(value, Sequence):
        raise TypeError("reconciliation must be a sequence of evidence entries")
    entries = tuple(value)
    if any(not isinstance(item, ReconciliationEvidenceEntry) for item in entries):
        raise TypeError("reconciliation entries must be ReconciliationEvidenceEntry")
    return entries


def _validate_reconciliation_lineage(
    entries: tuple[ReconciliationEvidenceEntry, ...],
) -> None:
    previous_state: str | None = None
    previous_created_at: datetime | None = None
    for index, entry in enumerate(entries, start=1):
        if entry.seq != index:
            raise EvidenceBundleValidationError(
                "reconciliation sequence numbers must start at 1 and be contiguous"
            )
        if index == 1 and entry.prior_state != "UNKNOWN":
            raise EvidenceBundleValidationError(
                "reconciliation lineage must begin at UNKNOWN"
            )
        if previous_created_at is not None and entry.created_at < previous_created_at:
            raise EvidenceBundleValidationError(
                "reconciliation lineage timestamps must not move backwards"
            )
        if previous_state is not None and entry.prior_state != previous_state:
            raise EvidenceBundleValidationError(
                "reconciliation lineage state transition is discontinuous"
            )
        if entry.new_state not in _RECONCILIATION_TRANSITIONS.get(
            entry.prior_state, frozenset()
        ):
            raise EvidenceBundleValidationError(
                "reconciliation lineage contains an illegal state transition"
            )
        previous_state = entry.new_state
        previous_created_at = entry.created_at


def _normalize_redactions(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, str | bytes) or not isinstance(value, Sequence):
        raise TypeError("redactions must be a sequence of JSON Pointer paths")
    paths = tuple(value)
    for path in paths:
        if not isinstance(path, str) or not _REDACTION_PATH.fullmatch(path):
            raise EvidenceBundleValidationError(
                "redactions must contain non-empty JSON Pointer paths"
            )
        if path not in _SAFE_REDACTION_PATHS:
            raise EvidenceBundleValidationError(
                "redactions must use an allowlisted source field path"
            )
    if len(set(paths)) != len(paths):
        raise EvidenceBundleValidationError("redactions must not contain duplicates")
    return tuple(sorted(paths))


def _validate_document(document: dict[str, Any]) -> None:
    errors = sorted(
        _SCHEMA_VALIDATOR.iter_errors(document),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        error = errors[0]
        path = "/".join(str(item) for item in error.absolute_path) or "$"
        raise EvidenceBundleValidationError(
            f"evidence bundle schema validation failed at {path}: {error.message}"
        )


def _require_document_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceBundleValidationError(f"evidence {name} must be an object")
    return dict(value)


def _require_document_array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceBundleValidationError(f"evidence {name} must be an array")
    return value


def _require_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise EvidenceBundleValidationError(
            f"{name} must be a stable 1-256 character identifier"
        )


def _require_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise EvidenceBundleValidationError(f"{name} must be a SHA-256 hex digest")


def _require_timestamp(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceBundleValidationError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _parse_external_timestamp(name: str, value: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceBundleValidationError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceBundleValidationError(
            f"{name} must be an RFC 3339 timestamp"
        ) from exc
    return _require_timestamp(name, parsed)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _enum_value(value: str | Enum) -> str:
    return value.value if isinstance(value, Enum) else value
