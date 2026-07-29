"""Detached, privacy-safe explanations for deterministic policy decisions.

An explanation attachment is not an authorizer, runtime snapshot, or audit log.
It commits only to stable policy-control outcomes for an already bound action.
The v0.8 Evidence Bundle remains unchanged and may be referenced by digest.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator

from ._internal.serialization.canonical import CanonicalJsonError, rfc8785_json_bytes

if TYPE_CHECKING:
    from .context import ExecutionContext
    from .evidence import EvidenceBundle

_ATTACHMENT_SCHEMA_VERSION = "1"
_ATTACHMENT_DOMAIN = b"arg.decision-explanation.v1\0"
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_DECISIONS = frozenset({"allow", "deny"})
_RISK_TIERS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_CONTROL_EFFECTS = frozenset({"allow", "deny", "require_approval", "risk"})
_CONTROL_RESULTS = frozenset({"matched", "not_matched", "not_applicable"})
_HISTORY_CONTROLS_KEY = "decision_explanation_controls"
_HISTORY_UNAVAILABLE_KEY = "decision_explanation_unavailable"


class DecisionExplanationValidationError(ValueError):
    """Raised when an attachment is not a closed v1 decision explanation."""


DECISION_EXPLANATION_ATTACHMENT_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "action_digest",
        "evidence_bundle_digest",
        "policy_version",
        "policy_digest",
        "final_decision",
        "risk_tier",
        "requires_approval",
        "controls",
    ],
    "properties": {
        "schema_version": {"const": _ATTACHMENT_SCHEMA_VERSION},
        "action_digest": {"$ref": "#/$defs/digest"},
        "evidence_bundle_digest": {
            "oneOf": [
                {"type": "null"},
                {"$ref": "#/$defs/digest"},
            ]
        },
        "policy_version": {"type": "string", "pattern": _IDENTIFIER.pattern},
        "policy_digest": {"$ref": "#/$defs/digest"},
        "final_decision": {"enum": sorted(_DECISIONS)},
        "risk_tier": {"enum": sorted(_RISK_TIERS)},
        "requires_approval": {"type": "boolean"},
        "controls": {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/$defs/control"},
        },
    },
    "$defs": {
        "digest": {"type": "string", "pattern": _SHA256_HEX.pattern},
        "control": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "control_id",
                "control_version",
                "effect",
                "result",
                "reason_code",
            ],
            "properties": {
                "control_id": {"type": "string", "pattern": _IDENTIFIER.pattern},
                "control_version": {"type": "integer", "minimum": 1},
                "effect": {"enum": sorted(_CONTROL_EFFECTS)},
                "result": {"enum": sorted(_CONTROL_RESULTS)},
                "reason_code": {"type": "string", "pattern": _IDENTIFIER.pattern},
            },
        },
    },
}
Draft202012Validator.check_schema(DECISION_EXPLANATION_ATTACHMENT_SCHEMA_V1)
_SCHEMA_VALIDATOR = Draft202012Validator(DECISION_EXPLANATION_ATTACHMENT_SCHEMA_V1)


@dataclass(frozen=True, slots=True)
class DecisionControl:
    """One privacy-safe, deterministic policy-control outcome."""

    control_id: str
    control_version: int
    effect: str
    result: str
    reason_code: str

    def __post_init__(self) -> None:
        _require_identifier("control_id", self.control_id)
        if type(self.control_version) is not int or self.control_version < 1:
            raise DecisionExplanationValidationError(
                "control_version must be a positive integer"
            )
        if self.effect not in _CONTROL_EFFECTS:
            raise DecisionExplanationValidationError("control effect is not supported")
        if self.result not in _CONTROL_RESULTS:
            raise DecisionExplanationValidationError("control result is not supported")
        _require_identifier("reason_code", self.reason_code)

    @property
    def identity(self) -> tuple[str, int]:
        """Return the immutable control identity used for ordering and uniqueness."""

        return self.control_id, self.control_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_version": self.control_version,
            "effect": self.effect,
            "result": self.result,
            "reason_code": self.reason_code,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "DecisionControl":
        if not isinstance(document, Mapping):
            raise DecisionExplanationValidationError("control must be an object")
        required = {
            "control_id",
            "control_version",
            "effect",
            "result",
            "reason_code",
        }
        if set(document) != required:
            raise DecisionExplanationValidationError("control fields are invalid")
        return cls(
            control_id=document["control_id"],
            control_version=document["control_version"],
            effect=document["effect"],
            result=document["result"],
            reason_code=document["reason_code"],
        )


@dataclass(frozen=True, slots=True, repr=False)
class DecisionExplanationAttachment:
    """A canonical commitment to one deterministic policy decision."""

    action_digest: str
    policy_version: str
    policy_digest: str
    final_decision: str
    risk_tier: str
    requires_approval: bool
    controls: tuple[DecisionControl, ...]
    evidence_bundle_digest: str | None = None
    schema_version: str = field(default=_ATTACHMENT_SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        _require_digest("action_digest", self.action_digest)
        _require_identifier("policy_version", self.policy_version)
        _require_digest("policy_digest", self.policy_digest)
        if self.final_decision not in _DECISIONS:
            raise DecisionExplanationValidationError("final_decision must be allow or deny")
        if self.risk_tier not in _RISK_TIERS:
            raise DecisionExplanationValidationError("risk_tier is not supported")
        if type(self.requires_approval) is not bool:
            raise DecisionExplanationValidationError("requires_approval must be a boolean")
        if self.evidence_bundle_digest is not None:
            _require_digest("evidence_bundle_digest", self.evidence_bundle_digest)

        controls = _normalize_controls(self.controls)
        _validate_control_consistency(
            controls,
            final_decision=self.final_decision,
            requires_approval=self.requires_approval,
        )
        object.__setattr__(self, "controls", controls)
        self._validate_for_serialization()

    @classmethod
    def from_context(
        cls,
        context: "ExecutionContext",
        *,
        evidence_bundle: "EvidenceBundle | None" = None,
        controls: Sequence[DecisionControl] | None = None,
    ) -> "DecisionExplanationAttachment":
        """Create an attachment from a completed policy evaluation context.

        Built-in middleware records only structured controls in context history.
        External integrations must pass their explicit ``controls`` contract;
        a free-text policy reason is never projected into the attachment.
        """

        from .action_contracts import BoundAction
        from .context import ExecutionContext

        if not isinstance(context, ExecutionContext):
            raise TypeError("context must be an ExecutionContext")
        action = context.bound_action
        if not isinstance(action, BoundAction):
            raise DecisionExplanationValidationError(
                "decision explanations require a bound action"
            )
        if action.policy_version is None or action.policy_digest is None:
            raise DecisionExplanationValidationError(
                "decision explanations require bound policy identity"
            )

        _validate_recorded_policy_identity(
            context,
            policy_version=action.policy_version,
            policy_digest=action.policy_digest,
        )
        source_controls = (
            controls_from_context(context) if controls is None else tuple(controls)
        )
        ordered_controls = _canonical_control_order(source_controls)
        final_decision = _final_decision_from_controls(ordered_controls)
        bundle_digest = _bundle_digest_for_action(evidence_bundle, action)
        return cls(
            action_digest=action.action_digest,
            policy_version=action.policy_version,
            policy_digest=action.policy_digest,
            final_decision=final_decision,
            risk_tier=context.risk_tier.name,
            requires_approval=context.requires_approval,
            controls=ordered_controls,
            evidence_bundle_digest=bundle_digest,
        )

    @classmethod
    def from_dict(
        cls, document: Mapping[str, Any]
    ) -> "DecisionExplanationAttachment":
        """Restore one strict canonical v1 attachment."""

        if not isinstance(document, Mapping):
            raise DecisionExplanationValidationError("attachment must be an object")
        data = dict(document)
        _validate_document(data)
        controls = tuple(
            DecisionControl.from_dict(item)
            for item in _require_array(data["controls"], "controls")
        )
        attachment = cls(
            action_digest=data["action_digest"],
            evidence_bundle_digest=data["evidence_bundle_digest"],
            policy_version=data["policy_version"],
            policy_digest=data["policy_digest"],
            final_decision=data["final_decision"],
            risk_tier=data["risk_tier"],
            requires_approval=data["requires_approval"],
            controls=controls,
        )
        if attachment.to_dict() != data:
            raise DecisionExplanationValidationError(
                "attachment must use the canonical v1 representation"
            )
        return attachment

    @property
    def attachment_digest(self) -> str:
        """Return the domain-separated digest of this detached attachment."""

        return hashlib.sha256(self.commitment_bytes()).hexdigest()

    @property
    def digest(self) -> str:
        """Alias for :attr:`attachment_digest`."""

        return self.attachment_digest

    def canonical_bytes(self) -> bytes:
        """Return the RFC 8785 bytes committed by :attr:`attachment_digest`."""

        try:
            return rfc8785_json_bytes(self.to_dict_unchecked())
        except CanonicalJsonError as exc:
            raise DecisionExplanationValidationError(
                "attachment is not RFC 8785 canonicalizable"
            ) from exc

    def commitment_bytes(self) -> bytes:
        """Return the domain-separated bytes committed by the attachment."""

        return _ATTACHMENT_DOMAIN + self.canonical_bytes()

    def to_dict(self) -> dict[str, Any]:
        """Return the already-validated closed v1 representation."""

        return self.to_dict_unchecked()

    def _validate_for_serialization(
        self, document: dict[str, Any] | None = None
    ) -> None:
        _validate_document(self.to_dict_unchecked() if document is None else document)

    def to_dict_unchecked(self) -> dict[str, Any]:
        """Build the closed representation without recursively validating it."""

        return {
            "schema_version": self.schema_version,
            "action_digest": self.action_digest,
            "evidence_bundle_digest": self.evidence_bundle_digest,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "final_decision": self.final_decision,
            "risk_tier": self.risk_tier,
            "requires_approval": self.requires_approval,
            "controls": [item.to_dict() for item in self.controls],
        }


def controls_from_context(context: "ExecutionContext") -> tuple[DecisionControl, ...]:
    """Read only explicit, structured controls recorded by policy middleware."""

    from .context import ExecutionContext

    if not isinstance(context, ExecutionContext):
        raise TypeError("context must be an ExecutionContext")
    controls: list[DecisionControl] = []
    for entry in context.history:
        data = entry.data
        if _HISTORY_UNAVAILABLE_KEY in data:
            if data[_HISTORY_UNAVAILABLE_KEY] is not True:
                raise DecisionExplanationValidationError(
                    "decision explanation availability marker is invalid"
                )
            raise DecisionExplanationValidationError(
                "a policy evaluation did not provide structured controls"
            )
        if _HISTORY_CONTROLS_KEY not in data:
            continue
        raw_controls = data[_HISTORY_CONTROLS_KEY]
        if isinstance(raw_controls, str | bytes) or not isinstance(
            raw_controls, Sequence
        ):
            raise DecisionExplanationValidationError(
                "recorded decision controls must be a sequence"
            )
        for item in raw_controls:
            if not isinstance(item, Mapping):
                raise DecisionExplanationValidationError(
                    "recorded decision controls must be objects"
                )
            controls.append(DecisionControl.from_dict(item))
    if not controls:
        raise DecisionExplanationValidationError(
            "decision explanation requires structured controls"
        )
    return tuple(controls)


def decision_controls_history_data(
    controls: Sequence[DecisionControl],
) -> dict[str, list[dict[str, Any]]]:
    """Return the narrow history projection used by built-in middleware."""

    normalized = _normalize_control_items(controls)
    return {_HISTORY_CONTROLS_KEY: [item.to_dict() for item in normalized]}


def unavailable_decision_controls_history_data() -> dict[str, bool]:
    """Mark a policy event that had no explicit structured-control contract."""

    return {_HISTORY_UNAVAILABLE_KEY: True}


def _bundle_digest_for_action(
    evidence_bundle: "EvidenceBundle | None", action: Any
) -> str | None:
    if evidence_bundle is None:
        return None
    from .evidence import EvidenceBundle

    if not isinstance(evidence_bundle, EvidenceBundle):
        raise TypeError("evidence_bundle must be an EvidenceBundle")
    if evidence_bundle.action.action_digest != action.action_digest:
        raise DecisionExplanationValidationError(
            "evidence bundle action_digest does not match the bound action"
        )
    if (
        evidence_bundle.policy.version != action.policy_version
        or evidence_bundle.policy.digest != action.policy_digest
    ):
        raise DecisionExplanationValidationError(
            "evidence bundle policy identity does not match the bound action"
        )
    return evidence_bundle.bundle_digest


def _validate_recorded_policy_identity(
    context: "ExecutionContext", *, policy_version: str, policy_digest: str
) -> None:
    for entry in context.history:
        data = entry.data
        if (
            _HISTORY_CONTROLS_KEY not in data
            and _HISTORY_UNAVAILABLE_KEY not in data
        ):
            continue
        version = data.get("policy_version")
        digest = data.get("policy_digest")
        if (version is None) != (digest is None):
            raise DecisionExplanationValidationError(
                "recorded policy identity must include version and digest together"
            )
        if version is not None and (
            version != policy_version or digest != policy_digest
        ):
            raise DecisionExplanationValidationError(
                "recorded policy identity does not match the bound action"
            )


def _final_decision_from_controls(controls: tuple[DecisionControl, ...]) -> str:
    return (
        "deny"
        if any(item.effect == "deny" and item.result == "matched" for item in controls)
        else "allow"
    )


def _normalize_controls(value: Sequence[DecisionControl]) -> tuple[DecisionControl, ...]:
    controls = _normalize_control_items(value)
    if not controls:
        raise DecisionExplanationValidationError("controls must not be empty")
    identities = tuple(item.identity for item in controls)
    if len(set(identities)) != len(identities):
        raise DecisionExplanationValidationError("controls must not contain duplicates")
    if identities != tuple(sorted(identities)):
        raise DecisionExplanationValidationError(
            "controls must be ordered by control_id and control_version"
        )
    return controls


def _normalize_control_items(value: Sequence[DecisionControl]) -> tuple[DecisionControl, ...]:
    if isinstance(value, str | bytes) or not isinstance(value, Sequence):
        raise TypeError("controls must be a sequence of DecisionControl values")
    controls = tuple(value)
    if any(not isinstance(item, DecisionControl) for item in controls):
        raise TypeError("controls must contain DecisionControl values")
    return controls


def _canonical_control_order(
    value: Sequence[DecisionControl],
) -> tuple[DecisionControl, ...]:
    controls = _normalize_control_items(value)
    if len({item.identity for item in controls}) != len(controls):
        raise DecisionExplanationValidationError("controls must not contain duplicates")
    return tuple(sorted(controls, key=lambda item: item.identity))


def _validate_control_consistency(
    controls: tuple[DecisionControl, ...],
    *,
    final_decision: str,
    requires_approval: bool,
) -> None:
    denied = any(
        item.effect == "deny" and item.result == "matched" for item in controls
    )
    allowed = any(
        item.effect == "allow" and item.result == "matched" for item in controls
    )
    approval_required = any(
        item.effect == "require_approval" and item.result == "matched"
        for item in controls
    )
    if final_decision == "deny" and not denied:
        raise DecisionExplanationValidationError(
            "a denied final_decision requires a matched deny control"
        )
    if final_decision == "allow" and denied:
        raise DecisionExplanationValidationError(
            "an allowed final_decision cannot contain a matched deny control"
        )
    if final_decision == "allow" and not allowed:
        raise DecisionExplanationValidationError(
            "an allowed final_decision requires a matched allow control"
        )
    if approval_required and not requires_approval:
        raise DecisionExplanationValidationError(
            "a matched approval control requires requires_approval=True"
        )


def _validate_document(document: dict[str, Any]) -> None:
    errors = sorted(
        _SCHEMA_VALIDATOR.iter_errors(document),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        error = errors[0]
        path = "/".join(str(item) for item in error.absolute_path) or "$"
        raise DecisionExplanationValidationError(
            f"attachment schema validation failed at {path}: {error.message}"
        )


def _require_array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise DecisionExplanationValidationError(f"{name} must be an array")
    return value


def _require_identifier(name: str, value: Any) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise DecisionExplanationValidationError(
            f"{name} must be a stable 1-256 character identifier"
        )


def _require_digest(name: str, value: Any) -> None:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise DecisionExplanationValidationError(f"{name} must be a SHA-256 hex digest")
