"""Detached external-continuity and receipt-verification boundaries.

The v1 evidence bundle remains receipt-free and self-contained. This module
defines the narrow, caller-supplied inputs that an offline verifier may use to
check a protected external sequence or a tool-specific receipt. It owns no
network transport, runtime dispatch, persistence, or provider payload storage.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ._internal.serialization.canonical import rfc8785_json_bytes
from .evidence import EvidenceBundle

ANCHOR_PROVIDER_ENTRY_POINT_GROUP = "agent_runtime_governance.evidence_anchor_providers"
RECEIPT_VERIFIER_ENTRY_POINT_GROUP = "agent_runtime_governance.evidence_receipt_verifiers"

_ANCHOR_SCHEMA_VERSION = "1"
_RECEIPT_SCHEMA_VERSION = "1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_ANCHOR_ENTRIES = 4096
_MAX_RECEIPT_BYTES = 65536
_RECEIPT_REQUEST_DOMAIN = b"arg.evidence.receipt-request.v1\0"
_EXECUTION_STATUSES = frozenset({"succeeded", "failed", "unknown"})
_VERIFIED_OUTCOMES = frozenset({"succeeded", "failed"})
_RESULT_STATES = frozenset({"passed", "failed", "unsupported"})


class EvidenceExternalValidationError(ValueError):
    """Raised when a detached external-verification value is malformed."""


@dataclass(frozen=True, slots=True)
class AnchorSequenceEntry:
    """One privacy-safe item in a protected evidence-anchor sequence."""

    position: int
    bundle_id: str
    bundle_digest: str

    def __post_init__(self) -> None:
        if type(self.position) is not int or self.position < 1:
            raise EvidenceExternalValidationError("anchor entry position must be positive")
        _require_identifier("anchor entry bundle_id", self.bundle_id)
        _require_digest("anchor entry bundle_digest", self.bundle_digest)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AnchorSequenceEntry":
        """Parse one strict detached anchor-sequence entry."""

        data = _require_mapping(document, "anchor entry")
        _require_exact_keys(
            data,
            {"position", "bundle_id", "bundle_digest"},
            "anchor entry",
        )
        return cls(
            position=data["position"],
            bundle_id=data["bundle_id"],
            bundle_digest=data["bundle_digest"],
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the bounded portable anchor-sequence representation."""

        return {
            "position": self.position,
            "bundle_id": self.bundle_id,
            "bundle_digest": self.bundle_digest,
        }


@dataclass(frozen=True, slots=True)
class AnchorVerificationRequest:
    """A bounded candidate sequence to compare with a protected anchor."""

    sequence_id: str
    entries: tuple[AnchorSequenceEntry, ...]
    subject_bundle_id: str
    subject_bundle_digest: str
    tenant_digest: str
    schema_version: str = field(default=_ANCHOR_SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        _require_identifier("anchor sequence_id", self.sequence_id)
        _require_identifier("anchor subject_bundle_id", self.subject_bundle_id)
        _require_digest("anchor subject_bundle_digest", self.subject_bundle_digest)
        _require_digest("anchor tenant_digest", self.tenant_digest)
        if isinstance(self.entries, str | bytes) or not isinstance(self.entries, Sequence):
            raise TypeError("anchor entries must be a sequence of AnchorSequenceEntry")
        entries = tuple(self.entries)
        if not entries or len(entries) > _MAX_ANCHOR_ENTRIES:
            raise EvidenceExternalValidationError(
                f"anchor entries must contain 1 to {_MAX_ANCHOR_ENTRIES} values"
            )
        if any(not isinstance(item, AnchorSequenceEntry) for item in entries):
            raise TypeError("anchor entries must contain AnchorSequenceEntry values")
        _validate_anchor_entries(entries)
        object.__setattr__(self, "entries", entries)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AnchorVerificationRequest":
        """Parse a strict detached anchor-continuity request document."""

        data = _require_mapping(document, "anchor request")
        _require_exact_keys(
            data,
            {
                "anchor_schema_version",
                "sequence_id",
                "entries",
                "subject_bundle_id",
                "subject_bundle_digest",
                "tenant_digest",
            },
            "anchor request",
        )
        if data["anchor_schema_version"] != _ANCHOR_SCHEMA_VERSION:
            raise EvidenceExternalValidationError("unsupported anchor_schema_version")
        entries_data = data["entries"]
        if isinstance(entries_data, str | bytes) or not isinstance(entries_data, Sequence):
            raise EvidenceExternalValidationError("anchor entries must be an array")
        return cls(
            sequence_id=data["sequence_id"],
            entries=tuple(AnchorSequenceEntry.from_dict(item) for item in entries_data),
            subject_bundle_id=data["subject_bundle_id"],
            subject_bundle_digest=data["subject_bundle_digest"],
            tenant_digest=data["tenant_digest"],
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the strict portable anchor-continuity request document."""

        return {
            "anchor_schema_version": self.schema_version,
            "sequence_id": self.sequence_id,
            "entries": [entry.to_dict() for entry in self.entries],
            "subject_bundle_id": self.subject_bundle_id,
            "subject_bundle_digest": self.subject_bundle_digest,
            "tenant_digest": self.tenant_digest,
        }


@dataclass(frozen=True, slots=True)
class AnchorVerificationResult:
    """A provider's bounded continuity decision without anchor payloads."""

    state: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.state not in _RESULT_STATES:
            raise EvidenceExternalValidationError("anchor result state is invalid")
        if self.state == "passed":
            if self.reason is not None:
                raise EvidenceExternalValidationError(
                    "passed anchor result must not include a reason"
                )
            return
        if self.reason is None:
            raise EvidenceExternalValidationError(
                "non-passed anchor result must include a reason"
            )
        _require_identifier("anchor result reason", self.reason)


@runtime_checkable
class AnchorProvider(Protocol):
    """Checks a bounded candidate sequence against a protected external anchor."""

    provider_id: str
    protocol_version: str

    def verify_continuity(
        self, request: AnchorVerificationRequest
    ) -> AnchorVerificationResult: ...


class InMemoryAnchorProvider:
    """Reference-only protected sequence provider for deterministic tests.

    It is intentionally process-local and does not claim production-grade
    protection. Deployments must provide an independently protected provider.
    """

    provider_id = "in-memory-anchor-v1"
    protocol_version = "1"

    def __init__(
        self,
        *,
        sequence_id: str,
        tenant_digest: str,
        protected_entries: Sequence[AnchorSequenceEntry] = (),
    ) -> None:
        _require_identifier("protected anchor sequence_id", sequence_id)
        _require_digest("protected anchor tenant_digest", tenant_digest)
        if isinstance(protected_entries, str | bytes) or not isinstance(
            protected_entries, Sequence
        ):
            raise TypeError("protected_entries must be a sequence of AnchorSequenceEntry")
        entries = tuple(protected_entries)
        if len(entries) > _MAX_ANCHOR_ENTRIES:
            raise EvidenceExternalValidationError(
                f"protected_entries must contain at most {_MAX_ANCHOR_ENTRIES} values"
            )
        if any(not isinstance(item, AnchorSequenceEntry) for item in entries):
            raise TypeError("protected_entries must contain AnchorSequenceEntry values")
        if entries:
            _validate_anchor_entries(entries)
        self._sequence_id = sequence_id
        self._tenant_digest = tenant_digest
        self._protected_entries = entries

    def append(self, bundle_id: str, bundle_digest: str) -> AnchorSequenceEntry:
        """Append one local reference entry for deterministic fixture setup."""

        entry = AnchorSequenceEntry(
            position=len(self._protected_entries) + 1,
            bundle_id=bundle_id,
            bundle_digest=bundle_digest,
        )
        updated = (*self._protected_entries, entry)
        if len(updated) > _MAX_ANCHOR_ENTRIES:
            raise EvidenceExternalValidationError(
                f"protected_entries must contain at most {_MAX_ANCHOR_ENTRIES} values"
            )
        _validate_anchor_entries(updated)
        self._protected_entries = updated
        return entry

    def verify_continuity(
        self, request: AnchorVerificationRequest
    ) -> AnchorVerificationResult:
        """Compare a candidate history with the provider's protected sequence."""

        if (
            request.sequence_id != self._sequence_id
            or request.tenant_digest != self._tenant_digest
        ):
            return AnchorVerificationResult("unsupported", "anchor_sequence_unavailable")
        protected = self._protected_entries
        if not protected:
            return AnchorVerificationResult("unsupported", "anchor_sequence_unavailable")
        subject_count = sum(
            entry.bundle_id == request.subject_bundle_id
            and entry.bundle_digest == request.subject_bundle_digest
            for entry in request.entries
        )
        if subject_count != 1:
            return AnchorVerificationResult("failed", "anchor_subject_missing")
        if request.entries == protected:
            return AnchorVerificationResult("passed")
        if _is_subsequence(request.entries, protected):
            return AnchorVerificationResult("failed", "anchor_sequence_deletion_detected")
        if {
            (entry.bundle_id, entry.bundle_digest) for entry in request.entries
        } == {
            (entry.bundle_id, entry.bundle_digest) for entry in protected
        } and len(request.entries) == len(protected):
            return AnchorVerificationResult("failed", "anchor_sequence_reordered")
        return AnchorVerificationResult("failed", "anchor_sequence_mismatch")


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptAttachment:
    """A bounded detached receipt bound to one evidence bundle digest."""

    bundle_digest: str
    value: str
    schema_version: str = field(default=_RECEIPT_SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        _require_digest("receipt bundle_digest", self.bundle_digest)
        _decode_receipt_value(self.value)

    @property
    def receipt_bytes(self) -> bytes:
        """Return the validated receipt bytes without exposing them in reprs."""

        return _decode_receipt_value(self.value)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "ReceiptAttachment":
        """Parse a strict detached receipt attachment document."""

        data = _require_mapping(document, "receipt attachment")
        _require_exact_keys(
            data,
            {"receipt_schema_version", "bundle_digest", "value"},
            "receipt attachment",
        )
        if data["receipt_schema_version"] != _RECEIPT_SCHEMA_VERSION:
            raise EvidenceExternalValidationError("unsupported receipt_schema_version")
        return cls(bundle_digest=data["bundle_digest"], value=data["value"])

    def to_dict(self) -> dict[str, str]:
        """Return the detached receipt document without bundle contents."""

        _ = self.receipt_bytes
        return {
            "receipt_schema_version": self.schema_version,
            "bundle_digest": self.bundle_digest,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptVerificationRequest:
    """The bounded bundle identity and detached receipt given to one verifier."""

    bundle_id: str
    bundle_digest: str
    action_digest: str
    contract_id: str
    contract_version: int
    contract_digest: str
    tenant_digest: str
    execution_record_id: str
    execution_status: str
    receipt: ReceiptAttachment = field(repr=False)

    def __post_init__(self) -> None:
        _require_identifier("receipt bundle_id", self.bundle_id)
        _require_digest("receipt bundle_digest", self.bundle_digest)
        _require_digest("receipt action_digest", self.action_digest)
        _require_identifier("receipt contract_id", self.contract_id)
        if type(self.contract_version) is not int or self.contract_version < 1:
            raise EvidenceExternalValidationError("receipt contract_version must be positive")
        _require_digest("receipt contract_digest", self.contract_digest)
        _require_digest("receipt tenant_digest", self.tenant_digest)
        _require_identifier("receipt execution_record_id", self.execution_record_id)
        if self.execution_status not in _EXECUTION_STATUSES:
            raise EvidenceExternalValidationError("receipt execution_status is invalid")
        if not isinstance(self.receipt, ReceiptAttachment):
            raise TypeError("receipt must be a ReceiptAttachment")
        if self.receipt.bundle_digest != self.bundle_digest:
            raise EvidenceExternalValidationError("receipt bundle_digest must match request")

    @classmethod
    def from_bundle(
        cls, bundle: EvidenceBundle, receipt: ReceiptAttachment
    ) -> "ReceiptVerificationRequest":
        """Project the minimal verifier input from one parsed evidence bundle."""

        if not isinstance(bundle, EvidenceBundle):
            raise TypeError("bundle must be an EvidenceBundle")
        return cls(
            bundle_id=bundle.bundle_id,
            bundle_digest=bundle.bundle_digest,
            action_digest=bundle.action.action_digest,
            contract_id=bundle.action.contract_id,
            contract_version=bundle.action.contract_version,
            contract_digest=bundle.action.contract_digest,
            tenant_digest=bundle.identity.tenant_digest,
            execution_record_id=bundle.execution.execution_record_id,
            execution_status=bundle.execution.status,
            receipt=receipt,
        )

    @property
    def binding_digest(self) -> str:
        """Return the canonical digest a receipt verifier must bind to.

        The digest intentionally excludes the raw receipt, which is separately
        checked by the verifier. It prevents a reference verifier from treating
        the same receipt as evidence for another bundle, tenant, action, or
        execution identity.
        """

        document = {
            "action_digest": self.action_digest,
            "bundle_digest": self.bundle_digest,
            "bundle_id": self.bundle_id,
            "contract_digest": self.contract_digest,
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "execution_record_id": self.execution_record_id,
            "execution_status": self.execution_status,
            "tenant_digest": self.tenant_digest,
        }
        return hashlib.sha256(
            _RECEIPT_REQUEST_DOMAIN + rfc8785_json_bytes(document)
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ReceiptVerificationResult:
    """A receipt verifier's safe outcome claim without raw receipt data."""

    state: str
    outcome: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.state not in _RESULT_STATES:
            raise EvidenceExternalValidationError("receipt result state is invalid")
        if self.state == "passed":
            if self.outcome not in _VERIFIED_OUTCOMES or self.reason is not None:
                raise EvidenceExternalValidationError(
                    "passed receipt result must contain one verified outcome only"
                )
            return
        if self.outcome is not None or self.reason is None:
            raise EvidenceExternalValidationError(
                "non-passed receipt result must contain a reason only"
            )
        _require_identifier("receipt result reason", self.reason)


@dataclass(frozen=True, slots=True)
class ReceiptVerificationExpectation:
    """A raw-receipt-free reference expectation bound to one request identity."""

    binding_digest: str
    receipt_digest: str
    outcome: str

    def __post_init__(self) -> None:
        _require_digest("receipt expectation binding_digest", self.binding_digest)
        _require_digest("receipt expectation receipt_digest", self.receipt_digest)
        if self.outcome not in _VERIFIED_OUTCOMES:
            raise EvidenceExternalValidationError("receipt expectation outcome is invalid")

    @classmethod
    def from_request(
        cls,
        request: ReceiptVerificationRequest,
        *,
        outcome: str,
    ) -> "ReceiptVerificationExpectation":
        """Create one reference expectation without retaining receipt bytes."""

        if not isinstance(request, ReceiptVerificationRequest):
            raise TypeError("request must be a ReceiptVerificationRequest")
        return cls(
            binding_digest=request.binding_digest,
            receipt_digest=hashlib.sha256(request.receipt.receipt_bytes).hexdigest(),
            outcome=outcome,
        )


@runtime_checkable
class ReceiptVerifier(Protocol):
    """Verifies one detached receipt against the minimal evidence identity."""

    verifier_id: str
    protocol_version: str

    def verify(self, request: ReceiptVerificationRequest) -> ReceiptVerificationResult: ...


class UnsupportedReceiptVerifier:
    """Reference verifier that explicitly declines external outcome checking."""

    verifier_id = "unsupported-receipt-verifier-v1"
    protocol_version = "1"

    def verify(self, request: ReceiptVerificationRequest) -> ReceiptVerificationResult:
        """Return the explicit unsupported result without inspecting the receipt."""

        if not isinstance(request, ReceiptVerificationRequest):
            raise TypeError("request must be a ReceiptVerificationRequest")
        return ReceiptVerificationResult("unsupported", reason="receipt_verifier_unsupported")


class InMemoryReceiptVerifier:
    """Reference verifier bound to a complete request identity and receipt hash."""

    verifier_id = "in-memory-receipt-verifier-v1"
    protocol_version = "1"

    def __init__(
        self,
        expectations: Sequence[ReceiptVerificationExpectation] = (),
    ) -> None:
        if isinstance(expectations, str | bytes) or not isinstance(
            expectations, Sequence
        ):
            raise TypeError("expectations must be a sequence of ReceiptVerificationExpectation")
        entries = tuple(expectations)
        if len(entries) > _MAX_ANCHOR_ENTRIES:
            raise EvidenceExternalValidationError("receipt expectations are too large")
        if any(not isinstance(item, ReceiptVerificationExpectation) for item in entries):
            raise TypeError(
                "expectations must contain ReceiptVerificationExpectation values"
            )
        if len({item.binding_digest for item in entries}) != len(entries):
            raise EvidenceExternalValidationError(
                "receipt expectations must not repeat a binding_digest"
            )
        expected = {
            item.binding_digest: (item.receipt_digest, item.outcome) for item in entries
        }
        self._expected = expected

    def verify(self, request: ReceiptVerificationRequest) -> ReceiptVerificationResult:
        """Verify the detached receipt digest and return its configured outcome."""

        if not isinstance(request, ReceiptVerificationRequest):
            raise TypeError("request must be a ReceiptVerificationRequest")
        expected = self._expected.get(request.binding_digest)
        if expected is None:
            return ReceiptVerificationResult("failed", reason="receipt_not_found")
        receipt_digest, outcome = expected
        actual_digest = hashlib.sha256(request.receipt.receipt_bytes).hexdigest()
        if not hmac.compare_digest(receipt_digest, actual_digest):
            return ReceiptVerificationResult("failed", reason="receipt_not_verified")
        return ReceiptVerificationResult("passed", outcome=outcome)


def _validate_anchor_entries(entries: tuple[AnchorSequenceEntry, ...]) -> None:
    positions = tuple(item.position for item in entries)
    if positions != tuple(range(1, len(entries) + 1)):
        raise EvidenceExternalValidationError("anchor entry positions must be contiguous")
    identities = tuple((item.bundle_id, item.bundle_digest) for item in entries)
    if len(set(identities)) != len(identities):
        raise EvidenceExternalValidationError("anchor entries must not repeat a bundle")
    bundle_ids = tuple(item.bundle_id for item in entries)
    if len(set(bundle_ids)) != len(bundle_ids):
        raise EvidenceExternalValidationError("anchor entries must not repeat a bundle_id")


def _is_subsequence(
    candidate: tuple[AnchorSequenceEntry, ...],
    protected: tuple[AnchorSequenceEntry, ...],
) -> bool:
    """Return whether candidate identities preserve protected sequence order.

    Candidate positions are local to the supplied history and must therefore
    remain contiguous even when a malicious or incomplete copy has omitted an
    entry.  Compare the stable bundle identity rather than those local
    positions so an omitted middle entry is classified as a deletion instead
    of an opaque mismatch.
    """

    iterator = iter(protected)
    return all(
        any(
            (item.bundle_id, item.bundle_digest)
            == (expected.bundle_id, expected.bundle_digest)
            for expected in iterator
        )
        for item in candidate
    )


def _decode_receipt_value(value: str) -> bytes:
    if not isinstance(value, str):
        raise EvidenceExternalValidationError("receipt value must be canonical base64")
    max_base64_length = 4 * ((_MAX_RECEIPT_BYTES + 2) // 3)
    if not value or len(value) > max_base64_length:
        raise EvidenceExternalValidationError("receipt value has an invalid length")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise EvidenceExternalValidationError("receipt value must be canonical base64") from exc
    if not decoded or len(decoded) > _MAX_RECEIPT_BYTES:
        raise EvidenceExternalValidationError("receipt value has an invalid length")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise EvidenceExternalValidationError("receipt value must be canonical base64")
    return decoded


def _require_mapping(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return value


def _require_exact_keys(
    document: Mapping[str, Any], expected: set[str], name: str
) -> None:
    if set(document) != expected:
        raise EvidenceExternalValidationError(f"{name} fields are invalid")


def _require_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise EvidenceExternalValidationError(f"{name} must be an identifier")


def _require_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise EvidenceExternalValidationError(f"{name} must be a SHA-256 hex digest")
