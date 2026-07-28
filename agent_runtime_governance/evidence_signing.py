"""Detached, privacy-safe evidence signatures and explicit trust roots.

Evidence Bundle v1 remains unsigned by design.  This module binds a detached
signature attachment to its stable unsigned bundle digest, so attaching or
rotating a signature never changes the bundle's canonical payload or digest.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from jsonschema import Draft202012Validator

from ._internal.evidence import ed25519 as _evidence_ed25519
from ._internal.serialization.canonical import CanonicalJsonError, rfc8785_json_bytes
from .evidence import EvidenceBundle

_SIGNATURE_SCHEMA_VERSION = "1"
_SIGNATURE_DOMAIN = b"arg.evidence.signature.v1\0"
_ED25519 = "ed25519"
_ED25519_PUBLIC_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class EvidenceSigningError(ValueError):
    """Base class for evidence-signing failures."""


class EvidenceSigningDependencyError(EvidenceSigningError):
    """Raised when an optional evidence-signing dependency is unavailable."""


class EvidenceSignatureValidationError(EvidenceSigningError):
    """Raised when a detached signature attachment is malformed."""


class EvidenceTrustRootValidationError(EvidenceSigningError):
    """Raised when configured evidence trust roots are malformed."""


class EvidenceSignatureVerificationError(EvidenceSigningError):
    """Raised when an evidence signature cannot be trusted or verified."""


EVIDENCE_SIGNATURE_ATTACHMENT_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "signature_schema_version",
        "key_id",
        "algorithm",
        "bundle_digest",
        "value",
    ],
    "properties": {
        "signature_schema_version": {"const": _SIGNATURE_SCHEMA_VERSION},
        "key_id": {"type": "string", "pattern": _IDENTIFIER.pattern},
        "algorithm": {"const": _ED25519},
        "bundle_digest": {"type": "string", "pattern": _SHA256_HEX.pattern},
        "value": {
            "type": "string",
            "minLength": 88,
            "maxLength": 88,
            "pattern": r"^[A-Za-z0-9+/]{86}==$",
        },
    },
}

EVIDENCE_TRUST_ROOTS_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["keys"],
    "properties": {
        "keys": {
            "type": "array",
            "items": {"$ref": "#/$defs/key"},
        }
    },
    "$defs": {
        "key": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "key_id",
                "algorithm",
                "public_key",
                "not_before",
                "not_after",
                "revoked",
            ],
            "properties": {
                "key_id": {"type": "string", "pattern": _IDENTIFIER.pattern},
                "algorithm": {"const": _ED25519},
                "public_key": {
                    "type": "string",
                    "minLength": 44,
                    "maxLength": 44,
                    "pattern": r"^[A-Za-z0-9+/]{43}=$",
                },
                "not_before": {"type": "string", "format": "date-time"},
                "not_after": {"type": "string", "format": "date-time"},
                "revoked": {"type": "boolean"},
            },
        }
    },
}

Draft202012Validator.check_schema(EVIDENCE_SIGNATURE_ATTACHMENT_SCHEMA_V1)
Draft202012Validator.check_schema(EVIDENCE_TRUST_ROOTS_SCHEMA_V1)
_SIGNATURE_SCHEMA_VALIDATOR = Draft202012Validator(
    EVIDENCE_SIGNATURE_ATTACHMENT_SCHEMA_V1,
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
_TRUST_ROOTS_SCHEMA_VALIDATOR = Draft202012Validator(
    EVIDENCE_TRUST_ROOTS_SCHEMA_V1,
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


@runtime_checkable
class EvidenceSigner(Protocol):
    """A signer for the exact domain-separated evidence signature payload."""

    key_id: str
    algorithm: str

    def sign(self, payload: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class EvidenceSignatureAttachment:
    """A versioned detached Ed25519 signature over one evidence bundle digest."""

    key_id: str
    algorithm: str
    bundle_digest: str
    value: str = field(repr=False)
    signature_schema_version: str = field(
        default=_SIGNATURE_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        _require_identifier("signature key_id", self.key_id, EvidenceSignatureValidationError)
        _require_algorithm(self.algorithm, EvidenceSignatureValidationError)
        _require_digest(
            "signature bundle_digest", self.bundle_digest, EvidenceSignatureValidationError
        )
        _decode_exact_base64(
            "signature value",
            self.value,
            expected_bytes=_ED25519_SIGNATURE_BYTES,
            error_type=EvidenceSignatureValidationError,
        )

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "EvidenceSignatureAttachment":
        """Parse one strict portable signature attachment document."""

        data = _require_mapping(document, "signature attachment", EvidenceSignatureValidationError)
        _validate_document(
            _SIGNATURE_SCHEMA_VALIDATOR,
            data,
            "signature attachment",
            EvidenceSignatureValidationError,
        )
        return cls(
            key_id=data["key_id"],
            algorithm=data["algorithm"],
            bundle_digest=data["bundle_digest"],
            value=data["value"],
        )

    @property
    def signature_bytes(self) -> bytes:
        """Return the detached 64-byte Ed25519 signature."""

        return _decode_exact_base64(
            "signature value",
            self.value,
            expected_bytes=_ED25519_SIGNATURE_BYTES,
            error_type=EvidenceSignatureValidationError,
        )

    def signing_bytes(self) -> bytes:
        """Return the exact versioned bytes covered by this signature."""

        return _signature_payload(
            signature_schema_version=self.signature_schema_version,
            key_id=self.key_id,
            algorithm=self.algorithm,
            bundle_digest=self.bundle_digest,
        )

    def to_dict(self) -> dict[str, str]:
        """Return only the portable attachment fields, never bundle contents."""

        document = {
            "signature_schema_version": self.signature_schema_version,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "bundle_digest": self.bundle_digest,
            "value": self.value,
        }
        _validate_document(
            _SIGNATURE_SCHEMA_VALIDATOR,
            document,
            "signature attachment",
            EvidenceSignatureValidationError,
        )
        _ = self.signature_bytes
        return document


@dataclass(frozen=True, slots=True)
class EvidenceTrustRoot:
    """One explicit Ed25519 trust root and its validity lifecycle."""

    key_id: str
    algorithm: str
    public_key: str
    not_before: datetime
    not_after: datetime
    revoked: bool

    def __post_init__(self) -> None:
        _require_identifier("trust root key_id", self.key_id, EvidenceTrustRootValidationError)
        _require_algorithm(self.algorithm, EvidenceTrustRootValidationError)
        _decode_exact_base64(
            "trust root public_key",
            self.public_key,
            expected_bytes=_ED25519_PUBLIC_KEY_BYTES,
            error_type=EvidenceTrustRootValidationError,
        )
        not_before = _require_timestamp(
            "trust root not_before", self.not_before, EvidenceTrustRootValidationError
        )
        not_after = _require_timestamp(
            "trust root not_after", self.not_after, EvidenceTrustRootValidationError
        )
        if not_after <= not_before:
            raise EvidenceTrustRootValidationError(
                "trust root not_after must follow not_before"
            )
        if type(self.revoked) is not bool:
            raise EvidenceTrustRootValidationError("trust root revoked must be boolean")
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "EvidenceTrustRoot":
        """Parse one key entry from a validated trust-roots document."""

        data = _require_mapping(document, "trust root", EvidenceTrustRootValidationError)
        _validate_document(
            _TRUST_ROOT_KEY_VALIDATOR,
            data,
            "trust root",
            EvidenceTrustRootValidationError,
        )
        return cls(
            key_id=data["key_id"],
            algorithm=data["algorithm"],
            public_key=data["public_key"],
            not_before=_parse_timestamp(
                "trust root not_before", data["not_before"], EvidenceTrustRootValidationError
            ),
            not_after=_parse_timestamp(
                "trust root not_after", data["not_after"], EvidenceTrustRootValidationError
            ),
            revoked=data["revoked"],
        )

    @property
    def public_key_bytes(self) -> bytes:
        """Return the validated raw Ed25519 public-key bytes."""

        return _decode_exact_base64(
            "trust root public_key",
            self.public_key,
            expected_bytes=_ED25519_PUBLIC_KEY_BYTES,
            error_type=EvidenceTrustRootValidationError,
        )

    def is_valid_at(self, moment: datetime) -> bool:
        """Return whether this non-revoked root is valid at ``moment``."""

        verified_moment = _require_timestamp(
            "verification time", moment, EvidenceSignatureVerificationError
        )
        return not self.revoked and self.not_before <= verified_moment < self.not_after

    def to_dict(self) -> dict[str, Any]:
        """Return the strict public trust-root representation."""

        document: dict[str, Any] = {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "not_before": _timestamp_text(self.not_before),
            "not_after": _timestamp_text(self.not_after),
            "revoked": self.revoked,
        }
        _validate_document(
            _TRUST_ROOT_KEY_VALIDATOR,
            document,
            "trust root",
            EvidenceTrustRootValidationError,
        )
        _ = self.public_key_bytes
        return document


@dataclass(frozen=True, slots=True)
class EvidenceTrustRoots:
    """A closed, duplicate-free set of configured evidence trust roots."""

    keys: tuple[EvidenceTrustRoot, ...]

    def __post_init__(self) -> None:
        if isinstance(self.keys, str | bytes) or not isinstance(self.keys, Sequence):
            raise TypeError("trust roots keys must be a sequence of EvidenceTrustRoot")
        keys = tuple(self.keys)
        if any(not isinstance(item, EvidenceTrustRoot) for item in keys):
            raise TypeError("trust roots keys must contain EvidenceTrustRoot values")
        key_ids = [item.key_id for item in keys]
        if len(set(key_ids)) != len(key_ids):
            raise EvidenceTrustRootValidationError("trust roots must not repeat key_id")
        object.__setattr__(self, "keys", keys)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "EvidenceTrustRoots":
        """Parse a closed trust-roots document and reject unsupported input."""

        data = _require_mapping(document, "trust roots", EvidenceTrustRootValidationError)
        _validate_document(
            _TRUST_ROOTS_SCHEMA_VALIDATOR,
            data,
            "trust roots",
            EvidenceTrustRootValidationError,
        )
        return cls(keys=tuple(EvidenceTrustRoot.from_dict(item) for item in data["keys"]))

    def get(self, key_id: str) -> EvidenceTrustRoot | None:
        """Return the exact configured root for ``key_id``, if present."""

        return next((item for item in self.keys if item.key_id == key_id), None)

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        """Return the strict portable trust-roots document."""

        document = {"keys": [item.to_dict() for item in self.keys]}
        _validate_document(
            _TRUST_ROOTS_SCHEMA_VALIDATOR,
            document,
            "trust roots",
            EvidenceTrustRootValidationError,
        )
        return document


class Ed25519EvidenceSigner:
    """A local Ed25519 signer loaded only when the ``evidence`` extra is present."""

    algorithm = _ED25519
    __slots__ = ("_key_id", "_private_key")

    def __init__(self, key_id: str, private_key: object) -> None:
        _require_identifier("signature key_id", key_id, EvidenceSignatureValidationError)
        try:
            self._private_key = _evidence_ed25519.require_private_key(private_key)
        except _evidence_ed25519.EvidenceCryptographyUnavailableError as exc:
            raise EvidenceSigningDependencyError(str(exc)) from exc
        self._key_id = key_id

    @classmethod
    def from_private_key_bytes(
        cls, key_id: str, private_key: bytes
    ) -> "Ed25519EvidenceSigner":
        """Create a signer from caller-provided raw Ed25519 private-key bytes."""

        if type(private_key) is not bytes:
            raise EvidenceSignatureValidationError("private_key must be bytes")
        try:
            loaded_private_key = _evidence_ed25519.private_key_from_bytes(private_key)
        except _evidence_ed25519.EvidenceCryptographyUnavailableError as exc:
            raise EvidenceSigningDependencyError(str(exc)) from exc
        except ValueError as exc:
            raise EvidenceSignatureValidationError(
                "private_key must be a valid Ed25519 private key"
            ) from exc
        return cls(key_id, loaded_private_key)

    @property
    def key_id(self) -> str:
        """Return the stable configured signer key identifier."""

        return self._key_id

    def sign(self, payload: bytes) -> bytes:
        """Sign the exact domain-separated attachment payload."""

        try:
            return _evidence_ed25519.sign(self._private_key, payload)
        except _evidence_ed25519.EvidenceCryptographyUnavailableError as exc:
            raise EvidenceSigningDependencyError(str(exc)) from exc

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key_id={self.key_id!r})"


def sign_evidence_bundle(
    bundle: EvidenceBundle,
    signer: EvidenceSigner,
) -> EvidenceSignatureAttachment:
    """Create a detached signature without changing the bundle's V1 digest."""

    if not isinstance(bundle, EvidenceBundle):
        raise TypeError("bundle must be an EvidenceBundle")
    if not isinstance(signer, EvidenceSigner):
        raise TypeError("signer must implement EvidenceSigner")
    _require_identifier("signature key_id", signer.key_id, EvidenceSignatureValidationError)
    _require_algorithm(signer.algorithm, EvidenceSignatureValidationError)
    bundle_digest = bundle.bundle_digest
    payload = _signature_payload(
        signature_schema_version=_SIGNATURE_SCHEMA_VERSION,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        bundle_digest=bundle_digest,
    )
    try:
        signature = signer.sign(payload)
    except EvidenceSigningError:
        raise
    except Exception as exc:
        raise EvidenceSigningError("evidence signer failed") from exc
    if type(signature) is not bytes:
        raise EvidenceSignatureValidationError("evidence signer must return bytes")
    return EvidenceSignatureAttachment(
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        bundle_digest=bundle_digest,
        value=base64.b64encode(signature).decode("ascii"),
    )


def verify_evidence_bundle_signature(
    bundle: EvidenceBundle,
    attachment: EvidenceSignatureAttachment,
    trust_roots: EvidenceTrustRoots,
    *,
    now: datetime | None = None,
) -> None:
    """Verify a detached signature against one active explicit trust root.

    Successful verification returns ``None``.  Every unavailable, invalid, or
    untrusted condition raises a typed error so callers fail closed.
    """

    if not isinstance(bundle, EvidenceBundle):
        raise TypeError("bundle must be an EvidenceBundle")
    if not isinstance(attachment, EvidenceSignatureAttachment):
        raise TypeError("attachment must be an EvidenceSignatureAttachment")
    if not isinstance(trust_roots, EvidenceTrustRoots):
        raise TypeError("trust_roots must be an EvidenceTrustRoots")
    if attachment.bundle_digest != bundle.bundle_digest:
        raise EvidenceSignatureVerificationError(
            "signature attachment bundle_digest does not match evidence bundle"
        )
    root = trust_roots.get(attachment.key_id)
    if root is None:
        raise EvidenceSignatureVerificationError("signature key_id is not trusted")
    if root.algorithm != attachment.algorithm:
        raise EvidenceSignatureVerificationError("signature algorithm does not match trust root")
    verified_now = _require_timestamp(
        "verification time",
        datetime.now(timezone.utc) if now is None else now,
        EvidenceSignatureVerificationError,
    )
    if root.revoked:
        raise EvidenceSignatureVerificationError("signature trust root is revoked")
    if verified_now < root.not_before:
        raise EvidenceSignatureVerificationError("signature trust root is not yet valid")
    if verified_now >= root.not_after:
        raise EvidenceSignatureVerificationError("signature trust root is expired")
    try:
        verified = _evidence_ed25519.verify(
            root.public_key_bytes,
            attachment.signing_bytes(),
            attachment.signature_bytes,
        )
    except _evidence_ed25519.EvidenceCryptographyUnavailableError as exc:
        raise EvidenceSigningDependencyError(str(exc)) from exc
    if not verified:
        raise EvidenceSignatureVerificationError("evidence signature is invalid")


def _signature_payload(
    *,
    signature_schema_version: str,
    key_id: str,
    algorithm: str,
    bundle_digest: str,
) -> bytes:
    if signature_schema_version != _SIGNATURE_SCHEMA_VERSION:
        raise EvidenceSignatureValidationError("unsupported signature schema version")
    _require_identifier("signature key_id", key_id, EvidenceSignatureValidationError)
    _require_algorithm(algorithm, EvidenceSignatureValidationError)
    _require_digest("signature bundle_digest", bundle_digest, EvidenceSignatureValidationError)
    statement = {
        "signature_schema_version": signature_schema_version,
        "key_id": key_id,
        "algorithm": algorithm,
        "bundle_digest": bundle_digest,
    }
    try:
        return _SIGNATURE_DOMAIN + rfc8785_json_bytes(statement)
    except CanonicalJsonError as exc:
        raise EvidenceSignatureValidationError(
            "signature attachment is not RFC 8785 canonicalizable"
        ) from exc


_TRUST_ROOT_KEY_VALIDATOR = Draft202012Validator(
    EVIDENCE_TRUST_ROOTS_SCHEMA_V1["$defs"]["key"],
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def _validate_document(
    validator: Draft202012Validator,
    document: Mapping[str, Any],
    label: str,
    error_type: type[EvidenceSigningError],
) -> None:
    errors = sorted(
        validator.iter_errors(dict(document)),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        error = errors[0]
        path = "/".join(str(item) for item in error.absolute_path) or "$"
        raise error_type(f"{label} schema validation failed at {path}: {error.message}")


def _require_mapping(
    value: Mapping[str, Any],
    label: str,
    error_type: type[EvidenceSigningError],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise error_type(f"{label} must be an object")
    return dict(value)


def _require_identifier(
    name: str, value: str, error_type: type[EvidenceSigningError]
) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise error_type(f"{name} must be a stable 1-256 character identifier")


def _require_algorithm(value: str, error_type: type[EvidenceSigningError]) -> None:
    if value != _ED25519:
        raise error_type("only the ed25519 evidence signature algorithm is supported")


def _require_digest(
    name: str, value: str, error_type: type[EvidenceSigningError]
) -> None:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise error_type(f"{name} must be a SHA-256 hex digest")


def _decode_exact_base64(
    name: str,
    value: str,
    *,
    expected_bytes: int,
    error_type: type[EvidenceSigningError],
) -> bytes:
    if not isinstance(value, str):
        raise error_type(f"{name} must be canonical base64")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise error_type(f"{name} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise error_type(f"{name} must be canonical base64")
    if len(decoded) != expected_bytes:
        raise error_type(f"{name} must encode exactly {expected_bytes} bytes")
    return decoded


def _require_timestamp(
    name: str,
    value: datetime,
    error_type: type[EvidenceSigningError],
) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise error_type(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _parse_timestamp(
    name: str,
    value: str,
    error_type: type[EvidenceSigningError],
) -> datetime:
    if not isinstance(value, str):
        raise error_type(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise error_type(f"{name} must be an RFC 3339 timestamp") from exc
    return _require_timestamp(name, parsed, error_type)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
