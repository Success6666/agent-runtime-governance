"""Optional ``cryptography`` bindings for Ed25519 evidence signatures."""

from __future__ import annotations

from typing import Any


class EvidenceCryptographyUnavailableError(RuntimeError):
    """Raised when the optional evidence cryptography dependency is absent."""


def private_key_from_bytes(value: bytes) -> object:
    """Load a raw 32-byte Ed25519 private key without importing at module load."""

    if type(value) is not bytes:
        raise TypeError("Ed25519 private key bytes must be bytes")
    private_key_type, _, _ = _ed25519_types()
    return private_key_type.from_private_bytes(value)


def require_private_key(value: object) -> object:
    """Require a ``cryptography`` Ed25519 private-key instance."""

    private_key_type, _, _ = _ed25519_types()
    if not isinstance(value, private_key_type):
        raise TypeError("private_key must be a cryptography Ed25519PrivateKey")
    return value


def sign(private_key: object, payload: bytes) -> bytes:
    """Sign one exact payload with an already-validated private key."""

    if type(payload) is not bytes:
        raise TypeError("evidence signature payload must be bytes")
    return require_private_key(private_key).sign(payload)  # type: ignore[no-any-return]


def verify(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature, returning ``False`` for a bad signature."""

    if type(public_key) is not bytes:
        raise TypeError("Ed25519 public key must be bytes")
    if type(payload) is not bytes:
        raise TypeError("evidence signature payload must be bytes")
    if type(signature) is not bytes:
        raise TypeError("Ed25519 signature must be bytes")
    _, public_key_type, invalid_signature_type = _ed25519_types()
    verifier = public_key_type.from_public_bytes(public_key)
    try:
        verifier.verify(signature, payload)
    except invalid_signature_type:
        return False
    return True


def _ed25519_types() -> tuple[type[Any], type[Any], type[BaseException]]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise EvidenceCryptographyUnavailableError(
            "Ed25519 evidence signing requires the 'evidence' extra"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature
