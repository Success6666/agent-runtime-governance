"""Internal JSON codec profiles with explicit compatibility semantics.

Existing durable formats do not all share one byte representation.  New code
must select a named profile instead of treating every sorted JSON encoding as
interchangeable: audit-compatible records use ASCII escapes, contracts retain
their UTF-8 sorted-JSON form, policy identity retains its historical form, and
new portable commitments use RFC 8785.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import rfc8785


class CanonicalJsonError(ValueError):
    """Raised when a value cannot be represented by the RFC 8785 profile."""


def legacy_audit_json_text(value: Any) -> str:
    """Return the existing ASCII-escaped bytes used by audit integrity paths."""

    return _sorted_json_text(value, ensure_ascii=True, allow_nan=False)


def legacy_audit_json_bytes(value: Any) -> bytes:
    """Return :func:`legacy_audit_json_text` as UTF-8 bytes."""

    return legacy_audit_json_text(value).encode("utf-8")


def legacy_contract_json_bytes(value: Any) -> bytes:
    """Return the existing UTF-8 sorted JSON used by contract-facing paths."""

    return _sorted_json_text(value, ensure_ascii=False, allow_nan=False).encode("utf-8")


def legacy_storage_json_text(value: Any) -> str:
    """Return the existing JSONL/SQLite storage form without NaN rejection."""

    return _sorted_json_text(value, ensure_ascii=True, allow_nan=True)


def legacy_policy_json_bytes(value: Any) -> bytes:
    """Return the existing ASCII JSON bytes used by policy semantic digests."""

    return _sorted_json_text(value, ensure_ascii=True, allow_nan=True).encode("utf-8")


def rfc8785_json_bytes(
    value: Any,
    *,
    encoder: Callable[[Any], bytes] | None = None,
) -> bytes:
    """Return RFC 8785 bytes for new portable commitments.

    ``encoder`` exists only to preserve callers that translate the upstream
    canonicalization exception at their own public boundary.
    """

    try:
        return (encoder or rfc8785.dumps)(value)
    except (rfc8785.CanonicalizationError, UnicodeError) as exc:
        raise CanonicalJsonError(str(exc)) from exc


def rfc8785_json_text(
    value: Any,
    *,
    encoder: Callable[[Any], bytes] | None = None,
) -> str:
    """Return RFC 8785 bytes decoded as UTF-8 text for durable text columns."""

    return rfc8785_json_bytes(value, encoder=encoder).decode("utf-8")


def _sorted_json_text(value: Any, *, ensure_ascii: bool, allow_nan: bool) -> str:
    return json.dumps(
        value,
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=allow_nan,
    )
