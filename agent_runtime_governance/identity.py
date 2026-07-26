from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from ._serialization import freeze_mapping as _freeze_mapping
from ._serialization import thaw as _thaw
from ._sqlite import connect_sqlite, initialize_sqlite
from .contracts import canonical_json_bytes


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    """Identity claims accepted from a trusted boundary, not model output."""

    issuer: str
    subject: str
    tenant: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    source: str = "trusted"
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    claims: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("issuer is required")
        if not self.subject:
            raise ValueError("subject is required")
        if not self.tenant:
            raise ValueError("tenant is required")
        _validate_identifier("issuer", self.issuer)
        _validate_identifier("subject", self.subject)
        _validate_identifier("tenant", self.tenant)
        _parse_timestamp(self.verified_at, "verified_at")
        if len(self.permissions) > 256:
            raise ValueError("permissions cannot contain more than 256 entries")
        for permission in self.permissions:
            _validate_identifier("permission", permission)
        object.__setattr__(self, "permissions", frozenset(self.permissions))
        object.__setattr__(
            self,
            "claims",
            _freeze_mapping(self.claims),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "tenant": self.tenant,
            "permissions": sorted(self.permissions),
            "source": self.source,
            "verified_at": self.verified_at,
            "claims": _thaw(self.claims),
        }


class IdentityProvider(Protocol):
    def verify(self, claims: Mapping[str, Any] | None = None) -> VerifiedPrincipal: ...


class StaticIdentityProvider:
    """Returns a pre-verified principal from an already trusted host boundary."""

    production_trusted = True

    def __init__(self, principal: VerifiedPrincipal) -> None:
        self._principal = principal

    def verify(self, claims: Mapping[str, Any] | None = None) -> VerifiedPrincipal:
        return self._principal


class IdentityReplayStore(Protocol):
    def claim(self, issuer: str, jti: str, expires_at: datetime) -> bool: ...


class InMemoryIdentityReplayStore:
    """Process-local replay protection for signed identity envelopes."""

    production_durable = False

    def __init__(self) -> None:
        self._claims: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def claim(self, issuer: str, jti: str, expires_at: datetime) -> bool:
        now = datetime.now(timezone.utc)
        key = (issuer, jti)
        with self._lock:
            self._claims = {
                item: expiry for item, expiry in self._claims.items() if expiry > now
            }
            if key in self._claims:
                return False
            self._claims[key] = expires_at
            return True


class SQLiteIdentityReplayStore:
    """Cross-process replay protection backed by an atomic SQLite insert."""

    production_durable = True

    def __init__(self, path: str | Path, *, timeout_seconds: float = 30.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        with initialize_sqlite(self.path, self.timeout_seconds) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS identity_replay_claims (
                    issuer TEXT NOT NULL,
                    jti TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY(issuer, jti)
                )
                """
            )

    def claim(self, issuer: str, jti: str, expires_at: datetime) -> bool:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM identity_replay_claims WHERE expires_at <= ?",
                (now.isoformat(),),
            )
            try:
                connection.execute(
                    """
                    INSERT INTO identity_replay_claims(issuer, jti, expires_at)
                    VALUES (?, ?, ?)
                    """,
                    (issuer, jti, expires_at.astimezone(timezone.utc).isoformat()),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            connection.commit()
            return True

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.path, self.timeout_seconds)


class HMACClaimsIdentityProvider:
    """Verifies short-lived, audience-bound HMAC identity envelopes."""

    production_trusted = True

    def __init__(
        self,
        key: bytes | str | Mapping[str, bytes | str],
        *,
        expected_issuer: str,
        expected_audience: str,
        max_lifetime_seconds: float = 300.0,
        clock_skew_seconds: float = 30.0,
        replay_store: IdentityReplayStore | None = None,
        max_claims_bytes: int = 16 * 1024,
    ) -> None:
        if not expected_issuer:
            raise ValueError("expected_issuer is required")
        if not expected_audience:
            raise ValueError("expected_audience is required")
        if max_lifetime_seconds <= 0 or clock_skew_seconds < 0:
            raise ValueError("identity lifetime and clock skew are invalid")
        if max_claims_bytes <= 0:
            raise ValueError("max_claims_bytes must be positive")
        if isinstance(key, Mapping):
            self._keys = {
                str(kid): _normalize_key(value)
                for kid, value in key.items()
            }
        else:
            self._keys = {
                "default": _normalize_key(key)
            }
        if not self._keys:
            raise ValueError("at least one non-empty identity key is required")
        for kid in self._keys:
            _validate_identifier("identity key id", kid)
        _validate_identifier("expected_issuer", expected_issuer)
        _validate_identifier("expected_audience", expected_audience)
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.max_lifetime_seconds = max_lifetime_seconds
        self.clock_skew_seconds = clock_skew_seconds
        self.replay_store = replay_store or InMemoryIdentityReplayStore()
        self.max_claims_bytes = max_claims_bytes

    @staticmethod
    def sign_claims(
        claims: Mapping[str, Any], key: bytes | str, *, kid: str = "default"
    ) -> dict[str, Any]:
        secret = _normalize_key(key)
        _validate_identifier("identity key id", kid)
        payload = dict(claims)
        return {"kid": kid, "claims": payload, "signature": _sign(payload, secret)}

    def verify(self, claims: Mapping[str, Any] | None = None) -> VerifiedPrincipal:
        if not claims:
            raise ValueError("signed identity envelope is required")
        raw_claims = claims.get("claims")
        signature = claims.get("signature")
        kid = claims.get("kid", "default")
        if not isinstance(raw_claims, Mapping) or not isinstance(signature, str):
            raise ValueError("identity envelope must contain claims and signature")
        if not isinstance(kid, str) or kid not in self._keys:
            raise ValueError("unknown identity key id")
        encoded = _canonical_json(raw_claims)
        if len(encoded) > self.max_claims_bytes:
            raise ValueError("identity claims exceeded byte limit")
        expected = hmac.new(self._keys[kid], encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid identity claims signature")
        issuer = str(raw_claims.get("issuer", ""))
        if issuer != self.expected_issuer:
            raise ValueError("unexpected identity issuer")
        _validate_audience(raw_claims.get("audience", raw_claims.get("aud")), self.expected_audience)
        now = datetime.now(timezone.utc)
        issued_at = _claim_time(raw_claims, "iat")
        not_before = _claim_time(raw_claims, "nbf")
        expires_at = _claim_time(raw_claims, "exp")
        skew = timedelta(seconds=self.clock_skew_seconds)
        if issued_at > now + skew:
            raise ValueError("identity claims were issued in the future")
        if not_before > now + skew:
            raise ValueError("identity claims are not active yet")
        if expires_at <= now - skew:
            raise ValueError("identity claims expired")
        if expires_at <= issued_at:
            raise ValueError("identity expiry must be after issuance")
        if not_before >= expires_at:
            raise ValueError("identity not-before must precede expiry")
        if (expires_at - issued_at).total_seconds() > self.max_lifetime_seconds:
            raise ValueError("identity claims lifetime exceeds the configured maximum")
        subject = str(raw_claims.get("subject", ""))
        tenant = str(raw_claims.get("tenant", ""))
        _validate_identifier("identity subject", subject)
        _validate_identifier("identity tenant", tenant)
        jti = str(raw_claims.get("jti", ""))
        if not re.fullmatch(r"[A-Za-z0-9._:-]{16,256}", jti):
            raise ValueError("identity jti must be a stable 16-256 character identifier")
        permissions = raw_claims.get("permissions", [])
        if isinstance(permissions, str):
            permissions = [permissions]
        if not isinstance(permissions, list | tuple | set | frozenset):
            raise ValueError("identity permissions must be a sequence")
        if len(permissions) > 256:
            raise ValueError("identity permissions exceeded entry limit")
        normalized_permissions = frozenset(str(item) for item in permissions)
        for permission in normalized_permissions:
            _validate_identifier("identity permission", permission)
        replay_expires_at = expires_at + timedelta(seconds=self.clock_skew_seconds)
        if not self.replay_store.claim(issuer, jti, replay_expires_at):
            raise ValueError("identity claims were already used")
        return VerifiedPrincipal(
            issuer=issuer,
            subject=subject,
            tenant=tenant,
            permissions=normalized_permissions,
            source="hmac",
            claims=dict(raw_claims),
        )


def _claim_time(claims: Mapping[str, Any], name: str) -> datetime:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"identity {name} must be a Unix timestamp")
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"identity {name} is invalid") from exc


def _validate_audience(value: Any, expected: str) -> None:
    if isinstance(value, str):
        audiences = {value}
    elif isinstance(value, list | tuple):
        audiences = {str(item) for item in value}
    else:
        raise ValueError("identity audience is required")
    if expected not in audiences:
        raise ValueError("unexpected identity audience")


def _sign(claims: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical_json(claims), hashlib.sha256).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return canonical_json_bytes(value, label="identity claims")


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")


def _validate_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a stable 1-256 character identifier")


def _normalize_key(value: bytes | str) -> bytes:
    key = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("identity HMAC keys must contain at least 32 bytes")
    return key


def _parse_timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)
