from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol

from .decisions import (
    ApprovalRequest,
    DecisionRecord,
    denial_for_request,
)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    DECIDED = "decided"
    CONSUMED = "consumed"


@dataclass(frozen=True, slots=True)
class StoredApproval:
    request: ApprovalRequest
    decision: DecisionRecord | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    consumed_at: str | None = None
    reservation_token: str | None = None
    reserved_until: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovalReservation:
    decision: DecisionRecord
    token: str | None = None


class ApprovalStore(Protocol):
    def pending(self, request: ApprovalRequest) -> None: ...

    def decide(self, request_id: str, decision: DecisionRecord) -> DecisionRecord: ...

    def consume(self, request: ApprovalRequest) -> DecisionRecord: ...

    def reserve(
        self, request: ApprovalRequest, *, lease_seconds: float
    ) -> ApprovalReservation: ...

    def commit(self, request: ApprovalRequest, token: str) -> DecisionRecord: ...

    def release(self, request_id: str, token: str) -> bool: ...

    def get(self, request_id: str) -> StoredApproval | None: ...


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self._items: dict[str, StoredApproval] = {}
        self._lock = threading.RLock()

    def pending(self, request: ApprovalRequest) -> None:
        with self._lock:
            existing = self._items.get(request.request_id)
            if existing is None:
                self._items[request.request_id] = StoredApproval(request=request)
                return
            if _validate_request(existing.request, request) is not None:
                raise ValueError(
                    "approval request_id was reused for a different request"
                )

    def decide(self, request_id: str, decision: DecisionRecord) -> DecisionRecord:
        with self._lock:
            item = self._items.get(request_id)
            if item is None:
                raise KeyError(request_id)
            if item.status is ApprovalStatus.CONSUMED:
                raise ValueError("approval request already consumed")
            if item.request.is_expired():
                raise ValueError("approval request expired")
            bound = decision.bind_to(item.request)
            if item.status is ApprovalStatus.DECIDED:
                if item.decision == bound:
                    return bound
                raise ValueError("approval request already has a decision")
            self._items[request_id] = StoredApproval(
                request=item.request,
                decision=bound,
                status=ApprovalStatus.DECIDED,
                consumed_at=item.consumed_at,
            )
            return bound

    def consume(self, request: ApprovalRequest) -> DecisionRecord:
        reservation = self.reserve(request, lease_seconds=30.0)
        if reservation.token is None:
            return reservation.decision
        return self.commit(request, reservation.token)

    def reserve(
        self, request: ApprovalRequest, *, lease_seconds: float
    ) -> ApprovalReservation:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self._lock:
            item = self._items.get(request.request_id)
            if item is None:
                return ApprovalReservation(
                    denial_for_request(request, "approval request not found")
                )
            denial = _validate_request(item.request, request)
            if denial is not None:
                return ApprovalReservation(denial)
            if item.status is ApprovalStatus.CONSUMED:
                return ApprovalReservation(
                    denial_for_request(request, "approval request already consumed")
                )
            if item.request.is_expired():
                return ApprovalReservation(
                    denial_for_request(request, "approval request expired")
                )
            if item.decision is None:
                return ApprovalReservation(
                    denial_for_request(request, "approval decision pending")
                )
            if item.decision.is_expired():
                return ApprovalReservation(
                    denial_for_request(request, "approval decision expired")
                )
            if item.reservation_token and not _reservation_expired(item.reserved_until):
                return ApprovalReservation(
                    denial_for_request(request, "approval request already reserved")
                )
            token = secrets.token_hex(32)
            reserved = StoredApproval(
                request=item.request,
                decision=item.decision,
                status=ApprovalStatus.DECIDED,
                consumed_at=item.consumed_at,
                reservation_token=token,
                reserved_until=(
                    datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)
                ).isoformat(),
            )
            self._items[request.request_id] = reserved
            return ApprovalReservation(item.decision, token)

    def commit(self, request: ApprovalRequest, token: str) -> DecisionRecord:
        with self._lock:
            item = self._items.get(request.request_id)
            if item is None:
                return denial_for_request(request, "approval request not found")
            denial = _validate_request(item.request, request)
            if denial is not None:
                return denial
            if item.status is ApprovalStatus.CONSUMED:
                return denial_for_request(request, "approval request already consumed")
            if item.reservation_token != token:
                return denial_for_request(request, "approval reservation mismatch")
            if _reservation_expired(item.reserved_until):
                self._items[request.request_id] = StoredApproval(
                    request=item.request,
                    decision=item.decision,
                    status=ApprovalStatus.DECIDED,
                )
                return denial_for_request(request, "approval reservation expired")
            assert item.decision is not None
            self._items[request.request_id] = StoredApproval(
                request=item.request,
                decision=item.decision,
                status=ApprovalStatus.CONSUMED,
                consumed_at=_utc_now(),
            )
            return item.decision

    def release(self, request_id: str, token: str) -> bool:
        with self._lock:
            item = self._items.get(request_id)
            if (
                item is None
                or item.status is ApprovalStatus.CONSUMED
                or item.reservation_token != token
            ):
                return False
            self._items[request_id] = StoredApproval(
                request=item.request,
                decision=item.decision,
                status=item.status,
                consumed_at=item.consumed_at,
            )
            return True

    def get(self, request_id: str) -> StoredApproval | None:
        with self._lock:
            return self._items.get(request_id)


class SQLiteApprovalStore:
    """Durable, cross-process approval state with atomic single consumption."""

    def __init__(
        self,
        path: str | Path,
        *,
        timeout_seconds: float = 30.0,
        sign_key: bytes | str | None = None,
        store_arguments: bool = False,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self._sign_key = (
            sign_key.encode("utf-8") if isinstance(sign_key, str) else sign_key
        )
        self.store_arguments = store_arguments
        self._initialize()

    def pending(self, request: ApprovalRequest) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_json FROM approvals WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            if row is None:
                request_json = _dump(self._stored_request(request))
                status = ApprovalStatus.PENDING.value
                connection.execute(
                    """
                    INSERT INTO approvals
                    (request_id, request_json, decision_json, status, consumed_at, integrity_tag)
                    VALUES (?, ?, NULL, ?, NULL, ?)
                    """,
                    (
                        request.request_id,
                        request_json,
                        status,
                        self._record_tag(request_json, None, status, None),
                    ),
                )
            else:
                stored = ApprovalRequest.from_dict(json.loads(row[0]))
                denial = _validate_request(stored, request)
                if denial is not None:
                    raise ValueError("approval request_id was reused for a different request")
            connection.commit()

    def decide(self, request_id: str, decision: DecisionRecord) -> DecisionRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._get(connection, request_id)
            if item is None:
                raise KeyError(request_id)
            if item.status is ApprovalStatus.CONSUMED:
                raise ValueError("approval request already consumed")
            if item.request.is_expired():
                raise ValueError("approval request expired")
            bound = decision.bind_to(item.request)
            if item.status is ApprovalStatus.DECIDED:
                if item.decision == bound:
                    return bound
                raise ValueError("approval request already has a decision")
            cursor = connection.execute(
                """
                UPDATE approvals
                SET decision_json = ?, status = ?, integrity_tag = ?
                WHERE request_id = ? AND status = ?
                """,
                (
                    _dump(bound.to_dict()),
                    ApprovalStatus.DECIDED.value,
                    self._record_tag(
                        _dump(item.request.to_dict()),
                        _dump(bound.to_dict()),
                        ApprovalStatus.DECIDED.value,
                        None,
                    ),
                    request_id,
                    ApprovalStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("approval request state changed before decision")
            connection.commit()
            return bound

    def consume(self, request: ApprovalRequest) -> DecisionRecord:
        reservation = self.reserve(request, lease_seconds=30.0)
        if reservation.token is None:
            return reservation.decision
        return self.commit(request, reservation.token)

    def reserve(
        self, request: ApprovalRequest, *, lease_seconds: float
    ) -> ApprovalReservation:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                item = self._get(connection, request.request_id)
                if item is None:
                    connection.commit()
                    return ApprovalReservation(
                        denial_for_request(request, "approval request not found")
                    )
                denial = _validate_request(item.request, request)
                if denial is not None:
                    connection.commit()
                    return ApprovalReservation(denial)
                if item.status is ApprovalStatus.CONSUMED:
                    connection.commit()
                    return ApprovalReservation(
                        denial_for_request(request, "approval request already consumed")
                    )
                if item.request.is_expired():
                    connection.commit()
                    return ApprovalReservation(
                        denial_for_request(request, "approval request expired")
                    )
                if item.decision is None:
                    connection.commit()
                    return ApprovalReservation(
                        denial_for_request(request, "approval decision pending")
                    )
                if item.decision.is_expired():
                    connection.commit()
                    return ApprovalReservation(
                        denial_for_request(request, "approval decision expired")
                    )
                now = datetime.now(timezone.utc)
                if item.reservation_token and not _reservation_expired(
                    item.reserved_until, now=now
                ):
                    connection.commit()
                    return ApprovalReservation(
                        denial_for_request(request, "approval request already reserved")
                    )
                token = secrets.token_hex(32)
                reserved_until = (
                    now + timedelta(seconds=lease_seconds)
                ).isoformat()
                cursor = connection.execute(
                    """
                    UPDATE approvals
                    SET reservation_token = ?, reserved_until = ?, integrity_tag = ?
                    WHERE request_id = ? AND status = ?
                      AND (reservation_token IS NULL OR reserved_until <= ?)
                    """,
                    (
                        token,
                        reserved_until,
                        self._record_tag(
                            _dump(item.request.to_dict()),
                            _dump(item.decision.to_dict()),
                            ApprovalStatus.DECIDED.value,
                            item.consumed_at,
                            token,
                            reserved_until,
                        ),
                        request.request_id,
                        ApprovalStatus.DECIDED.value,
                        now.isoformat(),
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return ApprovalReservation(
                        denial_for_request(
                            request, "approval request was reserved concurrently"
                        )
                    )
                connection.commit()
                return ApprovalReservation(item.decision, token)
            except Exception:
                connection.rollback()
                raise

    def commit(self, request: ApprovalRequest, token: str) -> DecisionRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                item = self._get(connection, request.request_id)
                if item is None:
                    connection.commit()
                    return denial_for_request(request, "approval request not found")
                denial = _validate_request(item.request, request)
                if denial is not None:
                    connection.commit()
                    return denial
                if item.status is ApprovalStatus.CONSUMED:
                    connection.commit()
                    return denial_for_request(request, "approval request already consumed")
                if item.reservation_token != token:
                    connection.commit()
                    return denial_for_request(request, "approval reservation mismatch")
                now = datetime.now(timezone.utc)
                if _reservation_expired(item.reserved_until, now=now):
                    self._clear_reservation(connection, item)
                    connection.commit()
                    return denial_for_request(request, "approval reservation expired")
                assert item.decision is not None
                consumed_at = now.isoformat()
                cursor = connection.execute(
                    """
                    UPDATE approvals
                    SET status = ?, consumed_at = ?, reservation_token = NULL,
                        reserved_until = NULL, integrity_tag = ?
                    WHERE request_id = ? AND status = ? AND reservation_token = ?
                    """,
                    (
                        ApprovalStatus.CONSUMED.value,
                        consumed_at,
                        self._record_tag(
                            _dump(item.request.to_dict()),
                            _dump(item.decision.to_dict()),
                            ApprovalStatus.CONSUMED.value,
                            consumed_at,
                        ),
                        request.request_id,
                        ApprovalStatus.DECIDED.value,
                        token,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return denial_for_request(
                        request, "approval reservation changed before commit"
                    )
                connection.commit()
                return item.decision
            except Exception:
                connection.rollback()
                raise

    def release(self, request_id: str, token: str) -> bool:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                item = self._get(connection, request_id)
                if (
                    item is None
                    or item.status is ApprovalStatus.CONSUMED
                    or item.reservation_token != token
                ):
                    connection.commit()
                    return False
                cursor = self._clear_reservation(connection, item)
                connection.commit()
                return cursor.rowcount == 1
            except Exception:
                connection.rollback()
                raise

    def get(self, request_id: str) -> StoredApproval | None:
        with self._connect() as connection:
            return self._get(connection, request_id)

    def close(self) -> None:
        """Compatibility no-op; operations use short-lived connections."""

    def _get(
        self,
        connection: sqlite3.Connection, request_id: str
    ) -> StoredApproval | None:
        row = connection.execute(
            """
            SELECT request_json, decision_json, status, consumed_at, integrity_tag,
                   reservation_token, reserved_until
            FROM approvals
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        (
            request_json,
            decision_json,
            status,
            consumed_at,
            integrity_tag,
            reservation_token,
            reserved_until,
        ) = row
        expected_tag = self._record_tag(
            request_json,
            decision_json,
            status,
            consumed_at,
            reservation_token,
            reserved_until,
        )
        if self._sign_key and (
            not isinstance(integrity_tag, str)
            or not hmac.compare_digest(integrity_tag, expected_tag or "")
        ):
            raise ValueError("approval record integrity verification failed")
        return StoredApproval(
            request=ApprovalRequest.from_dict(json.loads(request_json)),
            decision=(
                DecisionRecord.from_dict(json.loads(decision_json))
                if decision_json
                else None
            ),
            status=ApprovalStatus(status),
            consumed_at=consumed_at,
            reservation_token=reservation_token,
            reserved_until=reserved_until,
        )

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    request_id TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    decision_json TEXT,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'decided', 'consumed')),
                    consumed_at TEXT
                    , integrity_tag TEXT,
                    reservation_token TEXT,
                    reserved_until TEXT
                )
                """
            )
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(approvals)")
            }
            if "integrity_tag" not in columns:
                connection.execute("ALTER TABLE approvals ADD COLUMN integrity_tag TEXT")
            if "reservation_token" not in columns:
                connection.execute(
                    "ALTER TABLE approvals ADD COLUMN reservation_token TEXT"
                )
            if "reserved_until" not in columns:
                connection.execute(
                    "ALTER TABLE approvals ADD COLUMN reserved_until TEXT"
                )

    def _stored_request(self, request: ApprovalRequest) -> dict[str, object]:
        payload = request.to_dict()
        if not self.store_arguments:
            payload["arguments"] = {}
            payload["arguments_redacted"] = True
        return payload

    def _record_tag(
        self,
        request_json: str,
        decision_json: str | None,
        status: str,
        consumed_at: str | None,
        reservation_token: str | None = None,
        reserved_until: str | None = None,
    ) -> str | None:
        if not self._sign_key:
            return None
        payload = _dump(
            {
                "request_json": request_json,
                "decision_json": decision_json,
                "status": status,
                "consumed_at": consumed_at,
                "reservation_token": reservation_token,
                "reserved_until": reserved_until,
            }
        ).encode("utf-8")
        return hmac.new(self._sign_key, payload, hashlib.sha256).hexdigest()

    def _clear_reservation(
        self, connection: sqlite3.Connection, item: StoredApproval
    ) -> sqlite3.Cursor:
        assert item.decision is not None
        return connection.execute(
            """
            UPDATE approvals
            SET reservation_token = NULL, reserved_until = NULL, integrity_tag = ?
            WHERE request_id = ? AND status = ? AND reservation_token = ?
            """,
            (
                self._record_tag(
                    _dump(item.request.to_dict()),
                    _dump(item.decision.to_dict()),
                    ApprovalStatus.DECIDED.value,
                    item.consumed_at,
                ),
                item.request.request_id,
                ApprovalStatus.DECIDED.value,
                item.reservation_token,
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=self.timeout_seconds, isolation_level=None
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
        return connection


def _validate_request(stored: ApprovalRequest, request: ApprovalRequest) -> DecisionRecord | None:
    if stored.tool_name != request.tool_name:
        return denial_for_request(request, "approval request tool mismatch")
    if stored.arguments_digest != request.arguments_digest:
        return denial_for_request(request, "approval request arguments mismatch")
    if stored.policy_version != request.policy_version:
        return denial_for_request(request, "approval request policy mismatch")
    if stored.subject != request.subject:
        return denial_for_request(request, "approval request subject mismatch")
    if stored.tenant != request.tenant:
        return denial_for_request(request, "approval request tenant mismatch")
    if stored.identity_issuer != request.identity_issuer:
        return denial_for_request(request, "approval request identity issuer mismatch")
    if stored.risk_tier != request.risk_tier:
        return denial_for_request(request, "approval request risk mismatch")
    return None


def _dump(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reservation_expired(
    value: str | None, *, now: datetime | None = None
) -> bool:
    if value is None:
        return True
    expires_at = datetime.fromisoformat(value)
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        return True
    return expires_at <= (now or datetime.now(timezone.utc))
