from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Awaitable, Protocol

from filelock import FileLock

from ._canonical import legacy_audit_json_text
from ._serialization import json_safe as _json_safe
from ._sqlite import connect_sqlite, initialize_sqlite
from .context import ExecutionContext
from .errors import AuditIntegrityError

DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "authorization",
        "cookie",
        "identity_claims",
        "signature",
    }
)
DEFAULT_SENSITIVE_PATHS = frozenset(
    {
        "reason",
        "context.input_text",
        "context.result",
        "context.error",
        "context.tool_call.args.*",
        "context.tool_call.kwargs.*",
        "context.decision.reason",
        "context.history.*.reason",
    }
)
_REDACTED = "[REDACTED]"
_GENESIS_HASH = "0" * 64
_SOURCE_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class AuditSink(Protocol):
    def write(self, event: Mapping[str, Any]) -> None | Awaitable[None]: ...


class InMemoryAuditSink:
    production_durable = False
    production_integrity_protected = False

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def write(self, event: Mapping[str, Any]) -> None:
        with self._lock:
            self.events.append(dict(event))


class _AuditCodec:
    def __init__(
        self,
        *,
        sign_key: bytes | str | None,
        sensitive_keys: Iterable[str],
        sensitive_paths: Iterable[str],
        value_patterns: Iterable[str | re.Pattern[str]],
        allow_paths: Iterable[str],
    ) -> None:
        self.key = sign_key.encode() if isinstance(sign_key, str) else sign_key
        self.sensitive_keys = frozenset(key.lower() for key in sensitive_keys)
        self.sensitive_paths = frozenset(str(path) for path in sensitive_paths)
        self.allow_paths = frozenset(str(path) for path in allow_paths)
        self.value_patterns = tuple(
            re.compile(pattern) if isinstance(pattern, str) else pattern
            for pattern in value_patterns
        )

    def prepare(
        self, event: Mapping[str, Any], *, sequence: int, prev_hash: str
    ) -> dict[str, Any]:
        payload = redact_sensitive_data(
            dict(event),
            sensitive_keys=self.sensitive_keys,
            sensitive_paths=self.sensitive_paths,
            value_patterns=self.value_patterns,
            allow_paths=self.allow_paths,
        )
        payload["sequence"] = sequence
        payload["prev_hash"] = prev_hash
        payload["event_hash"] = _event_hash(payload)
        if self.key:
            payload["signature"] = sign_event(payload, self.key)
        return payload

    def verify(
        self,
        event: dict[str, Any],
        *,
        expected_sequence: int,
        expected_prev_hash: str,
        location: str,
    ) -> tuple[dict[str, Any], str]:
        signature = event.pop("signature", None)
        if self.key:
            expected_signature = sign_event(event, self.key)
            if not signature or not hmac.compare_digest(signature, expected_signature):
                raise AuditIntegrityError(f"invalid audit signature at {location}")
        sequence = event.get("sequence")
        prev_hash = event.get("prev_hash")
        recorded_hash = event.pop("event_hash", None)
        if sequence != expected_sequence:
            raise AuditIntegrityError(
                f"invalid audit sequence at {location}: expected {expected_sequence}, got {sequence}"
            )
        if prev_hash != expected_prev_hash:
            raise AuditIntegrityError(f"broken audit hash chain at {location}")
        calculated_hash = _event_hash(event)
        if not isinstance(recorded_hash, str) or not hmac.compare_digest(
            recorded_hash, calculated_hash
        ):
            raise AuditIntegrityError(f"invalid audit event hash at {location}")
        event["event_hash"] = recorded_hash
        if signature is not None:
            event["signature"] = signature
        return event, recorded_hash

    def sign_state(self, state: Mapping[str, Any]) -> str | None:
        if self.key is None:
            return None
        payload = {
            key: value for key, value in state.items() if key != "state_signature"
        }
        encoded = b"audit-state-v1\0" + _canonical_json(payload).encode("utf-8")
        return hmac.new(self.key, encoded, hashlib.sha256).hexdigest()


class JSONLAuditSink:
    """Durable, hash-chained JSONL audit sink with cross-process rotation."""

    production_durable = True

    def __init__(
        self,
        path: str | Path,
        *,
        sign_key: bytes | str | None = None,
        sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
        sensitive_paths: Iterable[str] = DEFAULT_SENSITIVE_PATHS,
        value_patterns: Iterable[str | re.Pattern[str]] = (),
        allow_paths: Iterable[str] = (),
        max_bytes: int | None = None,
        backup_count: int | None = None,
        lock_timeout: float = 30.0,
    ) -> None:
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if backup_count is not None and backup_count < 1:
            raise ValueError("backup_count must be at least 1")
        if backup_count is not None and max_bytes is None:
            raise ValueError("backup_count requires max_bytes")
        if lock_timeout <= 0:
            raise ValueError("lock_timeout must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._codec = _AuditCodec(
            sign_key=sign_key,
            sensitive_keys=sensitive_keys,
            sensitive_paths=sensitive_paths,
            value_patterns=value_patterns,
            allow_paths=allow_paths,
        )
        self._lock = FileLock(str(self.path) + ".lock", timeout=lock_timeout)
        self._state_path = Path(str(self.path) + ".state")

    @property
    def production_integrity_protected(self) -> bool:
        return self._codec.key is not None and len(self._codec.key) >= 32

    def write(self, event: Mapping[str, Any]) -> None:
        with self._lock:
            state = self._load_state_for_write()
            sequence = int(state["last_sequence"]) + 1
            prev_hash = str(state["last_hash"])
            payload = self._codec.prepare(
                event, sequence=sequence, prev_hash=prev_hash
            )
            line = _canonical_json(payload)
            if self._should_rotate(len((line + "\n").encode("utf-8"))):
                self._rotate()
                state = self._state_before_prune(state)
                self._write_state(state)
                self._prune_rotated_segments()
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if int(state["last_sequence"]) < int(state["first_sequence"]):
                state["first_sequence"] = sequence
                state["first_prev_hash"] = prev_hash
            state["last_sequence"] = sequence
            state["last_hash"] = payload["event_hash"]
            self._write_state(state)

    def read_verified(self) -> list[dict[str, Any]]:
        with self._lock:
            state = self._load_or_rebuild_state()
            events = self._read_verified_unlocked(state)
            self._verify_tail(events, state)
            return events

    def _read_verified_unlocked(
        self, state: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        expected_sequence = int(state["first_sequence"])
        expected_prev_hash = str(state["first_prev_hash"])
        for path in self._segment_paths():
            with path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    if not line.strip():
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise AuditIntegrityError(
                            f"invalid audit JSON at {path.name}:{line_number}"
                        ) from exc
                    if not isinstance(raw, dict):
                        raise AuditIntegrityError(
                            f"audit event must be an object at {path.name}:{line_number}"
                        )
                    raw_sequence = raw.get("sequence")
                    if isinstance(raw_sequence, int) and raw_sequence < expected_sequence:
                        # The retained-chain anchor is committed before old
                        # rotated segments are removed.
                        continue
                    event, expected_prev_hash = self._codec.verify(
                        raw,
                        expected_sequence=expected_sequence,
                        expected_prev_hash=expected_prev_hash,
                        location=f"{path.name}:{line_number}",
                    )
                    events.append(event)
                    expected_sequence += 1
        return events

    def _load_or_rebuild_state(self) -> dict[str, Any]:
        if self._state_path.exists():
            try:
                state = json.loads(self._state_path.read_text(encoding="utf-8"))
                self._validate_state_shape(state)
                events = self._read_verified_unlocked(state)
                return self._reconcile_appended_tail(events, state)
            except AuditIntegrityError:
                raise
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise AuditIntegrityError("invalid audit state file") from exc
        if any(self._segment_paths()):
            raise AuditIntegrityError(
                "audit state file is missing; existing events cannot be trusted"
            )
        return {
            "schema_version": 1,
            "first_sequence": 0,
            "first_prev_hash": _GENESIS_HASH,
            "last_sequence": -1,
            "last_hash": _GENESIS_HASH,
        }

    def _load_state_for_write(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return self._load_or_rebuild_state()
        try:
            state = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._validate_state_shape(state)
            tail = self._read_tail_unlocked()
            if tail is None:
                self._verify_tail([], state)
                return state
            sequence, event_hash = tail
            state_sequence = int(state["last_sequence"])
            if sequence == state_sequence and hmac.compare_digest(
                event_hash, str(state["last_hash"])
            ):
                return state
            if sequence > state_sequence:
                # A previous process may have crashed after fsyncing one or more
                # complete events but before atomically replacing the state file.
                return self._load_or_rebuild_state()
            raise AuditIntegrityError("audit tail does not match durable state")
        except AuditIntegrityError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise AuditIntegrityError("invalid audit state file") from exc

    def _reconcile_appended_tail(
        self, events: list[dict[str, Any]], state: dict[str, Any]
    ) -> dict[str, Any]:
        if not events:
            self._verify_tail(events, state)
            return state
        last = events[-1]
        state_sequence = int(state["last_sequence"])
        if last["sequence"] == state_sequence and hmac.compare_digest(
            str(last["event_hash"]), str(state["last_hash"])
        ):
            return state
        if last["sequence"] < state_sequence:
            raise AuditIntegrityError("audit events were deleted")
        if state_sequence >= int(state["first_sequence"]):
            checkpoint = next(
                (
                    event
                    for event in events
                    if int(event["sequence"]) == state_sequence
                ),
                None,
            )
            if checkpoint is None or not hmac.compare_digest(
                str(checkpoint["event_hash"]), str(state["last_hash"])
            ):
                raise AuditIntegrityError(
                    "audit log does not extend the durable state"
                )
        state["last_sequence"] = int(last["sequence"])
        state["last_hash"] = str(last["event_hash"])
        self._write_state(state)
        return state

    def _read_tail_unlocked(self) -> tuple[int, str] | None:
        for path in reversed(self._segment_paths()):
            if not path.exists() or path.stat().st_size == 0:
                continue
            last_line: bytes | None = None
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                position = stream.tell()
                buffer = bytearray()
                while position > 0:
                    position -= 1
                    stream.seek(position)
                    byte = stream.read(1)
                    if byte == b"\n":
                        if buffer:
                            last_line = bytes(reversed(buffer))
                            break
                        continue
                    buffer.extend(byte)
                if last_line is None and buffer:
                    last_line = bytes(reversed(buffer))
            if not last_line:
                continue
            try:
                raw = json.loads(last_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuditIntegrityError(f"invalid audit JSON at tail of {path.name}") from exc
            if not isinstance(raw, dict):
                raise AuditIntegrityError(f"audit event must be an object at tail of {path.name}")
            sequence = raw.get("sequence")
            event_hash = raw.get("event_hash")
            prev_hash = raw.get("prev_hash")
            if (
                not isinstance(sequence, int)
                or not isinstance(event_hash, str)
                or not isinstance(prev_hash, str)
            ):
                raise AuditIntegrityError(f"invalid audit tail at {path.name}")
            event, _ = self._codec.verify(
                raw,
                expected_sequence=sequence,
                expected_prev_hash=prev_hash,
                location=f"tail of {path.name}",
            )
            return sequence, str(event["event_hash"])
        return None

    def _validate_state_shape(self, state: Mapping[str, Any]) -> None:
        required = {
            "first_sequence",
            "first_prev_hash",
            "last_sequence",
            "last_hash",
        }
        if not required.issubset(state):
            raise AuditIntegrityError("audit state file is incomplete")
        if not isinstance(state["first_sequence"], int) or not isinstance(
            state["last_sequence"], int
        ):
            raise AuditIntegrityError("audit state sequence is invalid")
        for key in ("first_prev_hash", "last_hash"):
            value = state[key]
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise AuditIntegrityError(f"audit state {key} is invalid")
        expected_signature = self._codec.sign_state(state)
        if expected_signature is not None:
            recorded_signature = state.get("state_signature")
            if not isinstance(recorded_signature, str) or not hmac.compare_digest(
                recorded_signature, expected_signature
            ):
                raise AuditIntegrityError("invalid audit state signature")

    @staticmethod
    def _verify_tail(
        events: list[dict[str, Any]], state: Mapping[str, Any]
    ) -> None:
        if not events:
            if int(state["last_sequence"]) >= int(state["first_sequence"]):
                raise AuditIntegrityError("audit events were deleted")
            return
        last = events[-1]
        if (
            last["sequence"] != state["last_sequence"]
            or last["event_hash"] != state["last_hash"]
        ):
            raise AuditIntegrityError("audit tail does not match durable state")

    def _should_rotate(self, incoming_size: int) -> bool:
        return bool(
            self.max_bytes
            and self.path.exists()
            and self.path.stat().st_size > 0
            and self.path.stat().st_size + incoming_size > self.max_bytes
        )

    def _rotate(self) -> None:
        indices = self._backup_indices()
        for index in sorted(indices, reverse=True):
            source = Path(f"{self.path}.{index}")
            os.replace(source, Path(f"{self.path}.{index + 1}"))
        if self.path.exists():
            os.replace(self.path, Path(f"{self.path}.1"))
        _fsync_directory(self.path.parent)

    def _prune_rotated_segments(self) -> None:
        if self.backup_count is not None:
            for index in self._backup_indices():
                if index > self.backup_count:
                    Path(f"{self.path}.{index}").unlink(missing_ok=True)
        _fsync_directory(self.path.parent)

    def _state_before_prune(self, state: dict[str, Any]) -> dict[str, Any]:
        if self.backup_count is None:
            return state
        first = self._first_raw_event(max_backup_index=self.backup_count)
        if first is None:
            return state
        state["first_sequence"] = int(first["sequence"])
        state["first_prev_hash"] = str(first["prev_hash"])
        return state

    def _first_raw_event(
        self, *, max_backup_index: int | None = None
    ) -> dict[str, Any] | None:
        for path in self._segment_paths():
            if path != self.path and max_backup_index is not None:
                suffix = path.name.removeprefix(self.path.name + ".")
                if suffix.isdigit() and int(suffix) > max_backup_index:
                    continue
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if line.strip():
                        try:
                            value = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise AuditIntegrityError(
                                f"invalid audit JSON at head of {path.name}"
                            ) from exc
                        if not isinstance(value, dict):
                            raise AuditIntegrityError(
                                f"audit event at head of {path.name} must be an object"
                            )
                        sequence = value.get("sequence")
                        prev_hash = value.get("prev_hash")
                        if (
                            isinstance(sequence, bool)
                            or not isinstance(sequence, int)
                            or sequence < 0
                            or not isinstance(prev_hash, str)
                        ):
                            raise AuditIntegrityError(
                                f"invalid audit anchor at head of {path.name}"
                            )
                        return value
        return None

    def _segment_paths(self) -> list[Path]:
        backups = [Path(f"{self.path}.{index}") for index in self._backup_indices()]
        paths = list(reversed(backups))
        if self.path.exists():
            paths.append(self.path)
        return paths

    def _backup_indices(self) -> list[int]:
        prefix = self.path.name + "."
        indices: list[int] = []
        for candidate in self.path.parent.glob(prefix + "*"):
            suffix = candidate.name.removeprefix(prefix)
            if suffix.isdigit():
                indices.append(int(suffix))
        return sorted(indices)

    def _write_state(self, state: Mapping[str, Any]) -> None:
        payload = dict(state)
        payload.pop("state_signature", None)
        signature = self._codec.sign_state(payload)
        if signature is not None:
            payload["state_signature"] = signature
        temporary = self._state_path.with_name(
            f"{self._state_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(_canonical_json(payload) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._state_path)
            _fsync_directory(self._state_path.parent)
        finally:
            temporary.unlink(missing_ok=True)


class SQLiteAuditSink:
    """Transactional audit sink for multi-process production runtimes."""

    production_durable = True
    reconciliation_delivery_idempotent = True

    def __init__(
        self,
        path: str | Path,
        *,
        sign_key: bytes | str | None = None,
        sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
        sensitive_paths: Iterable[str] = DEFAULT_SENSITIVE_PATHS,
        value_patterns: Iterable[str | re.Pattern[str]] = (),
        allow_paths: Iterable[str] = (),
        timeout_seconds: float = 30.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self._codec = _AuditCodec(
            sign_key=sign_key,
            sensitive_keys=sensitive_keys,
            sensitive_paths=sensitive_paths,
            value_patterns=value_patterns,
            allow_paths=allow_paths,
        )
        self._initialize()

    @property
    def production_integrity_protected(self) -> bool:
        return self._codec.key is not None and len(self._codec.key) >= 32

    def write(self, event: Mapping[str, Any]) -> None:
        self._write(event)

    def write_idempotent(
        self, source_event_id: str, event: Mapping[str, Any]
    ) -> None:
        """Append a source-stable event exactly once, or verify a safe retry."""

        if not _SOURCE_EVENT_ID.fullmatch(source_event_id):
            raise ValueError("source_event_id must be a stable identifier")
        self._write(event, source_event_id=source_event_id)

    def _write(
        self,
        event: Mapping[str, Any],
        *,
        source_event_id: str | None = None,
    ) -> None:
        source_payload_digest = None
        if source_event_id is not None:
            source_payload_digest = _source_payload_digest(self._codec, event)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if source_event_id is not None:
                existing = connection.execute(
                    """
                    SELECT source_payload_digest FROM audit_events
                    WHERE source_event_id = ?
                    """,
                    (source_event_id,),
                ).fetchone()
                if existing is not None:
                    existing_digest = existing[0]
                    if not isinstance(existing_digest, str) or not hmac.compare_digest(
                        existing_digest, source_payload_digest
                    ):
                        raise AuditIntegrityError(
                            "audit source event was retried with different content"
                        )
                    connection.commit()
                    return
            row = connection.execute(
                "SELECT last_sequence, last_hash FROM audit_state WHERE id = 1"
            ).fetchone()
            if row is None:
                raise AuditIntegrityError("audit state row is missing")
            sequence = int(row[0]) + 1
            payload = self._codec.prepare(
                event, sequence=sequence, prev_hash=str(row[1])
            )
            connection.execute(
                """
                INSERT INTO audit_events(
                    sequence, event_json, event_hash, source_event_id,
                    source_payload_digest
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    _canonical_json(payload),
                    payload["event_hash"],
                    source_event_id,
                    source_payload_digest,
                ),
            )
            connection.execute(
                "UPDATE audit_state SET last_sequence = ?, last_hash = ? WHERE id = 1",
                (sequence, payload["event_hash"]),
            )
            connection.commit()

    def read_verified(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                "SELECT sequence, event_json, event_hash FROM audit_events ORDER BY sequence"
            ).fetchall()
            state = connection.execute(
                "SELECT last_sequence, last_hash FROM audit_state WHERE id = 1"
            ).fetchone()
        events: list[dict[str, Any]] = []
        expected_prev_hash = _GENESIS_HASH
        for expected_sequence, (sequence, encoded, stored_hash) in enumerate(rows):
            if sequence != expected_sequence:
                raise AuditIntegrityError(
                    f"invalid audit sequence in SQLite: expected {expected_sequence}, got {sequence}"
                )
            try:
                raw = json.loads(encoded)
            except json.JSONDecodeError as exc:
                raise AuditIntegrityError(
                    f"invalid audit JSON in SQLite sequence {sequence}"
                ) from exc
            event, expected_prev_hash = self._codec.verify(
                raw,
                expected_sequence=expected_sequence,
                expected_prev_hash=expected_prev_hash,
                location=f"SQLite sequence {sequence}",
            )
            if not hmac.compare_digest(str(stored_hash), event["event_hash"]):
                raise AuditIntegrityError(
                    f"audit index hash mismatch in SQLite sequence {sequence}"
                )
            events.append(event)
        if state is None:
            raise AuditIntegrityError("SQLite audit state is missing")
        expected_sequence = len(events) - 1
        expected_hash = events[-1]["event_hash"] if events else _GENESIS_HASH
        if int(state[0]) != expected_sequence or not hmac.compare_digest(
            str(state[1]), expected_hash
        ):
            raise AuditIntegrityError("SQLite audit tail does not match durable state")
        return events

    def _initialize(self) -> None:
        with initialize_sqlite(self.path, self.timeout_seconds) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    source_event_id TEXT,
                    source_payload_digest TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_sequence INTEGER NOT NULL,
                    last_hash TEXT NOT NULL
                );
                """
            )
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(audit_events)")
            }
            if "source_event_id" not in columns:
                connection.execute(
                    "ALTER TABLE audit_events ADD COLUMN source_event_id TEXT"
                )
            if "source_payload_digest" not in columns:
                connection.execute(
                    "ALTER TABLE audit_events ADD COLUMN source_payload_digest TEXT"
                )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_source_event_id
                ON audit_events(source_event_id)
                WHERE source_event_id IS NOT NULL
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO audit_state(id, last_sequence, last_hash) VALUES (1, -1, ?)",
                (_GENESIS_HASH,),
            )

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.path, self.timeout_seconds)


def context_event(context: ExecutionContext, *, stage: str) -> dict[str, Any]:
    context_data = context.to_dict()
    action = context.bound_action
    if action is not None:
        context_data["bound_action"] = action.to_evidence_dict()
    context_data["tool_call"] = {
        "name": context.tool_call.name,
        "args": _safe_json_value(context.tool_call.args),
        "kwargs": _safe_json_value(context.tool_call.kwargs),
    }
    context_data["result"] = _safe_json_value(context.result)
    return {
        "schema_version": 3,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "trace_id": context.trace_id,
        "span_id": context.span_id,
        "request_id": context.request_id,
        "tool_name": context.tool_call.name,
        "contract_id": action.contract.contract_id if action is not None else None,
        "contract_version": (
            action.contract.contract_version if action is not None else None
        ),
        "action_digest": action.action_digest if action is not None else None,
        "risk_tier": context.risk_tier.name,
        "risk_score": context.risk_score,
        "status": context.status.value,
        "decision": context.decision.outcome.value if context.decision else None,
        "reason": context.decision.reason if context.decision else context.error,
        "context": context_data,
    }


def reconciliation_event(
    head: Any,
    *,
    event_type: str,
    provider: Any | None = None,
    attempt_id: str | None = None,
    outcome: str | None = None,
    evidence_kind: str | None = None,
    evidence: Mapping[str, Any] | None = None,
    operator_identity_digest: str | None = None,
) -> dict[str, Any]:
    """Build a lineage-only audit record for explicit reconciliation work.

    Reconciliation evidence can contain provider-specific receipt data, so the
    audit channel records only its canonical digest.  The durable reconciliation
    ledger remains the authority for the bounded evidence payload.
    """

    action = head.action
    metadata = action.metadata
    trace_id = metadata.get("trace_id")
    request_id = metadata.get("request_id")
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
            _canonical_json({"evidence": _safe_json_value(evidence)}).encode("utf-8")
        ).hexdigest()
    return {
        "schema_version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
        "outcome": outcome,
        "evidence_kind": evidence_kind,
        "evidence_digest": evidence_digest,
        "operator_identity_digest": operator_identity_digest,
    }


def sign_event(event: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical_json(event).encode("utf-8"), hashlib.sha256).hexdigest()


def _event_hash(event: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in event.items() if key not in {"event_hash", "signature"}}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _source_payload_digest(codec: _AuditCodec, event: Mapping[str, Any]) -> str:
    """Digest the same redacted source payload used for an idempotent retry."""

    redacted = redact_sensitive_data(
        dict(event),
        sensitive_keys=codec.sensitive_keys,
        sensitive_paths=codec.sensitive_paths,
        value_patterns=codec.value_patterns,
        allow_paths=codec.allow_paths,
    )
    return hashlib.sha256(_canonical_json(redacted).encode("utf-8")).hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> str:
    return legacy_audit_json_text(value)


def redact_sensitive_data(
    value: Any,
    *,
    sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
    sensitive_paths: Iterable[str] = DEFAULT_SENSITIVE_PATHS,
    value_patterns: Iterable[str | re.Pattern[str]] = (),
    allow_paths: Iterable[str] = (),
) -> Any:
    """Return a JSON-safe copy with configured secrets removed."""

    patterns = tuple(
        re.compile(pattern) if isinstance(pattern, str) else pattern
        for pattern in value_patterns
    )
    return _redact(
        _safe_json_value(value),
        frozenset(str(key).lower() for key in sensitive_keys),
        frozenset(str(path) for path in sensitive_paths),
        patterns,
        frozenset(str(path) for path in allow_paths),
    )


def _redact(
    value: Any,
    sensitive_keys: frozenset[str],
    sensitive_paths: frozenset[str],
    value_patterns: tuple[re.Pattern[str], ...],
    allow_paths: frozenset[str],
    *,
    path: str = "",
) -> Any:
    if path and _matches_path(path, allow_paths):
        return value
    if path and _matches_path(path, sensitive_paths):
        return _REDACTED
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            result[str(key)] = (
                _REDACTED
                if normalized in sensitive_keys and not _matches_path(child_path, allow_paths)
                else _redact(
                    item,
                    sensitive_keys,
                    sensitive_paths,
                    value_patterns,
                    allow_paths,
                    path=child_path,
                )
            )
        return result
    if isinstance(value, list | tuple):
        return [
            _redact(
                item,
                sensitive_keys,
                sensitive_paths,
                value_patterns,
                allow_paths,
                path=f"{path}.{index}" if path else str(index),
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        for pattern in value_patterns:
            value = pattern.sub(_REDACTED, value)
        return value
    return value


def _matches_path(path: str, patterns: frozenset[str]) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def _safe_json_value(value: Any) -> Any:
    if isinstance(value, float):
        return _json_safe(value)
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, Mapping):
        return {str(key): _safe_json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_safe_json_value(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted((_safe_json_value(item) for item in value), key=str)
    return f"[UNSERIALIZABLE:{type(value).__name__}]"


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
