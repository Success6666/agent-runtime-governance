from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Mapping, Protocol, runtime_checkable

from filelock import FileLock

from ._blocking import invoke_extension
from ._canonical import legacy_audit_json_bytes, legacy_storage_json_text
from ._redaction import DEFAULT_SENSITIVE_KEYS, redact_sensitive_data
from ._sqlite import connect_sqlite, initialize_sqlite
from .context import ExecutionContext, ExecutionStatus, HistoryEntry
from .errors import AuditIntegrityError
from .middleware.base import ObservingMiddleware

SNAPSHOT_SENSITIVE_PATHS = frozenset(
    {
        "context.input_text",
        "context.result",
        "context.error",
        "context.tool_call.args.*",
        "context.tool_call.kwargs.*",
        "context.decision.reason",
        "context.history.*.reason",
    }
)


class _SnapshotCodec:
    def __init__(
        self,
        *,
        sign_key: bytes | str | None,
        redact: bool,
        sensitive_keys: Iterable[str],
        value_patterns: Iterable[str | re.Pattern[str]],
        allow_paths: Iterable[str],
    ) -> None:
        self.key = sign_key.encode() if isinstance(sign_key, str) else sign_key
        self.redact = redact
        self.sensitive_keys = tuple(sensitive_keys)
        self.value_patterns = tuple(value_patterns)
        self.allow_paths = tuple(allow_paths)

    def encode(self, snapshot: "ContextSnapshot") -> dict[str, Any]:
        payload = snapshot.to_dict()
        if self.redact:
            payload = redact_sensitive_data(
                payload,
                sensitive_keys=self.sensitive_keys,
                sensitive_paths=SNAPSHOT_SENSITIVE_PATHS,
                value_patterns=self.value_patterns,
                allow_paths=self.allow_paths,
            )
        payload["snapshot_hash"] = _snapshot_hash(payload)
        if self.key is not None:
            payload["signature"] = _snapshot_signature(payload, self.key)
        return payload

    def decode(self, raw: Mapping[str, Any], *, location: str) -> "ContextSnapshot":
        payload = dict(raw)
        signature = payload.pop("signature", None)
        if self.key is not None:
            expected_signature = _snapshot_signature(payload, self.key)
            if not isinstance(signature, str) or not hmac.compare_digest(
                signature, expected_signature
            ):
                raise AuditIntegrityError(
                    f"invalid snapshot signature at {location}"
                )
        recorded_hash = payload.pop("snapshot_hash", None)
        calculated_hash = _snapshot_hash(payload)
        if not isinstance(recorded_hash, str) or not hmac.compare_digest(
            recorded_hash, calculated_hash
        ):
            raise AuditIntegrityError(f"invalid snapshot hash at {location}")
        return ContextSnapshot.from_dict(payload)


@dataclass(frozen=True, slots=True)
class ContextSnapshot:
    trace_id: str
    sequence: int
    stage: str
    context: ExecutionContext
    created_at: str
    policy_version: str | None = None
    policy_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "trace_id": self.trace_id,
            "sequence": self.sequence,
            "stage": self.stage,
            "created_at": self.created_at,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "context": self.context.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ContextSnapshot":
        return cls(
            trace_id=str(data["trace_id"]),
            sequence=int(data["sequence"]),
            stage=str(data["stage"]),
            created_at=str(data["created_at"]),
            policy_version=data.get("policy_version"),
            policy_digest=data.get("policy_digest"),
            context=ExecutionContext.from_dict(data["context"]),
        )


class SnapshotStore(Protocol):
    def write(self, snapshot: ContextSnapshot) -> None | Awaitable[None]: ...
    def read_trace(self, trace_id: str) -> tuple[ContextSnapshot, ...]: ...


@runtime_checkable
class AtomicSnapshotStore(SnapshotStore, Protocol):
    def write_context(
        self,
        *,
        trace_id: str,
        stage: str,
        context: ExecutionContext,
        created_at: str,
        policy_version: str | None,
        policy_digest: str | None,
    ) -> ContextSnapshot | Awaitable[ContextSnapshot]: ...


class InMemorySnapshotStore:
    def __init__(self) -> None:
        self._snapshots: list[ContextSnapshot] = []
        self._lock = threading.Lock()

    def write(self, snapshot: ContextSnapshot) -> None:
        with self._lock:
            self._snapshots.append(snapshot)

    def write_context(
        self,
        *,
        trace_id: str,
        stage: str,
        context: ExecutionContext,
        created_at: str,
        policy_version: str | None,
        policy_digest: str | None,
    ) -> ContextSnapshot:
        with self._lock:
            sequence = _next_sequence(item for item in self._snapshots if item.trace_id == trace_id)
            context = _context_with_sequence(context, stage, sequence)
            snapshot = ContextSnapshot(
                trace_id=trace_id,
                sequence=sequence,
                stage=stage,
                context=context,
                created_at=created_at,
                policy_version=policy_version,
                policy_digest=policy_digest,
            )
            self._snapshots.append(snapshot)
            return snapshot

    def read_trace(self, trace_id: str) -> tuple[ContextSnapshot, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (item for item in self._snapshots if item.trace_id == trace_id),
                    key=lambda item: item.sequence,
                )
            )


class JSONLSnapshotStore:
    def __init__(
        self,
        path: str | Path,
        *,
        lock_timeout: float = 30.0,
        sign_key: bytes | str | None = None,
        redact_sensitive: bool = True,
        sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
        value_patterns: Iterable[str | re.Pattern[str]] = (),
        allow_paths: Iterable[str] = (),
    ) -> None:
        if lock_timeout <= 0:
            raise ValueError("lock_timeout must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = FileLock(str(self.path) + ".lock", timeout=lock_timeout)
        self._state_path = Path(str(self.path) + ".state")
        self._codec = _SnapshotCodec(
            sign_key=sign_key,
            redact=redact_sensitive,
            sensitive_keys=sensitive_keys,
            value_patterns=value_patterns,
            allow_paths=allow_paths,
        )

    def write(self, snapshot: ContextSnapshot) -> None:
        with self._lock:
            state = self._load_sequence_state_unlocked()
            last_sequence = int(state["sequences"].get(snapshot.trace_id, -1))
            if snapshot.sequence <= last_sequence:
                snapshot = replace(
                    snapshot,
                    sequence=last_sequence + 1,
                )
            file_size = self._append_unlocked(snapshot)
            state["sequences"][snapshot.trace_id] = snapshot.sequence
            state["file_size"] = file_size
            self._write_sequence_state_unlocked(state)

    def write_context(
        self,
        *,
        trace_id: str,
        stage: str,
        context: ExecutionContext,
        created_at: str,
        policy_version: str | None,
        policy_digest: str | None,
    ) -> ContextSnapshot:
        with self._lock:
            state = self._load_sequence_state_unlocked()
            sequence = int(state["sequences"].get(trace_id, -1)) + 1
            context = _context_with_sequence(context, stage, sequence)
            snapshot = ContextSnapshot(
                trace_id=trace_id,
                sequence=sequence,
                stage=stage,
                context=context,
                created_at=created_at,
                policy_version=policy_version,
                policy_digest=policy_digest,
            )
            file_size = self._append_unlocked(snapshot)
            state["sequences"][trace_id] = sequence
            state["file_size"] = file_size
            self._write_sequence_state_unlocked(state)
            return snapshot

    def read_trace(self, trace_id: str) -> tuple[ContextSnapshot, ...]:
        with self._lock:
            snapshots = [
                item for item in self._read_all_unlocked() if item.trace_id == trace_id
            ]
        return tuple(sorted(snapshots, key=lambda item: item.sequence))

    def _append_unlocked(self, snapshot: ContextSnapshot) -> int:
        line = legacy_storage_json_text(self._codec.encode(snapshot))
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return self.path.stat().st_size

    def _load_sequence_state_unlocked(self) -> dict[str, Any]:
        actual_size = self.path.stat().st_size if self.path.exists() else 0
        if not self._state_path.exists():
            if actual_size == 0:
                return {"schema_version": 1, "file_size": 0, "sequences": {}}
            return self._rebuild_sequence_state_unlocked(actual_size)
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
            state = self._verify_sequence_state(raw)
        except AuditIntegrityError:
            raise
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise AuditIntegrityError("invalid snapshot state file") from exc
        recorded_size = int(state["file_size"])
        if actual_size < recorded_size:
            raise AuditIntegrityError("snapshot log was truncated")
        if actual_size > recorded_size:
            return self._rebuild_sequence_state_unlocked(actual_size)
        return state

    def _rebuild_sequence_state_unlocked(
        self, actual_size: int
    ) -> dict[str, Any]:
        sequences: dict[str, int] = {}
        for snapshot in self._read_all_unlocked():
            previous = sequences.get(snapshot.trace_id, -1)
            if snapshot.sequence <= previous:
                raise AuditIntegrityError(
                    f"snapshot sequence is not increasing for trace {snapshot.trace_id!r}"
                )
            sequences[snapshot.trace_id] = snapshot.sequence
        state: dict[str, Any] = {
            "schema_version": 1,
            "file_size": actual_size,
            "sequences": sequences,
        }
        self._write_sequence_state_unlocked(state)
        return state

    def _verify_sequence_state(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise AuditIntegrityError("snapshot state must be an object")
        payload = dict(raw)
        signature = payload.pop("state_signature", None)
        recorded_hash = payload.pop("state_hash", None)
        expected_hash = _snapshot_hash(payload)
        if not isinstance(recorded_hash, str) or not hmac.compare_digest(
            recorded_hash, expected_hash
        ):
            raise AuditIntegrityError("invalid snapshot state hash")
        if self._codec.key is not None:
            expected_signature = _snapshot_signature(
                {**payload, "state_hash": recorded_hash},
                self._codec.key,
            )
            if not isinstance(signature, str) or not hmac.compare_digest(
                signature, expected_signature
            ):
                raise AuditIntegrityError("invalid snapshot state signature")
        if payload.get("schema_version") != 1:
            raise AuditIntegrityError("unsupported snapshot state schema")
        file_size = payload.get("file_size")
        sequences = payload.get("sequences")
        if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
            raise AuditIntegrityError("snapshot state file size is invalid")
        if not isinstance(sequences, dict) or any(
            not isinstance(trace_id, str)
            or not trace_id
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 0
            for trace_id, sequence in sequences.items()
        ):
            raise AuditIntegrityError("snapshot state sequences are invalid")
        return payload

    def _write_sequence_state_unlocked(self, state: Mapping[str, Any]) -> None:
        payload = dict(state)
        payload["sequences"] = dict(state["sequences"])
        payload["state_hash"] = _snapshot_hash(payload)
        if self._codec.key is not None:
            payload["state_signature"] = _snapshot_signature(payload, self._codec.key)
        temporary = self._state_path.with_name(
            f"{self._state_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(legacy_storage_json_text(payload) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._state_path)
            _fsync_directory(self._state_path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _read_all_unlocked(self) -> list[ContextSnapshot]:
        if not self.path.exists():
            return []
        snapshots: list[ContextSnapshot] = []
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditIntegrityError(
                        f"invalid snapshot JSON at {self.path.name}:{line_number}"
                    ) from exc
                if not isinstance(raw, dict):
                    raise AuditIntegrityError(
                        f"snapshot must be an object at {self.path.name}:{line_number}"
                    )
                snapshots.append(
                    self._codec.decode(
                        raw, location=f"{self.path.name}:{line_number}"
                    )
                )
        return snapshots


class SQLiteSnapshotStore:
    def __init__(
        self,
        path: str | Path,
        *,
        timeout_seconds: float = 30.0,
        sign_key: bytes | str | None = None,
        redact_sensitive: bool = True,
        sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
        value_patterns: Iterable[str | re.Pattern[str]] = (),
        allow_paths: Iterable[str] = (),
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds
        self._codec = _SnapshotCodec(
            sign_key=sign_key,
            redact=redact_sensitive,
            sensitive_keys=sensitive_keys,
            value_patterns=value_patterns,
            allow_paths=allow_paths,
        )
        self._initialize()

    def write(self, snapshot: ContextSnapshot) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            sequence = snapshot.sequence
            collision = connection.execute(
                "SELECT 1 FROM snapshots WHERE trace_id = ? AND sequence = ?",
                (snapshot.trace_id, sequence),
            ).fetchone()
            if collision:
                sequence = self._next_sequence(connection, snapshot.trace_id)
                snapshot = replace(snapshot, sequence=sequence)
            self._insert(connection, snapshot)
            connection.commit()

    def write_context(
        self,
        *,
        trace_id: str,
        stage: str,
        context: ExecutionContext,
        created_at: str,
        policy_version: str | None,
        policy_digest: str | None,
    ) -> ContextSnapshot:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            sequence = self._next_sequence(connection, trace_id)
            context = _context_with_sequence(context, stage, sequence)
            snapshot = ContextSnapshot(
                trace_id=trace_id,
                sequence=sequence,
                stage=stage,
                context=context,
                created_at=created_at,
                policy_version=policy_version,
                policy_digest=policy_digest,
            )
            self._insert(connection, snapshot)
            connection.commit()
            return snapshot

    def read_trace(self, trace_id: str) -> tuple[ContextSnapshot, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT snapshot_json FROM snapshots WHERE trace_id = ? ORDER BY sequence",
                (trace_id,),
            ).fetchall()
        snapshots: list[ContextSnapshot] = []
        for index, row in enumerate(rows):
            try:
                raw = json.loads(row[0])
            except json.JSONDecodeError as exc:
                raise AuditIntegrityError(
                    f"invalid snapshot JSON in SQLite row {index}"
                ) from exc
            if not isinstance(raw, dict):
                raise AuditIntegrityError(
                    f"snapshot must be an object in SQLite row {index}"
                )
            snapshots.append(
                self._codec.decode(raw, location=f"SQLite row {index}")
            )
        return tuple(snapshots)

    def _initialize(self) -> None:
        with initialize_sqlite(self.path, self.timeout_seconds) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    trace_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    PRIMARY KEY(trace_id, sequence)
                )
                """
            )

    def _insert(self, connection: sqlite3.Connection, snapshot: ContextSnapshot) -> None:
        connection.execute(
            "INSERT INTO snapshots(trace_id, sequence, snapshot_json) VALUES (?, ?, ?)",
            (
                snapshot.trace_id,
                snapshot.sequence,
                legacy_storage_json_text(self._codec.encode(snapshot)),
            ),
        )

    @staticmethod
    def _next_sequence(connection: sqlite3.Connection, trace_id: str) -> int:
        row = connection.execute(
            "SELECT COALESCE(MAX(sequence), -1) + 1 FROM snapshots WHERE trace_id = ?",
            (trace_id,),
        ).fetchone()
        return int(row[0])

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.path, self.timeout_seconds)


class SnapshotMiddleware(ObservingMiddleware):
    name = "snapshot"
    priority = 975
    replayable = False

    def __init__(
        self,
        store: SnapshotStore,
    ) -> None:
        self.store = store
        self._sequences: dict[str, int] = {}
        self._lock = threading.Lock()

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        stage = self._stage(context)
        if any(
            entry.middleware == self.name and entry.data.get("stage") == stage
            for entry in context.history
        ):
            return context
        created_at = datetime.now(timezone.utc).isoformat()
        if isinstance(self.store, AtomicSnapshotStore):
            snapshot = await invoke_extension(
                self.store.write_context,
                trace_id=context.trace_id,
                stage=stage,
                context=context,
                created_at=created_at,
                policy_version=context.metadata.get("policy_version"),
                policy_digest=context.metadata.get("policy_digest"),
            )
            return snapshot.context
        sequence = self._local_sequence(context.trace_id)
        updated = context.append_history(
            HistoryEntry(
                self.name,
                "record",
                f"recorded {stage} snapshot",
                data={"stage": stage, "sequence": sequence},
            )
        )
        snapshot = ContextSnapshot(
            trace_id=context.trace_id,
            sequence=sequence,
            stage=stage,
            context=updated,
            created_at=created_at,
            policy_version=updated.metadata.get("policy_version"),
            policy_digest=updated.metadata.get("policy_digest"),
        )
        await invoke_extension(self.store.write, snapshot)
        if context.status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.DENIED,
            ExecutionStatus.UNKNOWN,
        }:
            with self._lock:
                self._sequences.pop(context.trace_id, None)
        return updated

    def _local_sequence(self, trace_id: str) -> int:
        with self._lock:
            sequence = self._sequences.get(trace_id, 0)
            self._sequences[trace_id] = sequence + 1
            return sequence

    @staticmethod
    def _stage(context: ExecutionContext) -> str:
        if context.status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.UNKNOWN,
        }:
            return "result"
        if context.status is ExecutionStatus.DENIED:
            return "decision"
        return "governance"


def _next_sequence(snapshots: Any) -> int:
    maximum = -1
    for snapshot in snapshots:
        maximum = max(maximum, int(snapshot.sequence))
    return maximum + 1


def _context_with_sequence(
    context: ExecutionContext, stage: str, sequence: int
) -> ExecutionContext:
    return context.append_history(
        HistoryEntry(
            SnapshotMiddleware.name,
            "record",
            f"recorded {stage} snapshot",
            data={"stage": stage, "sequence": sequence},
        )
    )


def _snapshot_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(legacy_audit_json_bytes(payload)).hexdigest()


def _snapshot_signature(payload: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, legacy_audit_json_bytes(payload), hashlib.sha256).hexdigest()


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
