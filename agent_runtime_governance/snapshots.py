from __future__ import annotations

import asyncio
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
from typing import Any, Mapping, Protocol, runtime_checkable

from filelock import FileLock

from ._sqlite import connect_sqlite, initialize_sqlite
from .audit import DEFAULT_SENSITIVE_KEYS, redact_sensitive_data
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
    def write(self, snapshot: ContextSnapshot) -> None: ...
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
    ) -> ContextSnapshot: ...


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
        self._codec = _SnapshotCodec(
            sign_key=sign_key,
            redact=redact_sensitive,
            sensitive_keys=sensitive_keys,
            value_patterns=value_patterns,
            allow_paths=allow_paths,
        )

    def write(self, snapshot: ContextSnapshot) -> None:
        with self._lock:
            snapshots = self._read_all_unlocked()
            if any(
                item.trace_id == snapshot.trace_id and item.sequence == snapshot.sequence
                for item in snapshots
            ):
                snapshot = replace(
                    snapshot,
                    sequence=_next_sequence(
                        item for item in snapshots if item.trace_id == snapshot.trace_id
                    ),
                )
            self._append_unlocked(snapshot)

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
            snapshots = self._read_all_unlocked()
            sequence = _next_sequence(item for item in snapshots if item.trace_id == trace_id)
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
            self._append_unlocked(snapshot)
            return snapshot

    def read_trace(self, trace_id: str) -> tuple[ContextSnapshot, ...]:
        with self._lock:
            snapshots = [
                item for item in self._read_all_unlocked() if item.trace_id == trace_id
            ]
        return tuple(sorted(snapshots, key=lambda item: item.sequence))

    def _append_unlocked(self, snapshot: ContextSnapshot) -> None:
        line = json.dumps(
            self._codec.encode(snapshot),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())

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
                json.dumps(
                    self._codec.encode(snapshot),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
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

    def __init__(self, store: SnapshotStore) -> None:
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
            preliminary = context.append_history(
                HistoryEntry(
                    self.name,
                    "record",
                    f"recorded {stage} snapshot",
                    data={"stage": stage},
                )
            )
            snapshot = await asyncio.to_thread(
                self.store.write_context,
                trace_id=context.trace_id,
                stage=stage,
                context=preliminary,
                created_at=created_at,
                policy_version=preliminary.metadata.get("policy_version"),
                policy_digest=preliminary.metadata.get("policy_digest"),
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
        await asyncio.to_thread(self.store.write, snapshot)
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
            "sequence",
            "snapshot sequence assigned",
            data={"stage": stage, "sequence": sequence},
        )
    )


def _snapshot_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _snapshot_signature(payload: Mapping[str, Any], key: bytes) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()
