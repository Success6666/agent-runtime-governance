from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .context import ExecutionContext, ExecutionStatus, HistoryEntry
from .middleware.base import ObservingMiddleware


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


class InMemorySnapshotStore:
    def __init__(self) -> None:
        self._snapshots: list[ContextSnapshot] = []
        self._lock = threading.Lock()

    def write(self, snapshot: ContextSnapshot) -> None:
        with self._lock:
            self._snapshots.append(snapshot)

    def read_trace(self, trace_id: str) -> tuple[ContextSnapshot, ...]:
        with self._lock:
            return tuple(
                item for item in self._snapshots if item.trace_id == trace_id
            )


class JSONLSnapshotStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, snapshot: ContextSnapshot) -> None:
        line = json.dumps(
            snapshot.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        with self._lock:
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line + "\n")

    def read_trace(self, trace_id: str) -> tuple[ContextSnapshot, ...]:
        if not self.path.exists():
            return ()
        snapshots: list[ContextSnapshot] = []
        with self._lock:
            with self.path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    if data.get("trace_id") == trace_id:
                        snapshots.append(ContextSnapshot.from_dict(data))
        return tuple(sorted(snapshots, key=lambda item: item.sequence))


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
        with self._lock:
            sequence = self._sequences.get(context.trace_id, 0)
            self._sequences[context.trace_id] = sequence + 1
        updated = context.append_history(
            HistoryEntry(
                self.name,
                "record",
                f"recorded {stage} snapshot",
                data={"stage": stage, "sequence": sequence},
            )
        )
        self.store.write(
            ContextSnapshot(
                trace_id=context.trace_id,
                sequence=sequence,
                stage=stage,
                context=updated,
                created_at=datetime.now(timezone.utc).isoformat(),
                policy_version=updated.metadata.get("policy_version"),
                policy_digest=updated.metadata.get("policy_digest"),
            )
        )
        if context.status in {
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.FAILED,
            ExecutionStatus.DENIED,
        }:
            with self._lock:
                self._sequences.pop(context.trace_id, None)
        return updated

    @staticmethod
    def _stage(context: ExecutionContext) -> str:
        if context.status in {ExecutionStatus.SUCCEEDED, ExecutionStatus.FAILED}:
            return "result"
        if context.status is ExecutionStatus.DENIED:
            return "decision"
        return "governance"

