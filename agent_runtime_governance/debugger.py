from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .snapshots import SnapshotStore


@dataclass(frozen=True, slots=True)
class DiffEntry:
    path: str
    before: Any
    after: Any


def diff_values(before: Any, after: Any, path: str = "$",) -> tuple[DiffEntry, ...]:
    changes: list[DiffEntry] = []
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        for key in sorted(set(before) | set(after)):
            child = f"{path}.{key}"
            if key not in before:
                changes.append(DiffEntry(child, None, after[key]))
            elif key not in after:
                changes.append(DiffEntry(child, before[key], None))
            else:
                changes.extend(diff_values(before[key], after[key], child))
        return tuple(changes)
    if isinstance(before, Sequence) and not isinstance(before, str | bytes) and isinstance(
        after, Sequence
    ) and not isinstance(after, str | bytes):
        for index in range(max(len(before), len(after))):
            child = f"{path}[{index}]"
            if index >= len(before):
                changes.append(DiffEntry(child, None, after[index]))
            elif index >= len(after):
                changes.append(DiffEntry(child, before[index], None))
            else:
                changes.extend(diff_values(before[index], after[index], child))
        return tuple(changes)
    if before != after:
        changes.append(DiffEntry(path, before, after))
    return tuple(changes)


class ReplayDebugger:
    def __init__(self, store: SnapshotStore) -> None:
        self.store = store

    def timeline(self, trace_id: str) -> tuple[str, ...]:
        return tuple(
            f"{item.sequence:02d} {item.stage:<10} "
            f"{item.context.status.value:<10} risk={item.context.risk_score:.2f}"
            for item in self.store.read_trace(trace_id)
        )

    def diff(
        self, trace_id: str, before_sequence: int, after_sequence: int
    ) -> tuple[DiffEntry, ...]:
        snapshots = {item.sequence: item for item in self.store.read_trace(trace_id)}
        try:
            before = snapshots[before_sequence]
            after = snapshots[after_sequence]
        except KeyError as exc:
            raise KeyError(f"snapshot sequence not found: {exc.args[0]}") from exc
        return diff_values(before.context.to_dict(), after.context.to_dict())

    def format_diff(
        self, trace_id: str, before_sequence: int, after_sequence: int
    ) -> str:
        return "\n".join(
            f"{item.path}: {item.before!r} -> {item.after!r}"
            for item in self.diff(trace_id, before_sequence, after_sequence)
        )

