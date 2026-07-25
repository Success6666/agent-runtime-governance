from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .context import ExecutionContext


@dataclass(frozen=True, slots=True)
class ReplayTrace:
    trace_id: str
    snapshots: tuple[ExecutionContext, ...]

    @classmethod
    def from_jsonl(cls, path: str | Path, trace_id: str) -> "ReplayTrace":
        snapshots: list[ExecutionContext] = []
        with Path(path).open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                event = json.loads(line)
                if event.get("trace_id") == trace_id and "context" in event:
                    snapshots.append(ExecutionContext.from_dict(event["context"]))
        return cls(trace_id=trace_id, snapshots=tuple(snapshots))

    def lines(self) -> Iterable[str]:
        for index, context in enumerate(self.snapshots):
            yield (
                f"{index:02d} {context.status.value:<10} "
                f"{context.tool_call.name} risk={context.risk_score:.2f}"
            )

    def print(self) -> None:
        for line in self.lines():
            print(line)

