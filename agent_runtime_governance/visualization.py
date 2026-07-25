from __future__ import annotations

import re
from typing import Iterable

from .snapshots import ContextSnapshot


def trace_to_mermaid(snapshots: Iterable[ContextSnapshot]) -> str:
    items = sorted(snapshots, key=lambda item: item.sequence)
    lines = ["flowchart LR"]
    previous: str | None = None
    for snapshot in items:
        node = f"S{snapshot.sequence}"
        label = _label(snapshot)
        lines.append(f'    {node}["{label}"]')
        if previous is not None:
            lines.append(f"    {previous} --> {node}")
        previous = node
    if not items:
        lines.append('    EMPTY["No snapshots"]')
    return "\n".join(lines)


def _label(snapshot: ContextSnapshot) -> str:
    raw = (
        f"{snapshot.sequence}: {snapshot.stage} | "
        f"{snapshot.context.status.value} | risk {snapshot.context.risk_score:.2f}"
    )
    return re.sub(r"[^A-Za-z0-9 .:_|/-]", "", raw)
