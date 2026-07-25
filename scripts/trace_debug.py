from __future__ import annotations

import argparse

from agent_runtime_governance import (
    JSONLSnapshotStore,
    ReplayDebugger,
    trace_to_mermaid,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect runtime context snapshots")
    parser.add_argument("snapshot_file")
    parser.add_argument("trace_id")
    parser.add_argument("--diff", nargs=2, type=int, metavar=("FROM", "TO"))
    parser.add_argument("--mermaid", action="store_true")
    args = parser.parse_args()
    store = JSONLSnapshotStore(args.snapshot_file)
    debugger = ReplayDebugger(store)
    if args.diff:
        print(debugger.format_diff(args.trace_id, *args.diff))
    elif args.mermaid:
        print(trace_to_mermaid(store.read_trace(args.trace_id)))
    else:
        print("\n".join(debugger.timeline(args.trace_id)))


if __name__ == "__main__":
    main()
