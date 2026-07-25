from __future__ import annotations

import argparse

from agent_runtime_governance import ReplayTrace


def main() -> None:
    parser = argparse.ArgumentParser(description="Print context snapshots for one trace")
    parser.add_argument("audit_file")
    parser.add_argument("trace_id")
    args = parser.parse_args()
    ReplayTrace.from_jsonl(args.audit_file, args.trace_id).print()


if __name__ == "__main__":
    main()

