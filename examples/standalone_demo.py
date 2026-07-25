from pathlib import Path

from agent_runtime_governance import (
    AuditMiddleware,
    InMemoryAuditSink,
    Rule,
    RuleMiddleware,
    Runtime,
)

sink = InMemoryAuditSink()
runtime = Runtime(
    [
        RuleMiddleware([Rule("bulk-delete", r"\bdelete\s+all\b", "bulk deletion denied")]),
        AuditMiddleware(sink),
    ]
)


@runtime.tool()
def read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    print(read_file("README.md")[:80])
    print(f"audit events: {len(sink.events)}")

