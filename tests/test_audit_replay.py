from __future__ import annotations

import json

import pytest

from agent_runtime_governance import (
    AuditIntegrityError,
    AuditMiddleware,
    InMemoryAuditSink,
    JSONLAuditSink,
    ReplayTrace,
    Rule,
    RuleMiddleware,
    Runtime,
    InvocationOptions,
    GovernanceDenied,
)


def build_runtime(sink):
    runtime = Runtime([AuditMiddleware(sink)])

    @runtime.tool()
    def login(username: str, password: str) -> bool:
        return bool(username and password)

    return runtime


def test_in_memory_sink_records_decision_and_completion() -> None:
    sink = InMemoryAuditSink()
    runtime = build_runtime(sink)
    runtime.invoke("login", "ada", password="secret")
    assert [event["stage"] for event in sink.events] == ["decision", "completed"]


def test_jsonl_sink_redacts_sensitive_arguments(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    runtime = build_runtime(JSONLAuditSink(path))
    runtime.invoke("login", "ada", password="secret")
    text = path.read_text(encoding="utf-8")
    assert "secret" not in text
    assert "[REDACTED]" in text


def test_signed_jsonl_can_be_verified(tmp_path) -> None:
    sink = JSONLAuditSink(tmp_path / "audit.jsonl", sign_key="test-key")
    runtime = build_runtime(sink)
    runtime.invoke("login", "ada", password="secret")
    events = sink.read_verified()
    assert len(events) == 2
    assert all("signature" in event for event in events)


def test_tampered_jsonl_is_rejected(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path, sign_key="test-key")
    runtime = build_runtime(sink)
    runtime.invoke("login", "ada", password="secret")
    path.write_text(path.read_text(encoding="utf-8").replace("login", "logout", 1), encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        sink.read_verified()


def test_replay_filters_trace_id(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path)
    runtime = build_runtime(sink)
    first = runtime.invoke("login", "ada", password="secret")
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    trace_id = events[0]["trace_id"]
    trace = ReplayTrace.from_jsonl(path, trace_id)
    assert first is True
    assert len(trace.snapshots) == 2
    assert all(snapshot.trace_id == trace_id for snapshot in trace.snapshots)


def test_replay_lines_are_human_readable(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path)
    runtime = build_runtime(sink)
    runtime.invoke("login", "ada", password="secret")
    event = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    lines = list(ReplayTrace.from_jsonl(path, event["trace_id"]).lines())
    assert "login" in lines[0]
    assert "succeeded" in lines[-1]


def test_denied_call_writes_one_decision_snapshot() -> None:
    sink = InMemoryAuditSink()
    runtime = Runtime(
        [
            RuleMiddleware([Rule("deny", r"\bdeny\b", "blocked")]),
            AuditMiddleware(sink),
        ]
    )

    @runtime.tool()
    def work() -> None:
        return None

    with pytest.raises(GovernanceDenied):
        runtime.invoke("work", _governance=InvocationOptions(input_text="deny this"))
    assert len(sink.events) == 1
