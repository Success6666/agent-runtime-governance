from __future__ import annotations

import inspect
import json
import sqlite3
from pathlib import Path

import pytest

import agent_runtime_governance._redaction as private_redaction
import agent_runtime_governance.audit as audit_module
import agent_runtime_governance.snapshots as snapshots_module
from agent_runtime_governance.audit import (
    DEFAULT_SENSITIVE_PATHS,
    JSONLAuditSink,
    SQLiteAuditSink,
    redact_sensitive_data,
)
from agent_runtime_governance.context import ExecutionContext, ToolCall
from agent_runtime_governance.errors import AuditIntegrityError
from agent_runtime_governance.snapshots import (
    ContextSnapshot,
    JSONLSnapshotStore,
    SQLiteSnapshotStore,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "v0.7" / "redaction-boundary.json"
_AUDIT_KEY = b"audit-redaction-fixture-signing-key!"
_SNAPSHOT_KEY = b"snapshot-redaction-fixture-sign-key"


def _fixture() -> dict[str, str]:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert raw.pop("source_version") == "0.7.0"
    assert raw.pop("source_commit") == "3998c975f88737c9e009b9d85c073122431ddb94"
    return raw


def _audit_event() -> dict[str, object]:
    return {
        "event_type": "redaction-fixture",
        "password": "top-secret",
        "visible": {
            "private": "path-secret",
            "password": "allowed-password",
            "note": "ticket SECRET-123",
        },
        "context": {
            "input_text": "prompt-secret",
            "tool_call": {
                "args": ["arg-secret"],
                "kwargs": {"password": "kw-password", "allowed": "shown"},
            },
        },
        "currency": "\u20ac",
        "nonfinite": float("nan"),
    }


def _snapshot() -> ContextSnapshot:
    context = ExecutionContext(
        trace_id="snapshot-redaction-context",
        span_id="snapshot-redaction-span",
        request_id="snapshot-redaction-request",
        input_text="snapshot-prompt-secret",
        tool_call=ToolCall(
            "redaction_fixture",
            ("argument-secret", float("inf")),
            {"password": "snapshot-password", "allowed": "shown"},
        ),
        result={"token": "result-secret"},
        metadata={
            "api_key": "metadata-secret",
            "currency": "\u20ac",
            "nonfinite": float("nan"),
            "note": "ticket SECRET-456",
        },
    )
    return ContextSnapshot(
        trace_id="snapshot-redaction-trace",
        sequence=0,
        stage="fixture",
        context=context,
        created_at="2026-07-01T00:00:00+00:00",
        policy_version="policy-v1",
        policy_digest="c" * 64,
    )


def _audit_sink(path: Path) -> JSONLAuditSink:
    return JSONLAuditSink(
        path,
        sign_key=_AUDIT_KEY,
        sensitive_paths=(*DEFAULT_SENSITIVE_PATHS, "visible.private"),
        value_patterns=("SECRET-[0-9]+",),
        allow_paths=("visible.password", "context.tool_call.kwargs.allowed"),
    )


def _sqlite_audit_sink(path: Path) -> SQLiteAuditSink:
    return SQLiteAuditSink(
        path,
        sign_key=_AUDIT_KEY,
        sensitive_paths=(*DEFAULT_SENSITIVE_PATHS, "visible.private"),
        value_patterns=("SECRET-[0-9]+",),
        allow_paths=("visible.password", "context.tool_call.kwargs.allowed"),
    )


def _snapshot_store(path: Path) -> JSONLSnapshotStore:
    return JSONLSnapshotStore(
        path,
        sign_key=_SNAPSHOT_KEY,
        value_patterns=("SECRET-[0-9]+",),
        allow_paths=("context.tool_call.kwargs.allowed",),
    )


def _sqlite_snapshot_store(path: Path) -> SQLiteSnapshotStore:
    return SQLiteSnapshotStore(
        path,
        sign_key=_SNAPSHOT_KEY,
        value_patterns=("SECRET-[0-9]+",),
        allow_paths=("context.tool_call.kwargs.allowed",),
    )


def test_audit_redaction_public_exports_retain_signature_and_defaults() -> None:
    assert audit_module.DEFAULT_SENSITIVE_KEYS is private_redaction.DEFAULT_SENSITIVE_KEYS
    assert audit_module.DEFAULT_SENSITIVE_PATHS is private_redaction.DEFAULT_SENSITIVE_PATHS
    assert snapshots_module.DEFAULT_SENSITIVE_KEYS is private_redaction.DEFAULT_SENSITIVE_KEYS
    assert snapshots_module.redact_sensitive_data is private_redaction.redact_sensitive_data
    assert audit_module.redact_sensitive_data.__module__ == audit_module.__name__
    assert inspect.signature(audit_module.redact_sensitive_data) == inspect.signature(
        private_redaction.redact_sensitive_data
    )


def test_redaction_boundary_preserves_path_pattern_and_json_safe_behavior() -> None:
    class Unserializable:
        def __repr__(self) -> str:
            raise AssertionError("redaction must not call repr")

    value = {
        "PASSWORD": "secret",
        "records": [
            {"private": "hidden", "note": "ticket SECRET-123"},
        ],
        "allow": {"password": "visible"},
        "numbers": [float("nan"), float("inf")],
        "items": {"z", 2},
        "object": Unserializable(),
        5: "numeric-key",
    }

    redacted = redact_sensitive_data(
        value,
        sensitive_paths=(*DEFAULT_SENSITIVE_PATHS, "records.*.private"),
        value_patterns=("SECRET-[0-9]+",),
        allow_paths=("allow.password",),
    )

    assert redacted == {
        "PASSWORD": "[REDACTED]",
        "records": [{"private": "[REDACTED]", "note": "ticket [REDACTED]"}],
        "allow": {"password": "visible"},
        "numbers": [
            "[NONFINITE_FLOAT:NAN]",
            "[NONFINITE_FLOAT:POSITIVE_INFINITY]",
        ],
        "items": [2, "z"],
        "object": "[UNSERIALIZABLE:Unserializable]",
        "5": "numeric-key",
    }


def test_v07_redacted_audit_jsonl_and_sqlite_records_remain_byte_compatible(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    event = _audit_event()
    path = tmp_path / "audit.jsonl"
    _audit_sink(path).write(event)

    assert path.read_bytes() == (fixture["audit_jsonl"] + "\n").encode("utf-8")
    assert Path(str(path) + ".state").read_bytes() == (
        fixture["audit_state"] + "\n"
    ).encode("utf-8")

    sqlite_path = tmp_path / "audit.db"
    _sqlite_audit_sink(sqlite_path).write(event)
    with sqlite3.connect(sqlite_path) as connection:
        event_json = connection.execute(
            "SELECT event_json FROM audit_events WHERE sequence = 0"
        ).fetchone()[0]
    assert event_json.encode("utf-8") == fixture["audit_sqlite_event_json"].encode(
        "utf-8"
    )


def test_v07_redacted_snapshot_jsonl_and_sqlite_records_remain_byte_compatible(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    snapshot = _snapshot()
    path = tmp_path / "snapshot.jsonl"
    _snapshot_store(path).write(snapshot)

    assert path.read_bytes() == (fixture["snapshot_jsonl"] + "\n").encode("utf-8")
    assert Path(str(path) + ".state").read_bytes() == (
        fixture["snapshot_state"] + "\n"
    ).encode("utf-8")

    sqlite_path = tmp_path / "snapshot.db"
    _sqlite_snapshot_store(sqlite_path).write(snapshot)
    with sqlite3.connect(sqlite_path) as connection:
        snapshot_json = connection.execute(
            "SELECT snapshot_json FROM snapshots WHERE trace_id = ? AND sequence = 0",
            (snapshot.trace_id,),
        ).fetchone()[0]
    assert snapshot_json.encode("utf-8") == fixture["snapshot_sqlite_json"].encode(
        "utf-8"
    )


def test_idempotent_audit_retry_uses_the_redacted_source_payload(tmp_path: Path) -> None:
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    source_event_id = "redaction-boundary-1"

    sink.write_idempotent(
        source_event_id,
        {"event_type": "fixture", "password": "first-secret", "public": "same"},
    )
    sink.write_idempotent(
        source_event_id,
        {"event_type": "fixture", "password": "second-secret", "public": "same"},
    )
    assert len(sink.read_verified()) == 1

    with pytest.raises(AuditIntegrityError, match="different content"):
        sink.write_idempotent(
            source_event_id,
            {"event_type": "fixture", "password": "third-secret", "public": "changed"},
        )
