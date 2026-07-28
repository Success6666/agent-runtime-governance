from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import rfc8785

import agent_runtime_governance.reconciliation as reconciliation
from agent_runtime_governance._canonical import (
    CanonicalJsonError,
    legacy_audit_json_bytes,
    legacy_audit_json_text,
    legacy_contract_json_bytes,
    legacy_storage_json_text,
    rfc8785_json_bytes,
    rfc8785_json_text,
)
from agent_runtime_governance.action_contracts import _canonical_bytes
from agent_runtime_governance.approval_store import SQLiteApprovalStore
from agent_runtime_governance.audit import (
    JSONLAuditSink,
    SQLiteAuditSink,
    _canonical_json,
    _event_hash,
    sign_event,
)
from agent_runtime_governance.context import ExecutionContext, ToolCall
from agent_runtime_governance.contracts import canonical_json_bytes
from agent_runtime_governance.decisions import ApprovalRequest
from agent_runtime_governance.reconciliation import ReconciliationValidationError, _dump
from agent_runtime_governance.snapshots import (
    ContextSnapshot,
    JSONLSnapshotStore,
    SQLiteSnapshotStore,
    _snapshot_hash,
    _snapshot_signature,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "v0.7" / "canonical-codec.json"
_PERSISTENCE_FIXTURE = (
    Path(__file__).parent / "fixtures" / "v0.7" / "persistence-codec.json"
)
_SIGNING_KEY = b"fixture-signing-key"
_APPROVAL_KEY = b"approval-fixture-signing-key-32byte"
_AUDIT_KEY = b"audit-fixture-signing-key-32bytes!!"
_SNAPSHOT_KEY = b"snapshot-fixture-signing-key-32byte"


def _fixture() -> dict[str, object]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _persistence_fixture() -> dict[str, str]:
    raw = json.loads(_PERSISTENCE_FIXTURE.read_text(encoding="utf-8"))
    assert raw.pop("source_version") == "0.7.0"
    return raw


def _fixture_request() -> ApprovalRequest:
    return ApprovalRequest(
        trace_id="trace-euro",
        request_id="approval-fixture-1",
        tool_name="fixture_tool",
        arguments={
            "args": [1.0, -0.0, "\u20ac"],
            "kwargs": {"label": "\u00e9"},
        },
        risk_tier="HIGH",
        reason="fixture approval \u00e9",
        policy_version="policy-v1",
        policy_digest="a" * 64,
        issued_at="2026-07-01T00:00:00+00:00",
        expires_at="2030-07-01T00:00:00+00:00",
        subject="fixture-user",
        tenant="fixture-tenant",
        identity_issuer="fixture-issuer",
    )


def _fixture_event() -> dict[str, object]:
    return {
        "event_type": "fixture-event",
        "amount": 1.0,
        "negative_zero": -0.0,
        "currency": "\u20ac",
        "nested": {"label": "\u00e9"},
    }


def _fixture_snapshot() -> ContextSnapshot:
    context = ExecutionContext(
        trace_id="snapshot-context-trace",
        span_id="snapshot-span",
        request_id="snapshot-request",
        tool_call=ToolCall(
            "fixture_tool",
            (1.0, -0.0, "\u20ac"),
            {"label": "\u00e9"},
        ),
        metadata={"currency": "\u20ac", "amount": 1.0, "negative_zero": -0.0},
    )
    return ContextSnapshot(
        trace_id="snapshot-trace-\u00e9",
        sequence=0,
        stage="fixture",
        context=context,
        created_at="2026-07-01T00:00:00+00:00",
        policy_version="policy-v1",
        policy_digest="b" * 64,
    )


def test_codec_profiles_match_v07_golden_bytes() -> None:
    fixture = _fixture()
    payload = fixture["payload"]

    assert legacy_audit_json_text(payload) == fixture["legacy_audit_json"]
    assert legacy_audit_json_bytes(payload) == fixture["legacy_audit_json"].encode(
        "utf-8"
    )
    assert legacy_storage_json_text(payload) == fixture["legacy_audit_json"]
    assert legacy_contract_json_bytes(payload) == fixture["legacy_contract_json"].encode(
        "utf-8"
    )
    assert rfc8785_json_bytes(payload) == fixture["rfc8785_json"].encode("utf-8")
    assert rfc8785_json_text(payload) == fixture["rfc8785_json"]


def test_existing_contract_and_rfc8785_callers_match_golden_bytes() -> None:
    fixture = _fixture()
    payload = fixture["payload"]

    assert canonical_json_bytes(payload, label="fixture") == fixture[
        "legacy_contract_json"
    ].encode("utf-8")
    assert _canonical_bytes(payload, label="fixture") == fixture["rfc8785_json"].encode(
        "utf-8"
    )
    assert _dump(payload) == fixture["rfc8785_json"]


def test_audit_and_snapshot_integrity_bytes_match_v07_golden_fixture() -> None:
    fixture = _fixture()
    payload = fixture["payload"]
    event = {"schema_version": 1, "trace_id": "trace-1", "payload": payload}

    assert _canonical_json(payload) == fixture["legacy_audit_json"]
    assert _event_hash(event) == fixture["audit_event_hash"]
    assert sign_event(event, _SIGNING_KEY) == fixture["audit_signature"]
    assert _snapshot_hash(event) == fixture["snapshot_hash"]
    assert _snapshot_signature(event, _SIGNING_KEY) == fixture["snapshot_signature"]


def test_codec_profiles_preserve_nonfinite_compatibility_boundaries() -> None:
    payload = {"value": float("nan")}

    with pytest.raises(ValueError):
        legacy_audit_json_text(payload)
    assert legacy_storage_json_text(payload) == '{"value":NaN}'
    with pytest.raises(CanonicalJsonError):
        rfc8785_json_bytes(payload)


def test_reconciliation_retains_its_canonicalization_error_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_: object) -> bytes:
        raise rfc8785.CanonicalizationError("fixture canonicalization failure")

    monkeypatch.setattr(reconciliation.rfc8785, "dumps", fail)

    with pytest.raises(
        ReconciliationValidationError,
        match="fixture canonicalization failure",
    ):
        reconciliation._dump({"value": 1})


def test_v07_approval_sqlite_payload_and_integrity_tag_remain_compatible(
    tmp_path: Path,
) -> None:
    fixture = _persistence_fixture()
    request = _fixture_request()
    path = tmp_path / "approval.db"
    store = SQLiteApprovalStore(path, sign_key=_APPROVAL_KEY, store_arguments=True)

    store.pending(request)
    with sqlite3.connect(path) as connection:
        request_json, integrity_tag = connection.execute(
            "SELECT request_json, integrity_tag FROM approvals WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()

    assert request_json.encode("utf-8") == fixture["approval_request_json"].encode(
        "utf-8"
    )
    assert integrity_tag == fixture["approval_integrity_tag"]
    assert store.get(request.request_id).request.to_dict() == request.to_dict()  # type: ignore[union-attr]

    legacy_path = tmp_path / "legacy-approval.db"
    legacy_store = SQLiteApprovalStore(
        legacy_path,
        sign_key=_APPROVAL_KEY,
        store_arguments=True,
    )
    with sqlite3.connect(legacy_path) as connection:
        connection.execute(
            """
            INSERT INTO approvals(
                request_id, request_json, decision_json, status, consumed_at,
                integrity_tag, reservation_token, reserved_until
            ) VALUES (?, ?, NULL, 'pending', NULL, ?, NULL, NULL)
            """,
            (
                request.request_id,
                fixture["approval_request_json"],
                fixture["approval_integrity_tag"],
            ),
        )
        connection.commit()

    restored = legacy_store.get(request.request_id)
    assert restored is not None
    assert restored.request.to_dict() == request.to_dict()


def test_v07_audit_jsonl_and_sqlite_payloads_remain_compatible(
    tmp_path: Path,
) -> None:
    fixture = _persistence_fixture()
    event = _fixture_event()
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path, sign_key=_AUDIT_KEY)

    sink.write(event)

    assert path.read_bytes() == (fixture["audit_jsonl"] + "\n").encode("utf-8")
    state_path = Path(str(path) + ".state")
    assert state_path.read_bytes() == (fixture["audit_state"] + "\n").encode("utf-8")
    assert sink.read_verified()[0]["event_hash"] == json.loads(
        fixture["audit_jsonl"]
    )["event_hash"]

    sqlite_path = tmp_path / "audit.db"
    sqlite_sink = SQLiteAuditSink(sqlite_path, sign_key=_AUDIT_KEY)
    sqlite_sink.write(event)
    with sqlite3.connect(sqlite_path) as connection:
        event_json = connection.execute(
            "SELECT event_json FROM audit_events WHERE sequence = 0"
        ).fetchone()[0]
    assert event_json.encode("utf-8") == fixture["audit_sqlite_event_json"].encode(
        "utf-8"
    )
    assert sqlite_sink.read_verified()[0]["event_hash"] == json.loads(
        fixture["audit_jsonl"]
    )["event_hash"]

    legacy_path = tmp_path / "legacy-audit.jsonl"
    legacy_path.write_bytes((fixture["audit_jsonl"] + "\n").encode("utf-8"))
    Path(str(legacy_path) + ".state").write_bytes(
        (fixture["audit_state"] + "\n").encode("utf-8")
    )
    legacy_sink = JSONLAuditSink(legacy_path, sign_key=_AUDIT_KEY)
    assert legacy_sink.read_verified()[0]["event_hash"] == json.loads(
        fixture["audit_jsonl"]
    )["event_hash"]


def test_v07_snapshot_jsonl_and_sqlite_payloads_remain_compatible(
    tmp_path: Path,
) -> None:
    fixture = _persistence_fixture()
    snapshot = _fixture_snapshot()
    path = tmp_path / "snapshot.jsonl"
    store = JSONLSnapshotStore(
        path,
        sign_key=_SNAPSHOT_KEY,
        redact_sensitive=False,
    )

    store.write(snapshot)

    assert path.read_bytes() == (fixture["snapshot_jsonl"] + "\n").encode("utf-8")
    state_path = Path(str(path) + ".state")
    assert state_path.read_bytes() == (fixture["snapshot_state"] + "\n").encode(
        "utf-8"
    )
    assert store.read_trace(snapshot.trace_id) == (snapshot,)

    sqlite_path = tmp_path / "snapshot.db"
    sqlite_store = SQLiteSnapshotStore(
        sqlite_path,
        sign_key=_SNAPSHOT_KEY,
        redact_sensitive=False,
    )
    sqlite_store.write(snapshot)
    with sqlite3.connect(sqlite_path) as connection:
        snapshot_json = connection.execute(
            "SELECT snapshot_json FROM snapshots WHERE trace_id = ? AND sequence = 0",
            (snapshot.trace_id,),
        ).fetchone()[0]
    assert snapshot_json.encode("utf-8") == fixture["snapshot_sqlite_json"].encode(
        "utf-8"
    )
    assert sqlite_store.read_trace(snapshot.trace_id) == (snapshot,)

    legacy_path = tmp_path / "legacy-snapshot.jsonl"
    legacy_path.write_bytes((fixture["snapshot_jsonl"] + "\n").encode("utf-8"))
    Path(str(legacy_path) + ".state").write_bytes(
        (fixture["snapshot_state"] + "\n").encode("utf-8")
    )
    legacy_store = JSONLSnapshotStore(
        legacy_path,
        sign_key=_SNAPSHOT_KEY,
        redact_sensitive=False,
    )
    assert legacy_store.read_trace(snapshot.trace_id) == (snapshot,)
