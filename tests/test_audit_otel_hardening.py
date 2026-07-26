from __future__ import annotations

import asyncio
import json
import sqlite3
import warnings
from contextlib import closing, contextmanager
from urllib.error import HTTPError

import pytest

from agent_runtime_governance import Runtime
from agent_runtime_governance.audit import JSONLAuditSink, SQLiteAuditSink
from agent_runtime_governance.context import (
    ExecutionContext,
    ExecutionMode,
    ExecutionStatus,
    HistoryEntry,
    RiskTier,
    ToolCall,
)
from agent_runtime_governance.decisions import DecisionOutcome, DecisionRecord
from agent_runtime_governance.errors import AuditIntegrityError
from agent_runtime_governance.middleware.audit import AuditMiddleware
from agent_runtime_governance.plugins.opa import OPAClient
from agent_runtime_governance.plugins.slack import SlackWebhookNotifier
from agent_runtime_governance.snapshots import (
    InMemorySnapshotStore,
    JSONLSnapshotStore,
    SnapshotMiddleware,
    SQLiteSnapshotStore,
)
from agent_runtime_governance.telemetry import OpenTelemetryMiddleware, _set_status


class RetryAuditSink:
    def __init__(self) -> None:
        self.calls = 0

    def write(self, event) -> None:
        self.calls += 1
        if self.calls == 1:
            raise OSError("temporary audit outage")


def make_context(**changes) -> ExecutionContext:
    context = ExecutionContext.create(
        ToolCall("danger", args=("secret-positional",), kwargs={"password": "secret"}),
        input_text="delete user token-123",
        user="alice",
        permissions=frozenset({"admin"}),
        risk_tier=RiskTier.CRITICAL,
    )
    if changes:
        context = context.evolve(**changes)
    return context


@pytest.mark.asyncio
async def test_noncritical_audit_failure_is_retried_and_denial_is_terminal() -> None:
    sink = RetryAuditSink()
    middleware = AuditMiddleware(sink)
    denied = make_context(
        status=ExecutionStatus.DENIED,
        decision=DecisionRecord(DecisionOutcome.DENY, "blocked", "policy"),
        risk_tier=RiskTier.LOW,
    )

    failed = await middleware.process(denied)
    assert failed.history[-1].outcome == "error"
    recorded = await middleware.process(failed)
    assert sink.calls == 2
    assert recorded.history[-1].outcome == "record"


def test_audit_critical_configuration_has_explicit_precedence() -> None:
    critical = AuditMiddleware(
        RetryAuditSink(),
        critical=True,
        fail_closed=False,
    )
    assert critical.critical is True
    assert critical.fail_closed is False
    assert critical.is_critical(make_context(risk_tier=RiskTier.LOW)) is True

    fail_closed = AuditMiddleware(
        RetryAuditSink(),
        fail_closed=True,
        critical_tiers=frozenset(),
    )
    assert fail_closed.critical is False
    assert fail_closed.is_critical(make_context(risk_tier=RiskTier.LOW)) is True


def test_jsonl_audit_wraps_invalid_state_json(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path, sign_key="k")
    sink.write({"event": 1})
    (tmp_path / "audit.jsonl.state").write_text("{", encoding="utf-8")

    with pytest.raises(AuditIntegrityError, match="invalid audit state file"):
        sink.read_verified()
    with pytest.raises(AuditIntegrityError, match="invalid audit state file"):
        sink.write({"event": 2})


@pytest.mark.parametrize(
    "raw",
    [
        "{",
        "[]",
        '{"sequence": 0}',
        '{"sequence": "0", "prev_hash": "x"}',
    ],
)
def test_jsonl_audit_rejects_malformed_segment_anchor(tmp_path, raw: str) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(raw + "\n", encoding="utf-8")
    sink = JSONLAuditSink(path, max_bytes=1, backup_count=1)

    with pytest.raises(
        AuditIntegrityError, match="audit JSON|must be an object|anchor"
    ):
        sink._first_raw_event()


def test_audit_and_snapshot_hashes_reject_nonfinite_numbers(tmp_path) -> None:
    audit = JSONLAuditSink(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError, match="Out of range float"):
        audit.write({"risk_score": float("nan")})

    context = ExecutionContext.create(
        ToolCall("measure"), metadata={"risk_score": float("inf")}
    )
    snapshots = JSONLSnapshotStore(
        tmp_path / "snapshots.jsonl", redact_sensitive=False
    )
    with pytest.raises(ValueError, match="Out of range float"):
        snapshots.write_context(
            trace_id=context.trace_id,
            stage="governance",
            context=context,
            created_at="2026-01-01T00:00:00+00:00",
            policy_version=None,
            policy_digest=None,
        )


def test_sqlite_audit_missing_state_row_fails_closed(tmp_path) -> None:
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path, sign_key="k")
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute("DELETE FROM audit_state")

    with pytest.raises(AuditIntegrityError, match="state row is missing"):
        sink.write({"event": 1})


def test_jsonl_audit_hash_chain_detects_deletion_and_tamper(tmp_path) -> None:
    sink = JSONLAuditSink(tmp_path / "audit.jsonl", sign_key="k")
    sink.write({"trace_id": "t", "stage": "decision", "context": {"tool_call": {"args": ["x"]}}})
    sink.write({"trace_id": "t", "stage": "completed", "context": {"tool_call": {"args": ["x"]}}})
    assert [event["sequence"] for event in sink.read_verified()] == [0, 1]

    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:1]) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        sink.read_verified()

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.write_text(path.read_text(encoding="utf-8").replace("decision", "approve", 1), encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        sink.read_verified()


def test_jsonl_audit_rotation_preserves_verifiable_chain(tmp_path) -> None:
    sink = JSONLAuditSink(
        tmp_path / "audit.jsonl",
        sign_key="k",
        max_bytes=450,
        backup_count=4,
    )
    for index in range(8):
        sink.write({"trace_id": "t", "stage": f"s{index}", "context": {"tool_call": {"args": []}}})
    events = sink.read_verified()
    assert events
    assert events == sorted(events, key=lambda event: event["sequence"])
    assert any((tmp_path / f"audit.jsonl.{index}").exists() for index in range(1, 5))


def test_jsonl_audit_recovers_a_fsynced_tail_after_state_lag(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    state_path = tmp_path / "audit.jsonl.state"
    sink = JSONLAuditSink(path, sign_key="k")
    sink.write({"event": 1})
    old_state = state_path.read_bytes()
    sink.write({"event": 2})

    state_path.write_bytes(old_state)

    assert [event["event"] for event in sink.read_verified()] == [1, 2]
    recovered = json.loads(state_path.read_text(encoding="utf-8"))
    assert recovered["last_sequence"] == 1


def test_jsonl_audit_does_not_recover_a_non_extending_state(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    state_path = tmp_path / "audit.jsonl.state"
    sink = JSONLAuditSink(path, sign_key="k")
    sink.write({"event": 1})
    sink.write({"event": 2})
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["last_sequence"] = 0
    state["last_hash"] = "f" * 64
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(AuditIntegrityError, match="state signature|does not extend"):
        sink.read_verified()


def test_jsonl_audit_redaction_blocks_repr_and_defaults(tmp_path) -> None:
    class SecretObject:
        def __repr__(self) -> str:
            return "repr-secret"

    sink = JSONLAuditSink(
        tmp_path / "audit.jsonl",
        value_patterns=[r"token-[0-9]+"],
    )
    context = make_context(result=SecretObject(), error="token-123 failed")
    from agent_runtime_governance.audit import context_event

    sink.write(context_event(context, stage="completed"))
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "secret-positional" not in text
    assert "delete user" not in text
    assert "repr-secret" not in text
    assert "token-123" not in text
    assert "[REDACTED]" in text


def test_audit_redacts_decision_history_and_identity_claims_by_default(
    tmp_path,
) -> None:
    secret = "production-secret-value"
    context = make_context(
        metadata={"identity_claims": {"signature": secret}},
    )
    context = context.with_decision(
        DecisionRecord(DecisionOutcome.ALLOW, secret, "test", approver="operator")
    ).append_history(HistoryEntry("test", "allow", secret))
    from agent_runtime_governance.audit import context_event

    sink = JSONLAuditSink(tmp_path / "audit.jsonl", sign_key="k")
    sink.write(context_event(context, stage="decision"))
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

    assert secret not in text
    event = sink.read_verified()[0]
    assert event["reason"] == "[REDACTED]"
    assert event["context"]["decision"]["reason"] == "[REDACTED]"
    assert event["context"]["history"][-1]["reason"] == "[REDACTED]"


def test_jsonl_audit_allowlist_can_preserve_explicit_path(tmp_path) -> None:
    sink = JSONLAuditSink(
        tmp_path / "audit.jsonl",
        allow_paths={"context.input_text"},
    )
    from agent_runtime_governance.audit import context_event

    sink.write(context_event(make_context(), stage="decision"))
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "delete user token-123" in text
    assert "secret-positional" not in text


def test_sqlite_audit_sink_is_transactional_and_verifiable(tmp_path) -> None:
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path, sign_key="k")
    sink.write({"trace_id": "t", "stage": "decision", "context": {"tool_call": {"args": []}}})
    sink.write({"trace_id": "t", "stage": "completed", "context": {"tool_call": {"args": []}}})
    assert [event["sequence"] for event in sink.read_verified()] == [0, 1]

    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(
                "UPDATE audit_events SET event_json = replace(event_json, "
                "'completed', 'tampered') WHERE sequence = 1"
            )
    with pytest.raises(AuditIntegrityError):
        sink.read_verified()


def test_jsonl_snapshot_store_allocates_sequence_across_instances(tmp_path) -> None:
    path = tmp_path / "snapshots.jsonl"
    first = JSONLSnapshotStore(path)
    second = JSONLSnapshotStore(path)
    context = make_context()
    first.write_context(
        trace_id=context.trace_id,
        stage="governance",
        context=context,
        created_at="2026-01-01T00:00:00+00:00",
        policy_version=None,
        policy_digest=None,
    )
    second.write_context(
        trace_id=context.trace_id,
        stage="result",
        context=context.evolve(status=ExecutionStatus.SUCCEEDED, result=True),
        created_at="2026-01-01T00:00:01+00:00",
        policy_version=None,
        policy_digest=None,
    )
    assert [snapshot.sequence for snapshot in first.read_trace(context.trace_id)] == [0, 1]


def test_sqlite_snapshot_store_round_trips_with_atomic_sequence(tmp_path) -> None:
    store = SQLiteSnapshotStore(tmp_path / "snapshots.db")
    context = make_context()
    store.write_context(
        trace_id=context.trace_id,
        stage="governance",
        context=context,
        created_at="2026-01-01T00:00:00+00:00",
        policy_version="v1",
        policy_digest="digest",
    )
    store.write_context(
        trace_id=context.trace_id,
        stage="result",
        context=context.evolve(status=ExecutionStatus.SUCCEEDED, result=True),
        created_at="2026-01-01T00:00:01+00:00",
        policy_version="v1",
        policy_digest="digest",
    )
    restored = store.read_trace(context.trace_id)
    assert [snapshot.sequence for snapshot in restored] == [0, 1]
    assert restored[0].policy_version == "v1"


def test_jsonl_snapshot_redacts_secrets_and_detects_tampering(tmp_path) -> None:
    path = tmp_path / "snapshots.jsonl"
    secret = "snapshot-secret-value"
    store = JSONLSnapshotStore(path, sign_key="snapshot-signing-key")
    context = ExecutionContext.create(
        ToolCall("danger", args=(secret,), kwargs={"payload": secret}),
        input_text=secret,
    )
    store.write_context(
        trace_id=context.trace_id,
        stage="governance",
        context=context,
        created_at="2026-01-01T00:00:00+00:00",
        policy_version=None,
        policy_digest=None,
    )

    text = path.read_text(encoding="utf-8")
    assert secret not in text
    assert store.read_trace(context.trace_id)[0].context.input_text == "[REDACTED]"

    path.write_text(text.replace('"pending"', '"failed"', 1), encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="snapshot"):
        store.read_trace(context.trace_id)


def test_sqlite_snapshot_redacts_secrets_on_disk(tmp_path) -> None:
    path = tmp_path / "snapshots.db"
    secret = "sqlite-snapshot-secret"
    store = SQLiteSnapshotStore(path, sign_key="snapshot-signing-key")
    context = ExecutionContext.create(
        ToolCall("danger", kwargs={"payload": secret}),
        input_text=secret,
    )
    store.write_context(
        trace_id=context.trace_id,
        stage="governance",
        context=context,
        created_at="2026-01-01T00:00:00+00:00",
        policy_version=None,
        policy_digest=None,
    )

    assert secret.encode() not in path.read_bytes()
    assert store.read_trace(context.trace_id)[0].context.input_text == "[REDACTED]"


@pytest.mark.asyncio
async def test_snapshot_records_unknown_as_a_terminal_result() -> None:
    store = InMemorySnapshotStore()
    middleware = SnapshotMiddleware(store)
    context = ExecutionContext.create(ToolCall("danger"))
    context = await middleware.process(context)
    context = context.evolve(
        status=ExecutionStatus.UNKNOWN,
        error="side effect outcome unknown",
    )

    context = await middleware.process(context)

    snapshots = store.read_trace(context.trace_id)
    assert [snapshot.stage for snapshot in snapshots] == ["governance", "result"]
    assert snapshots[-1].context.status is ExecutionStatus.UNKNOWN
    for snapshot in snapshots:
        entries = [
            entry
            for entry in snapshot.context.history
            if entry.middleware == "snapshot"
            and entry.data.get("stage") == snapshot.stage
        ]
        assert len(entries) == 1
        assert entries[0].outcome == "record"
        assert entries[0].data["sequence"] == snapshot.sequence


def test_opa_client_limits_payload_and_circuit_breaks() -> None:
    context = make_context()
    with pytest.raises(ValueError):
        OPAClient(
            "http://localhost:8181",
            "agent/allow",
            transport=lambda payload: {"result": True},
            max_request_bytes=8,
        ).evaluate(context)

    client = OPAClient(
        "http://localhost:8181",
        "agent/allow",
        transport=lambda payload: (_ for _ in ()).throw(ConnectionError("down")),
        failure_threshold=1,
        recovery_timeout=60,
    )
    with pytest.raises(ConnectionError):
        client.evaluate(context)
    with pytest.raises(RuntimeError, match="circuit breaker"):
        client.evaluate(context)


def test_external_header_validation_rejects_injection() -> None:
    with pytest.raises(ValueError):
        OPAClient("http://localhost:8181", "agent/allow", headers={"X-Test\n": "1"})
    with pytest.raises(ValueError):
        SlackWebhookNotifier(
            "https://hooks.slack.com/services/T/B/C",
            headers={"X-Test": "one\ntwo"},
        )


def test_slack_notifier_limits_payload_and_circuit_breaks(monkeypatch) -> None:
    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C",
        max_request_bytes=16,
    )
    with pytest.raises(ValueError):
        notifier.send({"text": "x" * 100})

    calls = {"count": 0}

    class FailingOpener:
        def open(self, *args, **kwargs):
            calls["count"] += 1
            raise ConnectionError("down")

    monkeypatch.setattr(
        "agent_runtime_governance.plugins.slack.build_opener",
        lambda *handlers: FailingOpener(),
    )
    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C",
        failure_threshold=1,
        recovery_timeout=60,
    )
    with pytest.raises(ConnectionError):
        notifier.send({"text": "ok"})
    with pytest.raises(RuntimeError, match="circuit breaker"):
        notifier.send({"text": "ok"})
    assert calls["count"] == 1


def test_slack_notifier_installs_redirect_rejecting_opener(monkeypatch) -> None:
    handlers = []

    class RedirectOpener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 302, "redirect", {}, None)

    def capture_opener(*installed):
        handlers.extend(installed)
        return RedirectOpener()

    monkeypatch.setattr(
        "agent_runtime_governance.plugins.slack.build_opener", capture_opener
    )
    notifier = SlackWebhookNotifier(
        "https://hooks.slack.com/services/T/B/C",
        headers={"Authorization": "Bearer secret"},
    )

    with pytest.raises(HTTPError) as caught:
        notifier.send({"text": "ok"})

    assert caught.value.code == 302
    assert any(type(handler).__name__ == "_RejectRedirects" for handler in handlers)


class FakeSpan:
    def __init__(self) -> None:
        self.attributes = {}
        self.statuses = []
        self.exceptions = []
        self.ended = False

    def set_attribute(self, key, value) -> None:
        self.attributes[key] = value

    def set_status(self, status) -> None:
        self.statuses.append(status)

    def record_exception(self, exc) -> None:
        self.exceptions.append(exc)

    def end(self) -> None:
        self.ended = True


def test_opentelemetry_uses_status_types_exposed_by_injected_span() -> None:
    class StatusCode:
        OK = object()
        ERROR = object()

    class Status:
        def __init__(self, code, description=None) -> None:
            self.code = code
            self.description = description

    span = FakeSpan()
    span.Status = Status
    span.StatusCode = StatusCode

    _set_status(span, "ERROR", "failed")

    assert span.statuses[0].code is StatusCode.ERROR
    assert span.statuses[0].description == "failed"


def test_opentelemetry_warns_once_when_injected_status_types_are_missing(
    monkeypatch,
) -> None:
    import agent_runtime_governance.telemetry as telemetry

    monkeypatch.setattr(telemetry, "_STATUS_WARNING_EMITTED", False)
    with pytest.warns(RuntimeWarning, match="terminal status was not exported"):
        _set_status(FakeSpan(), "ERROR", "failed")
    with warnings.catch_warnings(record=True) as repeated:
        _set_status(FakeSpan(), "ERROR", "failed")
    assert not repeated


class FakeSpanManager:
    def __init__(self, span: FakeSpan) -> None:
        self.span = span
        self.exited = False

    def __enter__(self) -> FakeSpan:
        return self.span

    def __exit__(self, exc_type, exc, tb) -> None:
        self.exited = True
        self.span.end()


class FakeCurrentTracer:
    def __init__(self) -> None:
        self.spans: list[FakeSpan] = []
        self.managers: list[FakeSpanManager] = []
        self.parent_contexts = []

    @contextmanager
    def start_as_current_span(self, name, **kwargs):
        span = FakeSpan()
        span.attributes.update(kwargs["attributes"])
        self.spans.append(span)
        self.parent_contexts.append(kwargs.get("context"))
        manager = FakeSpanManager(span)
        self.managers.append(manager)
        try:
            yield manager.__enter__()
        finally:
            manager.__exit__(None, None, None)


def test_opentelemetry_uses_current_span_parent_and_cleans_failed_span() -> None:
    tracer = FakeCurrentTracer()
    parent = object()
    middleware = OpenTelemetryMiddleware(tracer, parent_context=parent)
    runtime = Runtime([middleware])

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def fail() -> None:
        raise RuntimeError("boom")

    with pytest.raises(Exception):
        runtime.invoke("fail")
    assert tracer.parent_contexts == [parent]
    assert tracer.spans[0].ended
    assert tracer.spans[0].exceptions
    assert tracer.spans[0].attributes["arg.status"] == "failed"
    assert middleware.active_span_count == 0


def test_opentelemetry_does_not_export_raw_error_details() -> None:
    tracer = FakeCurrentTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    context = make_context(
        status=ExecutionStatus.FAILED,
        error="database password is production-secret",
    )

    import asyncio

    asyncio.run(middleware.process(context))

    span = tracer.spans[0]
    assert "arg.error" not in span.attributes
    assert all("production-secret" not in str(exc) for exc in span.exceptions)


def test_opentelemetry_abort_finishes_and_forgets_active_span() -> None:
    tracer = FakeCurrentTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    context = make_context()

    import asyncio

    asyncio.run(middleware.process(context))
    assert middleware.active_span_count == 1

    assert middleware.abort(context.trace_id)
    assert middleware.active_span_count == 0
    assert tracer.spans[0].ended
    assert not middleware.abort(context.trace_id)


def test_opentelemetry_exports_a_real_sdk_span_without_secret_details() -> None:
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    middleware = OpenTelemetryMiddleware(provider.get_tracer("test"))
    context = make_context(
        status=ExecutionStatus.FAILED,
        error="production-secret",
    )

    import asyncio

    asyncio.run(middleware.process(context))

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    encoded = repr(spans[0].attributes) + repr(spans[0].events)
    assert "production-secret" not in encoded
    assert spans[0].status.status_code.name == "ERROR"


def test_opentelemetry_context_propagates_into_synchronous_tool_thread() -> None:
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    runtime = Runtime([OpenTelemetryMiddleware(tracer)])

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def read() -> str:
        with tracer.start_as_current_span("inside-tool"):
            return "ok"

    assert read() == "ok"
    spans = {span.name: span for span in exporter.get_finished_spans()}
    assert spans["inside-tool"].parent is not None
    assert spans["inside-tool"].parent.span_id == spans["tool.read"].context.span_id
    runtime.close()


@pytest.mark.asyncio
async def test_runtime_cancellation_closes_opentelemetry_span() -> None:
    tracer = FakeCurrentTracer()
    middleware = OpenTelemetryMiddleware(tracer)
    runtime = Runtime([middleware])
    started = asyncio.Event()

    @runtime.tool()
    async def mutate() -> None:
        started.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(runtime.arun("mutate"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert middleware.active_span_count == 0
    assert tracer.spans[0].ended
