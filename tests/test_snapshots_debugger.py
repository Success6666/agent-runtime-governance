from __future__ import annotations

from agent_runtime_governance import (
    InMemorySnapshotStore,
    JSONLSnapshotStore,
    ReplayDebugger,
    Runtime,
    SnapshotMiddleware,
    diff_values,
    trace_to_mermaid,
)


def run_with_snapshots(store):
    runtime = Runtime([SnapshotMiddleware(store)])

    @runtime.tool()
    def add(left: int, right: int) -> int:
        return left + right

    result = __import__("asyncio").run(runtime.arun("add", 2, 3))
    return result


def test_snapshot_middleware_records_governance_and_result() -> None:
    store = InMemorySnapshotStore()
    result = run_with_snapshots(store)
    snapshots = store.read_trace(result.context.trace_id)
    assert [item.stage for item in snapshots] == ["governance", "result"]
    assert snapshots[-1].context.result == 5


def test_jsonl_snapshot_store_round_trip(tmp_path) -> None:
    store = JSONLSnapshotStore(tmp_path / "snapshots.jsonl")
    result = run_with_snapshots(store)
    restored = store.read_trace(result.context.trace_id)
    assert len(restored) == 2
    assert restored[-1].context.to_dict() == result.context.to_dict()


def test_debugger_timeline_is_ordered() -> None:
    store = InMemorySnapshotStore()
    result = run_with_snapshots(store)
    timeline = ReplayDebugger(store).timeline(result.context.trace_id)
    assert timeline[0].startswith("00 governance")
    assert "succeeded" in timeline[1]


def test_debugger_reports_field_level_diff() -> None:
    store = InMemorySnapshotStore()
    result = run_with_snapshots(store)
    changes = ReplayDebugger(store).diff(result.context.trace_id, 0, 1)
    paths = {item.path for item in changes}
    assert "$.status" in paths
    assert "$.result" in paths


def test_debugger_formats_diff() -> None:
    store = InMemorySnapshotStore()
    result = run_with_snapshots(store)
    output = ReplayDebugger(store).format_diff(result.context.trace_id, 0, 1)
    assert "$.status" in output
    assert "->" in output


def test_missing_snapshot_sequence_is_reported() -> None:
    store = InMemorySnapshotStore()
    result = run_with_snapshots(store)
    try:
        ReplayDebugger(store).diff(result.context.trace_id, 0, 99)
    except KeyError as exc:
        assert "99" in str(exc)
    else:
        raise AssertionError("missing sequence should fail")


def test_generic_diff_handles_nested_values() -> None:
    changes = diff_values({"risk": {"score": 0.2}}, {"risk": {"score": 0.8}})
    assert changes[0].path == "$.risk.score"
    assert changes[0].before == 0.2
    assert changes[0].after == 0.8


def test_mermaid_trace_contains_ordered_edges() -> None:
    store = InMemorySnapshotStore()
    result = run_with_snapshots(store)
    output = trace_to_mermaid(store.read_trace(result.context.trace_id))
    assert output.startswith("flowchart LR")
    assert "S0 --> S1" in output


def test_empty_mermaid_trace_is_valid() -> None:
    assert "No snapshots" in trace_to_mermaid([])

