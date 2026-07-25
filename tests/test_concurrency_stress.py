from __future__ import annotations

import asyncio
import multiprocessing
import time
from pathlib import Path

import pytest

from agent_runtime_governance.approval_store import SQLiteApprovalStore
from agent_runtime_governance.audit import JSONLAuditSink, SQLiteAuditSink
from agent_runtime_governance.context import ExecutionContext, ExecutionMode, ToolCall
from agent_runtime_governance.decisions import (
    ApprovalRequest,
    DecisionOutcome,
    DecisionRecord,
)
from agent_runtime_governance.identity import SQLiteIdentityReplayStore
from agent_runtime_governance.registry import SQLiteIdempotencyStore
from agent_runtime_governance.runtime import InvocationOptions, Runtime
from agent_runtime_governance.snapshots import JSONLSnapshotStore, SQLiteSnapshotStore


def _audit_writer(path: str, worker: int, count: int) -> None:
    sink = JSONLAuditSink(path, sign_key="multiprocess-test")
    for index in range(count):
        sink.write({"worker": worker, "index": index})


def _sqlite_audit_writer(path: str, worker: int, count: int) -> None:
    sink = SQLiteAuditSink(path, sign_key="multiprocess-test")
    for index in range(count):
        sink.write({"worker": worker, "index": index})


def _snapshot_writer(
    store_type: str,
    path: str,
    context_data: dict,
    worker: int,
    count: int,
) -> None:
    store_class = (
        JSONLSnapshotStore if store_type == "jsonl" else SQLiteSnapshotStore
    )
    store = store_class(path, sign_key="multiprocess-snapshot-test")
    execution_context = ExecutionContext.from_dict(context_data)
    for index in range(count):
        store.write_context(
            trace_id=execution_context.trace_id,
            stage=f"worker-{worker}-{index}",
            context=execution_context,
            created_at=f"2026-01-01T00:00:{index:02d}+00:00",
            policy_version="v1",
            policy_digest="digest",
        )


def _idempotency_contender(path: str, start, results) -> None:
    store = SQLiteIdempotencyStore(path, lease_seconds=30)
    start.wait()
    claim = store.acquire("tenant/tool", "operation", "a" * 64)
    if claim.owner:
        results.put("owner")
        return
    try:
        claim.future.result()
    except Exception as exc:
        results.put(type(exc).__name__)
    else:
        results.put("replayed")


def _approval_contender(path: str, request_data: dict, outcome: str, start, results) -> None:
    store = SQLiteApprovalStore(path, sign_key="multiprocess-approval-key")
    request = ApprovalRequest.from_dict(request_data)
    start.wait()
    try:
        store.decide(
            request.request_id,
            DecisionRecord(
                DecisionOutcome(outcome),
                outcome,
                "human",
                approver=f"operator-{outcome}",
            ),
        )
    except Exception as exc:
        results.put(type(exc).__name__)
    else:
        results.put("decided")


def _identity_replay_contender(path: str, start, results) -> None:
    from datetime import datetime, timedelta, timezone

    store = SQLiteIdentityReplayStore(path)
    start.wait()
    claimed = store.claim(
        "gateway",
        "shared-jti-0000000000000001",
        datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    results.put(claimed)


def _sleep_worker(seconds: float) -> None:
    time.sleep(seconds)


def _join_all(workers, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    for process in workers:
        process.join(timeout=max(0.0, deadline - time.monotonic()))
    still_alive = [process for process in workers if process.is_alive()]
    for process in still_alive:
        process.terminate()
    for process in still_alive:
        process.join(timeout=5)
    assert not [process.pid for process in workers if process.is_alive()], (
        "worker processes remained alive after termination"
    )
    failures = {
        process.pid: process.exitcode
        for process in workers
        if process.exitcode != 0
    }
    assert not failures, f"worker processes failed with exit codes: {failures}"


def test_join_all_terminates_timed_out_workers() -> None:
    context = multiprocessing.get_context("spawn")
    worker = context.Process(target=_sleep_worker, args=(60,))
    worker.start()
    with pytest.raises(AssertionError, match="exit codes"):
        _join_all([worker], timeout=0.05)
    assert not worker.is_alive()


@pytest.mark.asyncio
async def test_500_concurrent_contexts_are_isolated() -> None:
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    async def echo(value: int) -> int:
        await asyncio.sleep(0)
        return value

    results = await asyncio.gather(
        *(runtime.arun("echo", index) for index in range(500))
    )
    assert [result.value for result in results] == list(range(500))
    assert len({result.context.trace_id for result in results}) == 500
    assert len({result.context.request_id for result in results}) == 500
    assert all(result.context.tool_call.args == (index,) for index, result in enumerate(results))


@pytest.mark.asyncio
async def test_100_concurrent_idempotent_requests_execute_once() -> None:
    runtime = Runtime()
    executions = 0

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    async def write(value: int) -> int:
        nonlocal executions
        executions += 1
        await asyncio.sleep(0.02)
        return value

    options = InvocationOptions(idempotency_key="concurrent-operation")
    values = await asyncio.gather(
        *(write.ainvoke(7, _governance=options) for _ in range(100))
    )
    assert values == [7] * 100
    assert executions == 1


def test_jsonl_audit_chain_is_consistent_across_processes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(target=_audit_writer, args=(str(path), worker, 25))
        for worker in range(4)
    ]
    for process in workers:
        process.start()
    _join_all(workers)

    events = JSONLAuditSink(path, sign_key="multiprocess-test").read_verified()
    assert len(events) == 100
    assert [event["sequence"] for event in events] == list(range(100))
    assert {(event["worker"], event["index"]) for event in events} == {
        (worker, index) for worker in range(4) for index in range(25)
    }


def test_sqlite_audit_chain_is_consistent_across_processes(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(target=_sqlite_audit_writer, args=(str(path), worker, 25))
        for worker in range(4)
    ]
    for process in workers:
        process.start()
    _join_all(workers)

    events = SQLiteAuditSink(path, sign_key="multiprocess-test").read_verified()
    assert len(events) == 100
    assert [event["sequence"] for event in events] == list(range(100))


@pytest.mark.parametrize("store_type,suffix", [("jsonl", "jsonl"), ("sqlite", "db")])
def test_snapshot_sequence_is_atomic_across_processes(
    tmp_path: Path, store_type: str, suffix: str
) -> None:
    path = str(tmp_path / f"snapshots.{suffix}")
    execution_context = ExecutionContext.create(ToolCall("observe"))
    process_context = multiprocessing.get_context("spawn")
    workers = [
        process_context.Process(
            target=_snapshot_writer,
            args=(
                store_type,
                path,
                execution_context.to_dict(),
                worker,
                25,
            ),
        )
        for worker in range(4)
    ]
    for process in workers:
        process.start()
    _join_all(workers)

    store_class = (
        JSONLSnapshotStore if store_type == "jsonl" else SQLiteSnapshotStore
    )
    snapshots = store_class(
        path, sign_key="multiprocess-snapshot-test"
    ).read_trace(execution_context.trace_id)
    assert len(snapshots) == 100
    assert [snapshot.sequence for snapshot in snapshots] == list(range(100))


def test_sqlite_idempotency_has_one_owner_across_processes(tmp_path: Path) -> None:
    path = str(tmp_path / "idempotency.db")
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(target=_idempotency_contender, args=(path, start, results))
        for _ in range(4)
    ]
    for process in workers:
        process.start()
    start.set()
    outcomes = [results.get(timeout=2) for _ in workers]
    _join_all(workers)
    assert outcomes.count("owner") == 1
    assert outcomes.count("IdempotencyInProgressError") == 3


def test_sqlite_approval_accepts_one_decision_across_processes(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "approvals.db")
    request = ApprovalRequest(
        trace_id="trace",
        request_id="request-1",
        tool_name="operate",
        arguments={"args": [], "kwargs": {}},
        risk_tier="HIGH",
        reason="approval required",
    )
    SQLiteApprovalStore(path, sign_key="multiprocess-approval-key").pending(request)
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(
            target=_approval_contender,
            args=(path, request.to_dict(), outcome, start, results),
        )
        for outcome in ("allow", "deny")
    ]
    for process in workers:
        process.start()
    start.set()
    outcomes = [results.get(timeout=2) for _ in workers]
    _join_all(workers)
    assert outcomes.count("decided") == 1
    assert outcomes.count("ValueError") == 1


def test_sqlite_identity_replay_has_one_winner_across_processes(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "replay.db")
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(target=_identity_replay_contender, args=(path, start, results))
        for _ in range(4)
    ]
    for process in workers:
        process.start()
    start.set()
    outcomes = [results.get(timeout=2) for _ in workers]
    _join_all(workers)
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 3
