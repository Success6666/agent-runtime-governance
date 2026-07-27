from __future__ import annotations

from queue import Queue
from threading import Event

import pytest

from agent_runtime_governance._daemon_executor import DaemonThreadPoolExecutor


class _InterruptedQueue:
    """Raise once before consuming work to model an embedded-host interruption."""

    def __init__(self) -> None:
        self._queue: Queue[object] = Queue()
        self.read_started = Event()
        self.raise_interruption = Event()
        self.drain_started = Event()
        self.release_drain = Event()
        self.pause_drain = False
        self._raise_once = True

    def put(self, item: object) -> None:
        self._queue.put(item)

    def get(self) -> object:
        if self._raise_once:
            self._raise_once = False
            self.read_started.set()
            assert self.raise_interruption.wait(timeout=1)
            raise RuntimeError("embedded host interrupted queue read")
        return self._queue.get()

    def get_nowait(self) -> object:
        item = self._queue.get_nowait()
        if self.pause_drain:
            self.drain_started.set()
            assert self.release_drain.wait(timeout=1)
        return item

    def empty(self) -> bool:
        return self._queue.empty()


class _PausedGetQueue:
    """Hold a dequeued work item while another worker marks the pool broken."""

    def __init__(self) -> None:
        self._queue: Queue[object] = Queue()
        self.read_started = Event()
        self.release_read = Event()

    def put(self, item: object) -> None:
        self._queue.put(item)

    def get(self) -> object:
        self.read_started.set()
        assert self.release_read.wait(timeout=1)
        return self._queue.get()

    def get_nowait(self) -> object:
        return self._queue.get_nowait()

    def empty(self) -> bool:
        return self._queue.empty()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_workers": 0, "thread_name_prefix": "audit"},
        {"max_workers": 1, "thread_name_prefix": ""},
    ],
)
def test_daemon_executor_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        DaemonThreadPoolExecutor(**kwargs)  # type: ignore[arg-type]


def test_daemon_executor_rejects_submission_after_shutdown() -> None:
    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="audit")
    executor.shutdown(wait=False)

    with pytest.raises(RuntimeError, match="cannot schedule"):
        executor.submit(lambda: None)

    executor.shutdown(wait=True)


def test_daemon_executor_cancels_queued_work_during_nonblocking_shutdown() -> None:
    started = Event()
    release = Event()

    def block_worker() -> None:
        started.set()
        assert release.wait(timeout=1)

    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="audit")
    try:
        running = executor.submit(block_worker)
        assert started.wait(timeout=1)

        cancelled_by_shutdown = executor.submit(
            lambda: (_ for _ in ()).throw(AssertionError("queued work must not run"))
        )
        executor.shutdown(wait=False, cancel_futures=True)
        assert cancelled_by_shutdown.cancelled()

        release.set()
        assert running.result(timeout=1) is None
        executor.shutdown(wait=True)

    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_daemon_executor_skips_caller_cancelled_queued_future() -> None:
    started = Event()
    release = Event()
    executed: list[str] = []

    def block_worker() -> None:
        started.set()
        assert release.wait(timeout=1)

    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="audit")
    try:
        running = executor.submit(block_worker)
        assert started.wait(timeout=1)
        cancelled_by_caller = executor.submit(lambda: executed.append("ran"))
        assert cancelled_by_caller.cancel()

        release.set()
        assert running.result(timeout=1) is None
        executor.shutdown(wait=True)

        assert cancelled_by_caller.cancelled()
        assert executed == []
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_daemon_executor_fails_queued_work_after_queue_read_interruption() -> None:
    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="audit")
    interrupted_queue = _InterruptedQueue()
    executor._work_queue = interrupted_queue  # type: ignore[assignment]
    try:
        first = executor.submit(lambda: "first")
        assert interrupted_queue.read_started.wait(timeout=1)

        interrupted_queue.raise_interruption.set()
        with pytest.raises(RuntimeError, match="worker queue read failed"):
            first.result(timeout=1)
        with pytest.raises(RuntimeError, match="executor is unavailable"):
            executor.submit(lambda: "second")
    finally:
        interrupted_queue.raise_interruption.set()
        interrupted_queue.release_drain.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_daemon_executor_preserves_caller_cancellation_during_failure_drain() -> None:
    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="audit")
    interrupted_queue = _InterruptedQueue()
    interrupted_queue.pause_drain = True
    executor._work_queue = interrupted_queue  # type: ignore[assignment]
    try:
        queued = executor.submit(lambda: "must not run")
        assert interrupted_queue.read_started.wait(timeout=1)

        interrupted_queue.raise_interruption.set()
        assert interrupted_queue.drain_started.wait(timeout=1)
        assert queued.cancel()
        interrupted_queue.release_drain.set()

        assert queued.cancelled()
    finally:
        interrupted_queue.raise_interruption.set()
        interrupted_queue.release_drain.set()
        executor.shutdown(wait=True, cancel_futures=True)


def test_daemon_executor_preserves_caller_cancellation_after_dequeue_failure() -> None:
    """A cancelled future cannot make the worker crash while reporting failure."""

    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix="audit")
    paused_queue = _PausedGetQueue()
    executor._work_queue = paused_queue  # type: ignore[assignment]
    try:
        queued = executor.submit(lambda: "must not run")
        assert paused_queue.read_started.wait(timeout=1)

        with executor._lock:
            executor._broken = RuntimeError("embedded host interrupted another worker")
        assert queued.cancel()
        executor.shutdown(wait=False)
        paused_queue.release_read.set()
        executor.shutdown(wait=True)

        assert queued.cancelled()
    finally:
        paused_queue.release_read.set()
        executor.shutdown(wait=True, cancel_futures=True)
