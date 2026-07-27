"""Daemon-backed execution for abandonable, durably retried side work.

This executor is intentionally not a general replacement for
``ThreadPoolExecutor``.  It is used only for reconciliation audit delivery:
the authoritative outbox remains pending until an acknowledgement is
committed, and strict production requires the target sink to de-duplicate the
stable source event ID.  A blocked third-party sink can therefore be abandoned
at process shutdown without losing the delivery obligation.
"""

from __future__ import annotations

from concurrent.futures import Executor, Future
from dataclasses import dataclass
from queue import Empty, Queue
from threading import Lock, Thread, current_thread
from typing import Any, Callable


@dataclass(frozen=True, slots=True)
class _WorkItem:
    future: Future[Any]
    function: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]


class DaemonThreadPoolExecutor(Executor):
    """A bounded daemon executor for safely replayable background delivery.

    ``ThreadPoolExecutor`` workers are deliberately non-daemon and Python
    joins them during interpreter shutdown. That is correct for authoritative
    work, but wrong for a delivery attempt whose durable outbox entry has not
    yet been acknowledged. This executor makes that distinction explicit.
    """

    def __init__(self, *, max_workers: int, thread_name_prefix: str) -> None:
        if type(max_workers) is not int or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        if not thread_name_prefix:
            raise ValueError("thread_name_prefix must not be empty")
        self._max_workers = max_workers
        self._thread_name_prefix = thread_name_prefix
        self._work_queue: Queue[_WorkItem | None] = Queue()
        self._lock = Lock()
        self._threads: set[Thread] = set()
        self._idle_workers = 0
        self._shutdown = False
        self._thread_sequence = 0

    def submit(
        self,
        function: Callable[..., Any],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Future[Any]:
        future: Future[Any] = Future()
        with self._lock:
            if self._shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")
            self._work_queue.put(_WorkItem(future, function, args, kwargs))
            if self._idle_workers == 0 and len(self._threads) < self._max_workers:
                self._start_worker_unlocked()
        return future

    def shutdown(
        self,
        wait: bool = True,
        *,
        cancel_futures: bool = False,
    ) -> None:
        with self._lock:
            if not self._shutdown:
                self._shutdown = True
                if cancel_futures:
                    self._cancel_queued_work_unlocked()
                for _ in self._threads:
                    self._work_queue.put(None)
            threads = tuple(self._threads)
        if wait:
            caller = current_thread()
            for worker in threads:
                if worker is not caller:
                    worker.join()

    def _start_worker_unlocked(self) -> None:
        self._thread_sequence += 1
        worker = Thread(
            target=self._worker,
            name=f"{self._thread_name_prefix}_{self._thread_sequence}",
            daemon=True,
        )
        self._threads.add(worker)
        worker.start()

    def _cancel_queued_work_unlocked(self) -> None:
        while True:
            try:
                item = self._work_queue.get_nowait()
            except Empty:
                return
            if item is not None:
                item.future.cancel()

    def _worker(self) -> None:
        worker = current_thread()
        try:
            while True:
                with self._lock:
                    self._idle_workers += 1
                item = self._work_queue.get()
                with self._lock:
                    self._idle_workers -= 1
                if item is None:
                    return
                if not item.future.set_running_or_notify_cancel():
                    continue
                try:
                    result = item.function(*item.args, **item.kwargs)
                except BaseException as exc:
                    item.future.set_exception(exc)
                else:
                    item.future.set_result(result)
        finally:
            with self._lock:
                self._threads.discard(worker)
