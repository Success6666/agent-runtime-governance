from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
from concurrent.futures import Executor, ThreadPoolExecutor
from concurrent.futures import Future as ConcurrentFuture
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar, Token, copy_context
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from threading import Event, Lock, Thread, current_thread
from time import perf_counter
from typing import Any, Awaitable, Callable, Iterable, Mapping, ParamSpec, TypeVar
from uuid import uuid4
from weakref import WeakSet

from ._blocking import (
    BlockingRunner,
    ExtensionCleanupScheduler,
    ExtensionRunner,
    _discard_unstarted_awaitable,
    extension_cleanup_scope,
    has_extension_cleanup_context,
    install_blocking_runner,
    install_extension_cleanup_scheduler,
    install_extension_runner,
    is_extension_cleanup_active,
    is_extension_lifecycle_active,
    reset_blocking_runner,
    reset_extension_cleanup_scheduler,
    reset_extension_runner,
)
from ._context_boundaries import validate_middleware_transition
from ._daemon_executor import DaemonThreadPoolExecutor
from ._extensions import ExtensionDispatchSnapshot, _ExtensionDispatcher
from ._metadata import metadata_text as _metadata_text
from ._pipeline_runner import PipelineRunner
from ._serialization import thaw as _thaw
from .action_contracts import ActionContract, BoundAction
from .audit import reconciliation_event
from .context import (
    ExecutionContext,
    ExecutionMode,
    ExecutionStatus,
    HistoryEntry,
    RiskTier,
    ToolCall,
)
from .contracts import (
    bind_arguments,
    canonical_json_bytes,
    materialize_call,
    validate_instance,
)
from .decisions import DecisionOutcome, DecisionRecord, digest_arguments
from .errors import (
    AuditDeliveryError,
    ContextMutationError,
    ContractValidationError,
    ExecutionControlError,
    GovernanceCancelledError,
    GovernanceDenied,
    ReconciliationAuditDeliveryPendingError,
    RegistryError,
    ToolExecutionError,
)
from .hooks import CriticalHookError, HookCallback, HookPoint, HookRegistry
from .identity import IdentityProvider, VerifiedPrincipal
from .middleware.audit import AuditMiddleware
from .middleware.base import (
    ExecutionCall,
    ExecutionMiddleware,
    Middleware,
    MiddlewareKind,
)
from .pipeline import Pipeline
from .production import (
    ProductionProfile,
    ProductionReadinessError,
    ProductionReadinessReport,
    _same_sqlite_database,
)
from .reconciliation import (
    ManualResolution,
    ProviderDescriptor,
    ReconciliationAttemptContext,
    ReconciliationAttemptOutcome,
    ReconciliationAuditEnvelope,
    ReconciliationConflictError,
    ReconciliationFinding,
    ReconciliationHead,
    ReconciliationLedger,
    ReconciliationNotFoundError,
    ReconciliationState,
    SQLiteReconciliationLedger,
    UnknownAction,
    idempotency_namespace_digest,
    new_execution_record_id,
    tenant_partition_digest,
)
from .registry import (
    GovernedTool,
    IdempotencyClaim,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    IdempotencyOutcomeUnknownError,
    IdempotencyStore,
    InMemoryIdempotencyStore,
    SQLiteIdempotencyStore,
    ToolRegistry,
    ToolSpec,
)
from .resilience import (
    CapacityExceededError,
    RuntimeBulkhead,
    RuntimeLimits,
    StageTimeoutError,
    await_stage,
)

P = ParamSpec("P")
R = TypeVar("R")

_GOVERNANCE_METADATA_PREFIXES = ("approval_", "identity_", "policy_")
_RUNTIME_METADATA_KEYS = frozenset({"duration_ms"})
_TENANT_PARTITION_BOUND_METADATA_KEY = "tenant_partition_bound"
_ACTIVE_RUNTIME_IDS: ContextVar[frozenset[int]] = ContextVar(
    "agent_runtime_governance_active_runtime_ids",
    default=frozenset(),
)


@dataclass(frozen=True, slots=True)
class RunResult:
    value: Any
    context: ExecutionContext


@dataclass(slots=True)
class _ExtensionAdmissionScope:
    """Keep extension admission tied to the lifetime of one public operation."""

    _retain_detached_task: Callable[[asyncio.Future[Any]], None]
    _lock: Lock = field(default_factory=Lock)
    _active: bool = True
    _in_flight: dict[asyncio.Task[Any], int] = field(default_factory=dict)

    def close(self) -> None:
        """Reject new work and retain callbacks that outlive their operation."""

        current = asyncio.current_task()
        with self._lock:
            self._active = False
            pending = tuple(
                task
                for task in self._in_flight
                if task is not current and not task.done()
            )
        for task in pending:
            self._retain_detached_task(task)
            task.cancel()

    async def invoke(
        self,
        runner: ExtensionRunner,
        callback: Callable[..., Any],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        task = asyncio.current_task()
        tracked = False
        with self._lock:
            if has_extension_cleanup_context() and not is_extension_cleanup_active():
                raise RuntimeError("extension cleanup cannot spawn untracked work")
            cleanup_active = is_extension_cleanup_active()
            lifecycle_active = is_extension_lifecycle_active()
            if not self._active and not cleanup_active and not lifecycle_active:
                raise RuntimeError("runtime operation is complete")
            if task is not None and not cleanup_active and not lifecycle_active:
                self._in_flight[task] = self._in_flight.get(task, 0) + 1
                tracked = True
        try:
            return await runner(callback, *args, **kwargs)
        finally:
            if tracked and task is not None:
                with self._lock:
                    remaining = self._in_flight.get(task, 0) - 1
                    if remaining > 0:
                        self._in_flight[task] = remaining
                    else:
                        self._in_flight.pop(task, None)

    def schedule(
        self,
        scheduler: ExtensionCleanupScheduler,
        awaitable: Awaitable[Any],
    ) -> asyncio.Task[Any] | None:
        with self._lock:
            if has_extension_cleanup_context() and not is_extension_cleanup_active():
                _discard_unstarted_awaitable(awaitable)
                return None
            if not self._active:
                _discard_unstarted_awaitable(awaitable)
                return None
            return scheduler(awaitable)


@dataclass(frozen=True, slots=True)
class _ActiveOperation:
    task: asyncio.Task[Any] | None
    reconciliation: bool
    context_token: Token[frozenset[int]]
    extension_scope: _ExtensionAdmissionScope
    cleanup_scheduler_token: Token[ExtensionCleanupScheduler | None]
    extension_runner_token: Token[ExtensionRunner | None]
    blocking_runner_token: Token[BlockingRunner | None]


class _ActionBindingError(RuntimeError):
    """Internal fail-closed admission error with a non-sensitive message."""


@dataclass(frozen=True, slots=True)
class InvocationOptions:
    input_text: str = ""
    user: str | None = None
    tenant: str | None = None
    permissions: frozenset[str] = frozenset()
    task_id: str | None = None
    conversation_id: str | None = None
    request_id: str | None = None
    metadata: dict[str, Any] | None = None
    identity_claims: Mapping[str, Any] | None = None
    idempotency_key: str | None = None
    deadline: datetime | None = None

    def __post_init__(self) -> None:
        if self.idempotency_key is not None and not self.idempotency_key.strip():
            raise ValueError("idempotency_key cannot be empty")
        if self.deadline is not None and (
            self.deadline.tzinfo is None or self.deadline.utcoffset() is None
        ):
            raise ValueError("deadline must be timezone-aware")
        if self.request_id is not None and not self.request_id.strip():
            raise ValueError("request_id cannot be empty")


class Runtime:
    """Executes registered tools through a deterministic governance pipeline."""

    def __init__(
        self,
        pipeline: Pipeline | Iterable[Middleware] = (),
        *,
        hooks: HookRegistry | None = None,
        idempotency_store: IdempotencyStore | None = None,
        reconciliation_ledger: ReconciliationLedger | None = None,
        identity_provider: IdentityProvider | None = None,
        require_verified_identity: bool = False,
        limits: RuntimeLimits | None = None,
        sync_executor: Executor | None = None,
        idempotency_executor: Executor | None = None,
        reconciliation_executor: Executor | None = None,
        reconciliation_audit_executor: Executor | None = None,
        production_profile: ProductionProfile | None = None,
    ) -> None:
        self._pipeline = (
            pipeline if isinstance(pipeline, Pipeline) else Pipeline(pipeline)
        )
        self._pipeline_runner = PipelineRunner(self._pipeline)
        self._hooks = hooks or HookRegistry()
        self._registry = ToolRegistry()
        self._idempotency_store = idempotency_store or InMemoryIdempotencyStore()
        self._reconciliation_ledger = reconciliation_ledger
        self._atomic_reconciliation_preparation: bool | None = None
        self._identity_provider = identity_provider
        self._require_verified_identity = require_verified_identity
        self._production_profile = production_profile
        self._production_report: ProductionReadinessReport | None = None
        self._production_sealed = production_profile is None
        self._production_seal_lock = Lock()
        self.limits = limits or RuntimeLimits()
        self._lifecycle_lock = Lock()
        self._closing = False
        self._closed = False
        self._bulkhead = RuntimeBulkhead(self.limits.max_in_flight)
        self._async_tool_bulkhead = RuntimeBulkhead(self.limits.max_in_flight)
        self._sync_bulkhead = RuntimeBulkhead(self.limits.max_in_flight)
        self._owns_sync_executor = sync_executor is None
        self._sync_executor = sync_executor or ThreadPoolExecutor(
            max_workers=self.limits.max_in_flight,
            thread_name_prefix="arg-tool",
        )
        self._extension_dispatcher = _ExtensionDispatcher(
            max_workers=self.limits.max_blocking_extension_workers,
            max_in_flight=self.limits.max_blocking_extension_in_flight,
            capacity_timeout_seconds=self.limits.execution_timeout_seconds,
            admission_lock=self._lifecycle_lock,
            is_accepting=self._is_extension_dispatch_accepting,
        )
        self._extension_dispatch_lifecycle_bindings: WeakSet[Any] = WeakSet()
        self._bind_extension_dispatch_metrics()
        self._bind_extension_dispatch_lifecycle()
        self._owns_idempotency_executor = idempotency_executor is None
        self._idempotency_executor = idempotency_executor or ThreadPoolExecutor(
            max_workers=min(4, self.limits.max_in_flight),
            thread_name_prefix="arg-idempotency",
        )
        self._idempotency_bulkhead = RuntimeBulkhead(min(4, self.limits.max_in_flight))
        self._idempotency_poison_lock = Lock()
        self._idempotency_poison: BaseException | None = None
        self._idempotency_draining = 0
        self._owns_reconciliation_executor = reconciliation_executor is None
        self._reconciliation_executor = reconciliation_executor or ThreadPoolExecutor(
            max_workers=min(4, self.limits.max_reconciliation_in_flight),
            thread_name_prefix="arg-reconciliation",
        )
        self._reconciliation_bulkhead = RuntimeBulkhead(
            self.limits.max_reconciliation_in_flight
        )
        self._owns_reconciliation_audit_executor = reconciliation_audit_executor is None
        self._reconciliation_audit_executor = (
            reconciliation_audit_executor
            or DaemonThreadPoolExecutor(
                max_workers=self.limits.max_reconciliation_audit_delivery_in_flight,
                thread_name_prefix="arg-reconciliation-audit",
            )
        )
        self._reconciliation_audit_bulkhead = RuntimeBulkhead(
            self.limits.max_reconciliation_audit_delivery_in_flight
        )
        self._reconciliation_poison_lock = Lock()
        self._reconciliation_poison: BaseException | None = None
        self._reconciliation_draining = 0
        self._reconciliation_provider_lock = Lock()
        self._reconciliation_provider_poison: dict[str, BaseException] = {}
        self._reconciliation_provider_draining: set[str] = set()
        self._async_close_task: asyncio.Task[None] | None = None
        self._active_operations: dict[asyncio.Task[Any], int] = {}
        self._sync_invoke_futures: set[ConcurrentFuture[Any]] = set()
        self._sync_tool_futures: set[ConcurrentFuture[Any]] = set()
        self._detached_stage_tasks: set[asyncio.Future[Any]] = set()
        self._reconciliation_tasks: set[asyncio.Task[Any]] = set()
        self._reconciliation_finalizers: set[asyncio.Task[Any]] = set()
        self._reconciliation_workflows: dict[asyncio.Task[Any], int] = {}
        self._sync_loop_lock = Lock()
        self._sync_loop: asyncio.AbstractEventLoop | None = None
        self._sync_loop_thread: Thread | None = None
        self._sync_loop_ready: Event | None = None
        self._sync_loop_error: BaseException | None = None
        self._sync_loop_stopping = False

    def close(self, *, wait: bool = True) -> None:
        """Stop accepting work and release the owned synchronous executor."""

        if id(self) in _ACTIVE_RUNTIME_IDS.get():
            raise RuntimeError(
                "close() cannot be called from an active runtime operation"
            )
        if self.production_profile is not None and not wait:
            raise ValueError(
                "production runtimes require close(wait=True) or await aclose()"
            )
        with self._lifecycle_lock:
            if self._closing:
                raise RuntimeError("runtime close is already in progress")
            if self._closed:
                return
            self._closing = True
            try:
                if any(
                    not task.done()
                    for task in (
                        *self._reconciliation_tasks,
                        *self._reconciliation_finalizers,
                        *self._reconciliation_workflows,
                    )
                ):
                    raise RuntimeError(
                        "reconciliation work is pending; use await runtime.aclose()"
                    )
                if any(not task.done() for task in self._detached_stage_tasks):
                    raise RuntimeError(
                        "runtime work is pending; use await runtime.aclose()"
                    )
                if self._extension_dispatcher.has_pending_cleanup_tasks():
                    raise RuntimeError(
                        "extension cleanup is pending; use await runtime.aclose()"
                    )
                if self._extension_dispatcher.has_detached_sync_work():
                    raise RuntimeError(
                        "synchronous extension work is pending; use await runtime.aclose()"
                    )
                if self.extension_dispatch_snapshot.in_flight:
                    raise RuntimeError(
                        "synchronous extension work is pending; use await runtime.aclose()"
                    )
                if any(not task.done() for task in self._active_operations):
                    raise RuntimeError(
                        "runtime work is pending; use await runtime.aclose()"
                    )
                if any(not future.done() for future in self._sync_invoke_futures):
                    raise RuntimeError(
                        "runtime work is pending; use await runtime.aclose()"
                    )
                if any(not future.done() for future in self._sync_tool_futures):
                    raise RuntimeError(
                        "synchronous tool work is pending; use await runtime.aclose()"
                    )
                self._closed = True
                reconciliation_tasks = tuple(self._reconciliation_tasks)
            except BaseException:
                self._closing = False
                raise
        closed_successfully = False
        try:
            for task in reconciliation_tasks:
                task.cancel()
            self._shutdown_executors(wait=wait)
            closed_successfully = True
        finally:
            with self._lifecycle_lock:
                self._closing = False
        if closed_successfully:
            self._stop_sync_loop()

    async def aclose(self) -> None:
        """Close the Runtime from any caller loop without crossing Task ownership."""

        current_loop = asyncio.get_running_loop()
        with self._lifecycle_lock:
            if self._closed:
                return
            if self._closing:
                raise RuntimeError("runtime close is already in progress")
            caller = asyncio.current_task()
            if self._is_active_operation_context(caller):
                raise RuntimeError("aclose() cannot be called from an active runtime operation")
            owner_loops = self._pending_lifecycle_loops_unlocked()
            foreign_loops = owner_loops - {current_loop}
            if foreign_loops:
                sync_loop = self._get_sync_loop()
                if len(owner_loops) != 1 or sync_loop not in foreign_loops:
                    raise RuntimeError(
                        "runtime has active lifecycle work on another event loop"
                    )
                owner_loop = sync_loop
            else:
                owner_loop = current_loop
            self._closing = True
        if owner_loop is not current_loop:
            coroutine = self._aclose_on_current_loop(close_claimed=True)
            try:
                close_future = asyncio.run_coroutine_threadsafe(coroutine, owner_loop)
            except BaseException:
                coroutine.close()
                with self._lifecycle_lock:
                    if not self._closed:
                        self._closing = False
                raise
            close_future.add_done_callback(self._stop_sync_loop_after_close)
            await asyncio.shield(asyncio.wrap_future(close_future))
            await asyncio.to_thread(self._stop_sync_loop)
            return

        await self._aclose_on_current_loop(close_claimed=True)
        await asyncio.to_thread(self._stop_sync_loop)

    async def _aclose_on_current_loop(self, *, close_claimed: bool = False) -> None:
        """Close after durable reconciliation finalizers have completed.

        A finalizer represents a ledger attempt that has already been persisted
        as started.  It must finish under its independent bounded budget before
        the reconciliation executor is shut down.
        """

        with self._lifecycle_lock:
            if self._closing and not close_claimed:
                raise RuntimeError("runtime close is already in progress")
            if self._closed:
                return
            if not close_claimed:
                self._closing = True
            try:
                caller = asyncio.current_task()
                if self._is_active_operation_context(caller):
                    raise RuntimeError(
                        "aclose() cannot be called from an active runtime operation"
                    )
                self._reject_cross_loop_lifecycle_operation_unlocked()
                self._closed = True
                reconciliation_tasks = tuple(self._reconciliation_tasks)
                close_task = asyncio.create_task(
                    self._finish_async_close(reconciliation_tasks),
                    name="runtime-close",
                )
                close_task.add_done_callback(self._consume_background_result)
                close_task.add_done_callback(self._stop_sync_loop_after_close)
                self._async_close_task = close_task
            except BaseException:
                self._closing = False
                raise
        await asyncio.shield(close_task)

    async def _finish_async_close(
        self,
        reconciliation_tasks: tuple[asyncio.Task[Any], ...],
    ) -> None:
        """Complete shutdown even if the caller of :meth:`aclose` is cancelled."""

        try:
            for task in reconciliation_tasks:
                task.cancel()
            current = asyncio.current_task()
            while True:
                with self._lifecycle_lock:
                    detached_stage_tasks = tuple(
                        task
                        for task in self._detached_stage_tasks
                        if task is not current and not task.done()
                    )
                    provider_tasks = tuple(
                        task
                        for task in self._reconciliation_tasks
                        if task is not current and not task.done()
                    )
                    active_operations = tuple(
                        task
                        for task in self._active_operations
                        if task is not current and not task.done()
                    )
                    sync_tool_futures = tuple(
                        future
                        for future in self._sync_tool_futures
                        if not future.done()
                    )
                    sync_invoke_futures = tuple(
                        future
                        for future in self._sync_invoke_futures
                        if not future.done()
                    )
                    workflows = tuple(
                        task
                        for task in self._reconciliation_workflows
                        if task is not current and not task.done()
                    )
                    finalizers = tuple(
                        task
                        for task in self._reconciliation_finalizers
                        if task is not current and not task.done()
                    )
                for task in provider_tasks:
                    task.cancel()
                for task in detached_stage_tasks:
                    task.cancel()
                for task in workflows:
                    task.cancel()
                for future in sync_tool_futures:
                    future.cancel()
                pending = tuple(
                    dict.fromkeys(
                        (
                            *provider_tasks,
                            *detached_stage_tasks,
                            *active_operations,
                            *workflows,
                            *finalizers,
                        )
                    )
                )
                if not pending and not sync_tool_futures and not sync_invoke_futures:
                    break
                if pending:
                    await asyncio.shield(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                if sync_tool_futures:
                    await asyncio.shield(
                        asyncio.gather(
                            *(
                                asyncio.wrap_future(future)
                                for future in sync_tool_futures
                            ),
                            return_exceptions=True,
                        )
                    )
                if sync_invoke_futures:
                    await asyncio.shield(
                        asyncio.gather(
                            *(
                                asyncio.wrap_future(future)
                                for future in sync_invoke_futures
                            ),
                            return_exceptions=True,
                        )
                    )
            await self._extension_dispatcher.drain_cleanup_tasks()
            await asyncio.to_thread(self._shutdown_executors, wait=True)
        finally:
            with self._lifecycle_lock:
                self._closing = False
                self._async_close_task = None

    def _get_sync_loop(self) -> asyncio.AbstractEventLoop | None:
        with self._sync_loop_lock:
            loop = self._sync_loop
            if loop is None or loop.is_closed():
                return None
            return loop

    def _ensure_sync_loop(self) -> asyncio.AbstractEventLoop:
        """Start the Runtime-owned loop that preserves sync-call cleanup work."""

        with self._sync_loop_lock:
            loop = self._sync_loop
            if loop is not None and not loop.is_closed():
                return loop
            ready = self._sync_loop_ready
            thread = self._sync_loop_thread
            if thread is None or not thread.is_alive():
                ready = Event()
                thread = Thread(
                    target=self._run_sync_loop,
                    args=(ready,),
                    name="arg-runtime-sync-loop",
                    daemon=True,
                )
                self._sync_loop_ready = ready
                self._sync_loop_thread = thread
                self._sync_loop_error = None
                self._sync_loop_stopping = False
                thread.start()
        assert ready is not None
        if not ready.wait(timeout=self.limits.sync_loop_startup_timeout_seconds):
            raise RuntimeError("runtime synchronous event loop did not start")
        with self._sync_loop_lock:
            if self._sync_loop_error is not None:
                raise RuntimeError(
                    "runtime synchronous event loop failed to start"
                ) from self._sync_loop_error
            loop = self._sync_loop
            if loop is None or loop.is_closed():
                raise RuntimeError("runtime synchronous event loop is unavailable")
            return loop

    def _run_sync_loop(self, ready: Event) -> None:
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            with self._sync_loop_lock:
                self._sync_loop = loop
                stopping = self._sync_loop_stopping
            ready.set()
            if stopping:
                loop.call_soon(loop.stop)
            loop.run_forever()
        except BaseException as exc:
            with self._sync_loop_lock:
                self._sync_loop_error = exc
            ready.set()
        finally:
            if loop is not None:
                pending = tuple(
                    task for task in asyncio.all_tasks(loop) if not task.done()
                )
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.run_until_complete(loop.shutdown_default_executor())
                loop.close()
            asyncio.set_event_loop(None)
            with self._sync_loop_lock:
                if self._sync_loop is loop:
                    self._sync_loop = None
                    self._sync_loop_thread = None
                    self._sync_loop_ready = None
                    self._sync_loop_stopping = False

    def _request_sync_loop_stop(self) -> None:
        with self._sync_loop_lock:
            loop = self._sync_loop
            thread = self._sync_loop_thread
            if self._sync_loop_stopping:
                return
            self._sync_loop_stopping = True
        if loop is None or thread is None or loop.is_closed():
            return
        try:
            if thread is current_thread():
                loop.call_soon(loop.stop)
            else:
                loop.call_soon_threadsafe(loop.stop)
        except RuntimeError:
            return

    def _stop_sync_loop(self) -> None:
        with self._sync_loop_lock:
            thread = self._sync_loop_thread
        if thread is None:
            return
        if thread is current_thread():
            self._request_sync_loop_stop()
            return
        self._request_sync_loop_stop()
        thread.join()

    def _stop_sync_loop_after_close(
        self, future: ConcurrentFuture[Any] | asyncio.Future[Any]
    ) -> None:
        if future.cancelled():
            return
        try:
            future.result()
        except BaseException:
            return
        self._request_sync_loop_stop()

    def _begin_reconciliation_workflow(self) -> _ActiveOperation:
        return self._begin_active_operation(reconciliation=True)

    def _end_reconciliation_workflow(self, operation: _ActiveOperation) -> None:
        self._end_active_operation(operation)

    def _begin_active_operation(
        self,
        *,
        reconciliation: bool = False,
    ) -> _ActiveOperation:
        """Atomically admit and track one public runtime operation."""

        task = asyncio.current_task()
        with self._lifecycle_lock:
            if self._closed or self._closing:
                raise RuntimeError("runtime is closed")
            self._reject_cross_loop_lifecycle_operation_unlocked()
            if task is not None:
                self._active_operations[task] = (
                    self._active_operations.get(task, 0) + 1
                )
                if reconciliation:
                    self._reconciliation_workflows[task] = (
                        self._reconciliation_workflows.get(task, 0) + 1
                    )
        context_token = _ACTIVE_RUNTIME_IDS.set(
            _ACTIVE_RUNTIME_IDS.get() | frozenset({id(self)})
        )
        extension_scope = _ExtensionAdmissionScope(self._track_detached_stage)
        cleanup_scheduler_token = install_extension_cleanup_scheduler(
            partial(extension_scope.schedule, self._schedule_extension_cleanup)
        )
        extension_runner_token = install_extension_runner(
            partial(extension_scope.invoke, self._invoke_extension)
        )
        blocking_runner_token = install_blocking_runner(
            partial(extension_scope.invoke, self._run_blocking_extension)
        )
        return _ActiveOperation(
            task,
            reconciliation,
            context_token,
            extension_scope,
            cleanup_scheduler_token,
            extension_runner_token,
            blocking_runner_token,
        )

    def _end_active_operation(
        self,
        operation: _ActiveOperation,
    ) -> None:
        operation.extension_scope.close()
        reset_blocking_runner(operation.blocking_runner_token)
        reset_extension_runner(operation.extension_runner_token)
        reset_extension_cleanup_scheduler(operation.cleanup_scheduler_token)
        _ACTIVE_RUNTIME_IDS.reset(operation.context_token)
        task = operation.task
        if task is None:
            return
        with self._lifecycle_lock:
            remaining_operations = self._active_operations.get(task, 0) - 1
            if remaining_operations > 0:
                self._active_operations[task] = remaining_operations
            else:
                self._active_operations.pop(task, None)
            if operation.reconciliation:
                self._reconciliation_workflows[task] = (
                    self._reconciliation_workflows.get(task, 0) - 1
                )
                if self._reconciliation_workflows[task] <= 0:
                    self._reconciliation_workflows.pop(task, None)

    def _is_active_operation_context(
        self,
        caller: asyncio.Task[Any] | None,
    ) -> bool:
        return (
            id(self) in _ACTIVE_RUNTIME_IDS.get()
            or caller is not None and caller in self._active_operations
        )

    def _pending_lifecycle_loops_unlocked(
        self,
    ) -> set[asyncio.AbstractEventLoop]:
        """Return owner loops for work that must settle before executor shutdown."""

        pending_tasks = (
            *self._active_operations,
            *self._detached_stage_tasks,
            *self._reconciliation_workflows,
            *self._reconciliation_tasks,
            *self._reconciliation_finalizers,
            *self._extension_dispatcher.pending_cleanup_tasks(),
        )
        loops = {
            task.get_loop()
            for task in pending_tasks
            if not task.done()
        }
        if any(not future.done() for future in self._sync_invoke_futures):
            sync_loop = self._get_sync_loop()
            if sync_loop is not None:
                loops.add(sync_loop)
        return loops

    def _reject_cross_loop_lifecycle_operation_unlocked(self) -> None:
        """Reject lifecycle coordination across active event loops.

        ``asyncio.Task`` instances cannot be awaited or cancelled safely from a
        different event loop.  Runtime operations may run sequentially from
        distinct loops after previous work has settled, but admission and
        asynchronous shutdown require the loop that owns outstanding work.
        """

        current_loop = asyncio.get_running_loop()
        if any(
            loop is not current_loop
            for loop in self._pending_lifecycle_loops_unlocked()
        ):
            raise RuntimeError(
                "runtime has active lifecycle work on another event loop"
            )

    def _track_detached_stage(self, task: asyncio.Future[Any]) -> None:
        """Keep an uncooperative coroutine in shutdown coordination."""

        with self._lifecycle_lock:
            self._detached_stage_tasks.add(task)
        task.add_done_callback(self._forget_detached_stage)

    def _schedule_extension_cleanup(
        self, awaitable: Awaitable[Any]
    ) -> asyncio.Task[Any] | None:
        """Track terminal extension cleanup until the owned dispatcher drains it."""

        async def run_cleanup() -> Any:
            with extension_cleanup_scope():
                return await awaitable

        task = self._extension_dispatcher.create_cleanup_task(run_cleanup)
        if task is None:
            _discard_unstarted_awaitable(awaitable)
        return task

    def _forget_detached_stage(self, task: asyncio.Future[Any]) -> None:
        with self._lifecycle_lock:
            self._detached_stage_tasks.discard(task)

    def _track_sync_tool_future(self, future: ConcurrentFuture[Any]) -> None:
        """Retain a submitted sync tool even if its asyncio wrapper is cancelled."""

        with self._lifecycle_lock:
            self._sync_tool_futures.add(future)
        future.add_done_callback(self._forget_sync_tool_future)

    def _forget_sync_invoke_future(self, future: ConcurrentFuture[Any]) -> None:
        with self._lifecycle_lock:
            self._sync_invoke_futures.discard(future)

    def _forget_sync_tool_future(self, future: ConcurrentFuture[Any]) -> None:
        with self._lifecycle_lock:
            self._sync_tool_futures.discard(future)

    def _assert_accepting_work(self) -> None:
        """Atomically reject public work once shutdown starts."""

        with self._lifecycle_lock:
            if self._closed or self._closing:
                raise RuntimeError("runtime is closed")

    def _shutdown_executors(self, *, wait: bool) -> None:
        if self._owns_reconciliation_audit_executor:
            # A synchronous third-party sink cannot be force-cancelled once it
            # has entered a blocking write. This dedicated executor has daemon
            # workers: its event remains durably pending in the reconciliation
            # outbox, and its idempotent source identity makes a successor
            # worker safe after process exit.
            self._reconciliation_audit_executor.shutdown(
                wait=False, cancel_futures=True
            )
        if self._owns_reconciliation_executor:
            self._reconciliation_executor.shutdown(wait=wait, cancel_futures=True)
        if self._owns_idempotency_executor:
            self._idempotency_executor.shutdown(wait=wait, cancel_futures=True)
        if self._owns_sync_executor:
            self._sync_executor.shutdown(wait=wait, cancel_futures=True)
        self._extension_dispatcher.shutdown(wait=wait)

    @property
    def sync_executor(self) -> Executor:
        """Return the executor used for synchronous tool bodies."""

        return self._sync_executor

    @property
    def idempotency_executor(self) -> Executor:
        """Return the executor isolated for idempotency-store operations."""

        return self._idempotency_executor

    @property
    def reconciliation_executor(self) -> Executor:
        """Return the executor isolated for reconciliation-ledger operations."""

        return self._reconciliation_executor

    @property
    def reconciliation_audit_executor(self) -> Executor:
        """Return the executor isolated for reconciliation audit delivery."""

        return self._reconciliation_audit_executor

    @property
    def extension_dispatch_snapshot(self) -> ExtensionDispatchSnapshot:
        """Return read-only capacity state for third-party extension dispatch."""

        return self._extension_dispatcher.snapshot()

    def _is_extension_dispatch_accepting(self) -> bool:
        """Read the lifecycle state while the dispatcher's admission lock is held."""

        return not self._closed and not self._closing

    def _bind_extension_dispatch_metrics(self) -> None:
        """Allow built-in optional metrics middleware to observe internal dispatch."""

        from .plugins.prometheus import PrometheusMiddleware

        observers = []
        for middleware in self._pipeline:
            if isinstance(middleware, PrometheusMiddleware):
                middleware._bind_extension_dispatch_snapshot(
                    self._extension_dispatcher.snapshot
                )
                observers.append(middleware)
        self._extension_dispatcher.replace_observers(observers)

    def _bind_extension_dispatch_lifecycle(self) -> None:
        """Expose Runtime shutdown only to the built-in legacy OTel bridge."""

        from .telemetry import OpenTelemetryMiddleware

        for middleware in self._pipeline:
            if isinstance(middleware, OpenTelemetryMiddleware):
                if middleware in self._extension_dispatch_lifecycle_bindings:
                    continue
                middleware._bind_extension_shutdown_signal(
                    self._extension_dispatcher.shutdown_signal
                )
                self._extension_dispatch_lifecycle_bindings.add(middleware)

    @property
    def reconciliation_ledger_healthy(self) -> bool:
        """Return whether reconciliation ledger work is neither poisoned nor draining."""

        with self._reconciliation_poison_lock:
            return (
                self._reconciliation_poison is None
                and self._reconciliation_draining == 0
            )

    def __enter__(self) -> "Runtime":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    async def __aenter__(self) -> "Runtime":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def hook(
        self, point: HookPoint, *, critical: bool = False
    ) -> Callable[[HookCallback], HookCallback]:
        return self.hooks.decorator(point, critical=critical)

    @property
    def production_sealed(self) -> bool:
        return self._production_sealed

    @property
    def production_report(self) -> ProductionReadinessReport | None:
        return self._production_report

    def _guard_sealed_mutation(self, attribute: str) -> None:
        """Reject reassignment of governance components once sealed."""

        if self._production_profile is not None and self._production_sealed:
            raise RuntimeError(
                "runtime is sealed for production; "
                f"{attribute} cannot be reassigned"
            )

    @property
    def pipeline(self) -> Pipeline:
        return self._pipeline

    @pipeline.setter
    def pipeline(self, value: Pipeline | Iterable[Middleware]) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("pipeline")
            pipeline = (
                value if isinstance(value, Pipeline) else Pipeline(value)
            )
            self._pipeline = pipeline
            self._pipeline_runner = PipelineRunner(pipeline)
            self._bind_extension_dispatch_metrics()
            self._bind_extension_dispatch_lifecycle()

    @property
    def hooks(self) -> HookRegistry:
        return self._hooks

    @hooks.setter
    def hooks(self, value: HookRegistry) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("hooks")
            self._hooks = value

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @registry.setter
    def registry(self, value: ToolRegistry) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("registry")
            self._registry = value

    @property
    def idempotency_store(self) -> IdempotencyStore:
        return self._idempotency_store

    @idempotency_store.setter
    def idempotency_store(self, value: IdempotencyStore) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("idempotency_store")
            self._idempotency_store = value
            self._atomic_reconciliation_preparation = None

    @property
    def reconciliation_ledger(self) -> ReconciliationLedger | None:
        return self._reconciliation_ledger

    @reconciliation_ledger.setter
    def reconciliation_ledger(self, value: ReconciliationLedger | None) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("reconciliation_ledger")
            self._reconciliation_ledger = value
            self._atomic_reconciliation_preparation = None

    @property
    def identity_provider(self) -> IdentityProvider | None:
        return self._identity_provider

    @identity_provider.setter
    def identity_provider(self, value: IdentityProvider | None) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("identity_provider")
            self._identity_provider = value

    @property
    def require_verified_identity(self) -> bool:
        return self._require_verified_identity

    @require_verified_identity.setter
    def require_verified_identity(self, value: bool) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("require_verified_identity")
            self._require_verified_identity = value

    @property
    def production_profile(self) -> ProductionProfile | None:
        return self._production_profile

    @production_profile.setter
    def production_profile(self, value: ProductionProfile | None) -> None:
        with self._production_seal_lock:
            self._guard_sealed_mutation("production_profile")
            self._production_profile = value
            self._production_sealed = value is None
            self._production_report = None

    def production_readiness(
        self, profile: ProductionProfile | None = None
    ) -> ProductionReadinessReport:
        selected = profile or self.production_profile or ProductionProfile()
        return selected.evaluate(
            self.registry.list(),
            pipeline=self.pipeline,
            idempotency_store=self.idempotency_store,
            reconciliation_ledger=self.reconciliation_ledger,
            identity_provider=self.identity_provider,
            require_verified_identity=self.require_verified_identity,
        )

    def seal_production(self) -> ProductionReadinessReport:
        if self.production_profile is None:
            raise ValueError("production_profile is not configured")
        with self._production_seal_lock:
            if self._production_sealed and self._production_report is not None:
                return self._production_report

            def validate(
                tools: tuple[ToolSpec[Any, Any], ...]
            ) -> ProductionReadinessReport:
                report = self.production_profile.evaluate(
                    tools,
                    pipeline=self.pipeline,
                    idempotency_store=self.idempotency_store,
                    reconciliation_ledger=self.reconciliation_ledger,
                    identity_provider=self.identity_provider,
                    require_verified_identity=self.require_verified_identity,
                )
                if not report.ready:
                    raise ProductionReadinessError(report)
                return report

            report = self.registry._seal_with(validate)
            self._production_report = report
            self._production_sealed = True
            return report

    def before_tool(
        self, callback: HookCallback | None = None, *, critical: bool = False
    ) -> HookCallback | Callable[[HookCallback], HookCallback]:
        decorator = self.hook(HookPoint.BEFORE_EXECUTE, critical=critical)
        return decorator(callback) if callback is not None else decorator

    def after_tool(
        self, callback: HookCallback | None = None
    ) -> HookCallback | Callable[[HookCallback], HookCallback]:
        decorator = self.hook(HookPoint.AFTER_EXECUTE)
        return decorator(callback) if callback is not None else decorator

    def before_llm(
        self, callback: HookCallback | None = None, *, critical: bool = False
    ) -> HookCallback | Callable[[HookCallback], HookCallback]:
        decorator = self.hook(HookPoint.BEFORE_LLM, critical=critical)
        return decorator(callback) if callback is not None else decorator

    def after_llm(
        self, callback: HookCallback | None = None
    ) -> HookCallback | Callable[[HookCallback], HookCallback]:
        decorator = self.hook(HookPoint.AFTER_LLM)
        return decorator(callback) if callback is not None else decorator

    def tool(
        self,
        *,
        risk: RiskTier = RiskTier.LOW,
        requires_approval: bool = False,
        name: str | None = None,
        description: str = "",
        execution_mode: ExecutionMode = ExecutionMode.MUTATING,
        parameters_schema: dict[str, Any] | None = None,
        result_schema: dict[str, Any] | None = None,
        max_parameters_bytes: int | None = None,
        max_result_bytes: int | None = None,
        action_contract: ActionContract | None = None,
        reconciliation_provider: ProviderDescriptor | None = None,
        reconciliation_probe_schema: dict[str, Any] | None = None,
    ) -> Callable[[Callable[P, R]], GovernedTool[P, R]]:
        def decorator(function: Callable[P, R]) -> GovernedTool[P, R]:
            spec = ToolSpec(
                name=name or function.__name__,
                function=function,
                risk=risk,
                requires_approval=requires_approval,
                description=description or (function.__doc__ or ""),
                execution_mode=execution_mode,
                parameters_schema=parameters_schema,
                result_schema=result_schema,
                max_parameters_bytes=max_parameters_bytes,
                max_result_bytes=max_result_bytes,
                action_contract=action_contract,
                reconciliation_provider=reconciliation_provider,
                reconciliation_probe_schema=reconciliation_probe_schema,
            )
            self.registry.register(spec)
            return GovernedTool(self, spec)

        return decorator

    def invoke(self, name: str, *args: Any, **kwargs: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            with self._lifecycle_lock:
                if self._closed or self._closing:
                    raise RuntimeError("runtime is closed") from None
            loop = self._ensure_sync_loop()
            stop_loop = False
            with self._lifecycle_lock:
                if self._closed or self._closing:
                    stop_loop = True
                else:
                    coroutine = self.ainvoke(name, *args, **kwargs)
                    try:
                        future = copy_context().run(
                            asyncio.run_coroutine_threadsafe, coroutine, loop
                        )
                    except BaseException:
                        coroutine.close()
                        raise
                    self._sync_invoke_futures.add(future)
            if stop_loop:
                self._stop_sync_loop()
                raise RuntimeError("runtime is closed") from None
            future.add_done_callback(self._forget_sync_invoke_future)
            return future.result()
        raise RuntimeError("invoke() cannot run inside an event loop; use ainvoke()")

    async def ainvoke(self, name: str, *args: Any, **kwargs: Any) -> Any:
        return (await self.arun(name, *args, **kwargs)).value

    async def arun(
        self,
        name: str,
        *args: Any,
        _governance: InvocationOptions | None = None,
        **kwargs: Any,
    ) -> RunResult:
        operation = self._begin_active_operation()
        try:
            return await self._arun(name, *args, _governance=_governance, **kwargs)
        finally:
            self._end_active_operation(operation)

    async def _arun(
        self,
        name: str,
        *args: Any,
        _governance: InvocationOptions | None = None,
        **kwargs: Any,
    ) -> RunResult:
        self._assert_accepting_work()
        if self.production_profile is not None and not self._production_sealed:
            raise ProductionReadinessError(self.production_readiness())
        options = _governance or InvocationOptions()
        spec = self.registry.get(name)
        try:
            admission_timeout = self._bounded_timeout(
                options.deadline, self.limits.admission_timeout_seconds, "admission"
            )
            async with self._bulkhead.slot(admission_timeout):
                return await self._arun_admitted(
                    name, *args, _governance=options, **kwargs
                )
        except (CapacityExceededError, StageTimeoutError) as exc:
            await self._record_admission_failure(
                spec,
                args,
                kwargs,
                options,
                exc,
            )
            raise

    async def _arun_admitted(
        self,
        name: str,
        *args: Any,
        _governance: InvocationOptions,
        **kwargs: Any,
    ) -> RunResult:
        spec = self.registry.get(name)
        started = perf_counter()
        context = await self._create_context(
            spec,
            args,
            kwargs,
            _governance,
        )
        try:
            normalized_parameters = self._prepare_parameters(
                spec, args, kwargs, context.deadline
            )
            context = await self._bind_action(
                spec, context, normalized_parameters
            )
            if context.bound_action is not None:
                normalized_parameters = context.bound_action.parameters
            execution_args, execution_kwargs = materialize_call(
                spec.function, normalized_parameters
            )
        except _ActionBindingError as exc:
            context = self._deny_action_binding(context, str(exc))
            context = await self._run_observers(context, post=True)
            raise GovernanceDenied(context) from exc
        except (ContractValidationError, StageTimeoutError, ValueError) as exc:
            if context.denied:
                context = context.append_history(
                    HistoryEntry(
                        "contract",
                        "deny",
                        f"request rejected after {type(exc).__name__}",
                    )
                )
                context = await self._run_observers(context, post=True)
                raise GovernanceDenied(context) from exc
            context = self._failed_context(context, exc, started)
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, exc) from exc
        context = self._enforce_idempotency_key(context)
        if context.denied:
            context = await self._run_observers(context, post=True)
            raise GovernanceDenied(context)
        try:
            context = await self._emit_hook(
                HookPoint.BEFORE_PIPELINE, context, allow_critical=True
            )
            if not context.denied:
                context = await self._run_pre_pipeline(context)
            if not context.denied:
                context = await self._emit_hook(
                    HookPoint.AFTER_PIPELINE, context, allow_critical=True
                )
            context = self._enforce_required_approval(context)
            if context.denied:
                context = await self._release_approvals(context)
                context = await self._run_observers(context, post=True)
                raise GovernanceDenied(context)

            context = context.evolve(
                status=ExecutionStatus.EXECUTING,
                decision=context.decision
                or DecisionRecord(DecisionOutcome.ALLOW, "pipeline allowed", "runtime"),
            )
            context = await self._emit_hook(
                HookPoint.BEFORE_EXECUTE, context, allow_critical=True
            )
            context = self._enforce_required_approval(context)
            if context.denied:
                context = await self._release_approvals(context)
                context = await self._run_observers(context, post=True)
                raise GovernanceDenied(context)
        except asyncio.CancelledError as exc:
            context = await asyncio.shield(self._release_approvals(context))
            context = await self._handle_cancellation(context, started, uncertain=False)
            raise GovernanceCancelledError(context) from exc
        claim: IdempotencyClaim | None = None
        prepared_action: UnknownAction | None = None
        heartbeat_task: asyncio.Task[None] | None = None
        tool_returned = False
        execution_started = False
        try:
            if (
                context.execution_mode is ExecutionMode.IDEMPOTENT
                and context.idempotency_key
            ):
                fingerprint = self._idempotency_fingerprint(
                    context, spec.name, normalized_parameters
                )
                namespace = self._idempotency_namespace(context)
                if self._supports_atomic_reconciliation_preparation():
                    prepared_action = self._prepared_unknown_action(
                        spec,
                        context,
                        execution_record_id=new_execution_record_id(),
                        action_digest=fingerprint,
                        namespace=namespace,
                    )
                try:
                    claim = await self._acquire_idempotency(
                        namespace,
                        context.idempotency_key,
                        fingerprint,
                        context.deadline,
                        prepared_action=prepared_action,
                    )
                except IdempotencyConflictError as exc:
                    decision = DecisionRecord(
                        DecisionOutcome.DENY, str(exc), "idempotency"
                    )
                    context = context.with_decision(decision).append_history(
                        HistoryEntry("idempotency", "deny", str(exc))
                    )
                    context = await self._release_approvals(context)
                    context = await self._run_observers(context, post=True)
                    raise GovernanceDenied(context) from exc
                if not claim.owner:
                    timeout = self._bounded_timeout(
                        context.deadline,
                        self.limits.execution_timeout_seconds,
                        "idempotency wait",
                    )
                    value = await self._await_runtime_stage(
                        asyncio.shield(asyncio.wrap_future(claim.future)),
                        stage="idempotency wait",
                        timeout_seconds=timeout,
                        cancellation_grace_seconds=(
                            self.limits.cancellation_grace_seconds
                        ),
                    )
                    value = self._normalize_result(
                        spec, value, context.bound_action
                    )
                    self._enforce_size_limit("result", value, spec.max_result_bytes)
                    context = await self._commit_approvals(context)
                    context = self._enforce_required_approval(context)
                    if context.denied:
                        context = await self._run_observers(context, post=True)
                        raise GovernanceDenied(context)
                    metadata = {
                        **context.metadata,
                        "duration_ms": (perf_counter() - started) * 1000,
                    }
                    context = context.evolve(
                        status=ExecutionStatus.SUCCEEDED,
                        result=value,
                        metadata=metadata,
                    ).append_history(
                        HistoryEntry("idempotency", "cached", "reused completed result")
                    )
                    context = await self._emit_hook(
                        HookPoint.AFTER_EXECUTE, context, allow_critical=False
                    )
                    context = await self._run_observers(context, post=True)
                    return RunResult(value=value, context=context)
                if claim.execution_record_id is not None:
                    context = context.evolve(
                        metadata={
                            **context.metadata,
                            "execution_record_id": claim.execution_record_id,
                        }
                    )
                context = await self._commit_approvals(context)
                context = self._enforce_required_approval(context)
                if context.denied:
                    denial = GovernanceDenied(context)
                    await self._finish_idempotency(
                        claim, context, denial, spec=spec
                    )
                    claim = None
                    context = await self._run_observers(context, post=True)
                    raise denial
                if (
                    isinstance(self.reconciliation_ledger, SQLiteReconciliationLedger)
                    and prepared_action is None
                ):
                    # Compatibility path for non-co-located development adapters.
                    # Production sealing requires the atomic store/ledger path above.
                    prepared_action = self._unknown_action(spec, context, claim)
                    await self._run_reconciliation_operation(
                        self.reconciliation_ledger.prepare_action,
                        claim,
                        prepared_action,
                        deadline=context.deadline,
                        stage="reconciliation prepare action",
                    )
                heartbeat_task = self._start_idempotency_heartbeat(claim)
            else:
                context = await self._commit_approvals(context)
                context = self._enforce_required_approval(context)
                if context.denied:
                    context = await self._run_observers(context, post=True)
                    raise GovernanceDenied(context)

            async def execute_tool(
                current: ExecutionContext,
            ) -> tuple[ExecutionContext, Any]:
                nonlocal execution_started

                try:
                    current = validate_middleware_transition(
                        context, current, MiddlewareKind.EXECUTION
                    )
                except ContextMutationError as exc:
                    decision = DecisionRecord(
                        DecisionOutcome.DENY,
                        f"execution middleware boundary rejected context: {exc}",
                        "runtime",
                    )
                    denied = context.with_decision(decision).append_history(
                        HistoryEntry("runtime", "deny", decision.reason)
                    )
                    raise GovernanceDenied(denied) from exc
                current = self._enforce_required_approval(current)
                if current.denied:
                    raise GovernanceDenied(current)
                current = await self._revalidate_bound_action(
                    spec,
                    current,
                    execution_args,
                    execution_kwargs,
                )

                def mark_started() -> None:
                    nonlocal execution_started
                    execution_started = True

                with self._execution_scopes(current):
                    if inspect.iscoroutinefunction(spec.function):
                        value = await self._run_async_tool(
                            spec.function,
                            execution_args,
                            execution_kwargs,
                            current.deadline,
                            mark_started,
                        )
                    else:
                        value = await self._run_sync_tool(
                            spec.function,
                            execution_args,
                            execution_kwargs,
                            current.deadline,
                            mark_started,
                        )
                        if inspect.isawaitable(value):
                            value = await value
                return current, value

            call: ExecutionCall = execute_tool
            execution_middlewares = [
                item for item in self.pipeline if item.kind is MiddlewareKind.EXECUTION
            ]
            for middleware in reversed(execution_middlewares):
                next_call = call

                async def wrapped(
                    current: ExecutionContext,
                    *,
                    current_middleware: ExecutionMiddleware = middleware,
                    call_next: ExecutionCall = next_call,
                ) -> tuple[ExecutionContext, Any]:
                    candidate, value = await current_middleware.execute(
                        current, call_next
                    )
                    return (
                        validate_middleware_transition(
                            current,
                            candidate,
                            MiddlewareKind.EXECUTION,
                        ),
                        value,
                    )

                call = wrapped
            context, value = await self._with_deadline(context, call)
            tool_returned = True
            value = self._normalize_result(spec, value, context.bound_action)
            self._enforce_size_limit("result", value, spec.max_result_bytes)
            await self._stop_idempotency_heartbeat(
                heartbeat_task, raise_on_failure=True
            )
            heartbeat_task = None
            await self._finish_idempotency(claim, context, None, value, spec=spec)
            claim = None
        except ExecutionControlError as exc:
            await self._stop_idempotency_heartbeat(
                heartbeat_task, raise_on_failure=False
            )
            context = exc.context
            cause = exc.cause
            context = self._failed_context(
                context,
                cause,
                started,
                uncertain=(
                    tool_returned
                    and context.execution_mode is not ExecutionMode.READ_ONLY
                )
                or (
                    execution_started
                    and context.execution_mode is ExecutionMode.MUTATING
                ),
            )
            context = await self._settle_idempotency(
                claim, context, cause, spec=spec
            )
            context = await self._emit_hook(
                HookPoint.ON_ERROR, context, allow_critical=False
            )
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, cause) from cause
        except GovernanceDenied as exc:
            await self._stop_idempotency_heartbeat(
                heartbeat_task, raise_on_failure=False
            )
            context = await self._settle_idempotency(
                claim, exc.context, exc, spec=spec
            )
            claim = None
            context = await self._run_observers(context, post=True)
            raise GovernanceDenied(context) from exc
        except asyncio.CancelledError as exc:
            await asyncio.shield(
                self._stop_idempotency_heartbeat(heartbeat_task, raise_on_failure=False)
            )
            context = await self._handle_cancellation(
                context,
                started,
                uncertain=execution_started,
                claim=claim,
                spec=spec,
            )
            raise GovernanceCancelledError(context) from exc
        except Exception as exc:
            if not execution_started:
                context = await self._release_approvals(context)
            await self._stop_idempotency_heartbeat(
                heartbeat_task, raise_on_failure=False
            )
            context = self._failed_context(
                context,
                exc,
                started,
                uncertain=(
                    tool_returned
                    and context.execution_mode is not ExecutionMode.READ_ONLY
                )
                or (
                    execution_started
                    and context.execution_mode is ExecutionMode.MUTATING
                ),
            )
            context = await self._settle_idempotency(
                claim, context, exc, spec=spec
            )
            context = await self._emit_hook(
                HookPoint.ON_ERROR, context, allow_critical=False
            )
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, exc) from exc

        metadata = {
            **context.metadata,
            "duration_ms": (perf_counter() - started) * 1000,
        }
        context = context.evolve(
            status=ExecutionStatus.SUCCEEDED,
            result=value,
            metadata=metadata,
        ).append_history(HistoryEntry("executor", "succeeded", "tool completed"))
        try:
            context = await self._emit_hook(
                HookPoint.AFTER_EXECUTE, context, allow_critical=False
            )
            context = await self._run_observers(context, post=True)
        except asyncio.CancelledError as exc:
            context = await self._handle_cancellation(context, started, uncertain=True)
            raise GovernanceCancelledError(context) from exc
        return RunResult(value=value, context=context)

    async def apreview(
        self,
        name: str,
        *args: Any,
        _governance: InvocationOptions | None = None,
        replayable_only: bool = True,
        **kwargs: Any,
    ) -> ExecutionContext:
        operation = self._begin_active_operation()
        try:
            return await self._apreview(
                name,
                *args,
                _governance=_governance,
                replayable_only=replayable_only,
                **kwargs,
            )
        finally:
            self._end_active_operation(operation)

    async def _apreview(
        self,
        name: str,
        *args: Any,
        _governance: InvocationOptions | None = None,
        replayable_only: bool = True,
        **kwargs: Any,
    ) -> ExecutionContext:
        """Evaluate governance without executing the tool."""
        self._assert_accepting_work()
        if self._production_profile is not None and not self._production_sealed:
            raise ProductionReadinessError(self.production_readiness())
        spec = self.registry.get(name)
        context = await self._create_context(spec, args, kwargs, _governance)
        started = perf_counter()
        try:
            normalized_parameters = self._prepare_parameters(
                spec, args, kwargs, context.deadline
            )
            context = await self._bind_action(
                spec, context, normalized_parameters
            )
        except _ActionBindingError as exc:
            context = self._deny_action_binding(context, str(exc))
            return await self._run_observers(context, post=True)
        except (ContractValidationError, StageTimeoutError, ValueError) as exc:
            context = self._failed_context(context, exc, started)
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, exc) from exc
        context = self._enforce_idempotency_key(context)
        if context.denied:
            return await self._run_observers(context, post=True)
        try:
            context = await self._emit_hook(
                HookPoint.BEFORE_PIPELINE, context, allow_critical=True
            )
            if not context.denied:
                context = await self._run_pre_pipeline(
                    context, replayable_only=replayable_only
                )
            if not context.denied:
                context = await self._emit_hook(
                    HookPoint.AFTER_PIPELINE, context, allow_critical=True
                )
            context = self._enforce_required_approval(context)
            return await self._release_approvals(context)
        except asyncio.CancelledError as exc:
            context = await asyncio.shield(self._release_approvals(context))
            context = await self._handle_cancellation(context, started, uncertain=False)
            raise GovernanceCancelledError(context) from exc

    async def areplay(self, context: ExecutionContext) -> ExecutionContext:
        operation = self._begin_active_operation()
        try:
            return await self._areplay(context)
        finally:
            self._end_active_operation(operation)

    async def _areplay(self, context: ExecutionContext) -> ExecutionContext:
        """Reapply deterministic middleware as non-authoritative analysis.

        Replay never executes a tool or creates an executor-authoritative
        ``BoundAction`` from persisted identity fields. Use :meth:`apreview`
        with current trusted identity claims when a fresh action binding is
        required.
        """
        self._assert_accepting_work()
        if self._production_profile is not None and not self._production_sealed:
            raise ProductionReadinessError(self.production_readiness())
        spec = self.registry.get(context.tool_call.name)
        clean = context.reset_for_replay(
            risk_tier=spec.risk,
            requires_approval=spec.requires_approval,
            execution_mode=spec.execution_mode,
        )
        clean = clean.evolve(
            metadata={
                **clean.metadata,
                "replay_mode": "analysis",
                "replay_authoritative": False,
            }
        )
        try:
            self._prepare_parameters(
                spec,
                clean.tool_call.args,
                dict(clean.tool_call.kwargs),
                clean.deadline,
            )
        except (ContractValidationError, StageTimeoutError, ValueError):
            reason = "replay.parameter_validation_failed"
            decision = DecisionRecord(DecisionOutcome.DENY, reason, "replay")
            return clean.with_decision(decision).append_history(
                HistoryEntry("replay", "deny", reason)
            )
        # Parameter preparation is retained so analysis sees the same defaults
        # and contract validation as admission. Persisted identity metadata is
        # intentionally insufficient to mint a new BoundAction.
        clean = self._enforce_idempotency_key(clean)
        if clean.denied:
            return clean
        replayed = await self._run_pre_pipeline(clean, replayable_only=True)
        return self._enforce_required_approval(replayed)

    async def areconcile(
        self,
        execution_record_id: str,
        *,
        identity_claims: Mapping[str, Any] | None = None,
        deadline: datetime | None = None,
    ) -> ReconciliationHead:
        """Run one tracked explicit reconciliation workflow for UNKNOWN work."""

        workflow = self._begin_reconciliation_workflow()
        try:
            return await self._areconcile(
                execution_record_id,
                identity_claims=identity_claims,
                deadline=deadline,
            )
        finally:
            self._end_reconciliation_workflow(workflow)

    async def _areconcile(
        self,
        execution_record_id: str,
        *,
        identity_claims: Mapping[str, Any] | None = None,
        deadline: datetime | None = None,
    ) -> ReconciliationHead:
        """Run one explicit, read-only reconciliation attempt for UNKNOWN work."""

        self._assert_accepting_work()
        if self.production_profile is not None and not self._production_sealed:
            raise ProductionReadinessError(self.production_readiness())
        ledger = self.reconciliation_ledger
        if ledger is None:
            raise ReconciliationNotFoundError("reconciliation ledger is not configured")
        principal = await self._verify_reconciliation_principal(
            identity_claims,
            deadline=deadline,
            operation="probe",
        )

        async def read_head_with_audit(
            *,
            event_type: str | None = None,
            provider: ProviderDescriptor | None = None,
            attempt_id: str | None = None,
            outcome: ReconciliationAttemptOutcome | None = None,
            finding: ReconciliationFinding | None = None,
        ) -> ReconciliationHead:
            current = await self._run_reconciliation_operation(
                ledger.current,
                execution_record_id,
                deadline=deadline,
                stage="reconciliation read head",
            )
            if event_type is not None:
                await self._write_reconciliation_audit(
                    current,
                    event_type=event_type,
                    provider=provider,
                    attempt_id=attempt_id,
                    outcome=outcome,
                    finding=finding,
                    deadline=deadline,
                )
            return current

        head = await self._run_reconciliation_operation(
            ledger.current,
            execution_record_id,
            deadline=deadline,
            stage="reconciliation read head",
        )
        self._assert_reconciliation_tenant_access(principal, head.action)
        if isinstance(ledger, SQLiteReconciliationLedger):
            await self._drain_reconciliation_audit_outbox(
                ledger,
                execution_record_id=execution_record_id,
                deadline=deadline,
            )
        if head.state is not ReconciliationState.UNKNOWN:
            return head
        recovered = await self._run_reconciliation_operation(
            ledger.recover_unfinished_attempts,
            execution_record_id,
            deadline=deadline,
            stage="reconciliation recover unfinished attempt",
        )
        if recovered is not None:
            if recovered.revision != head.revision:
                await self._write_reconciliation_audit(
                    recovered,
                    event_type="recovery_transition_recorded",
                    deadline=deadline,
                )
            return recovered
        # A concurrent runtime may have finalized or quarantined the action
        # after the first read but before its recovery check. Re-read before a
        # new provider invocation so a stale UNKNOWN head cannot start another
        # durable probe attempt.
        head = await self._run_reconciliation_operation(
            ledger.current,
            execution_record_id,
            deadline=deadline,
            stage="reconciliation read head after recovery check",
        )
        self._assert_reconciliation_tenant_access(principal, head.action)
        if head.state is not ReconciliationState.UNKNOWN:
            return head
        provider, unavailable_reason = self._provider_for_reconciliation_action(
            head.action
        )
        attempt_timeout = self._bounded_timeout(
            deadline,
            self.limits.reconciliation_provider_timeout_seconds,
            "reconciliation provider",
        )
        attempt = ReconciliationAttemptContext(
            attempt_id=uuid4().hex,
            deadline=datetime.now(timezone.utc) + timedelta(seconds=attempt_timeout),
            protocol_version=("1" if provider is None else provider.protocol_version),
            action=head.action,
        )
        descriptor = provider or self._unavailable_provider_descriptor()
        started = await self._run_reconciliation_operation(
            ledger.start_attempt,
            attempt,
            descriptor,
            head.revision,
            deadline=deadline,
            stage="reconciliation start attempt",
        )
        if provider is None:
            await self._finalize_reconciliation_attempt(
                ledger,
                attempt,
                descriptor,
                ReconciliationAttemptOutcome.UNAVAILABLE,
                started.revision,
                error=(
                    unavailable_reason
                    or "no trusted reconciliation provider is registered for this tool"
                ),
            )
            return await read_head_with_audit(
                event_type="attempt_finished",
                provider=descriptor,
                attempt_id=attempt.attempt_id,
                outcome=ReconciliationAttemptOutcome.UNAVAILABLE,
            )

        try:
            finding = await self._invoke_reconciliation_provider(provider, attempt)
            if not isinstance(finding, ReconciliationFinding):
                raise TypeError("reconciliation provider must return ReconciliationFinding")
        except asyncio.CancelledError:
            await self._finalize_reconciliation_attempt(
                ledger,
                attempt,
                provider,
                ReconciliationAttemptOutcome.CANCELLED,
                started.revision,
                error="reconciliation caller cancelled the provider attempt",
            )
            raise
        except StageTimeoutError as exc:
            await self._finalize_reconciliation_attempt(
                ledger,
                attempt,
                provider,
                ReconciliationAttemptOutcome.TIMEOUT,
                started.revision,
                error=f"{type(exc).__name__}: provider deadline elapsed",
            )
            return await read_head_with_audit(
                event_type="attempt_finished",
                provider=provider,
                attempt_id=attempt.attempt_id,
                outcome=ReconciliationAttemptOutcome.TIMEOUT,
            )
        except ReconciliationConflictError as exc:
            await self._finalize_reconciliation_attempt(
                ledger,
                attempt,
                provider,
                ReconciliationAttemptOutcome.UNAVAILABLE,
                started.revision,
                error=f"{type(exc).__name__}: provider is unavailable",
            )
            return await read_head_with_audit(
                event_type="attempt_finished",
                provider=provider,
                attempt_id=attempt.attempt_id,
                outcome=ReconciliationAttemptOutcome.UNAVAILABLE,
            )
        except Exception as exc:
            await self._finalize_reconciliation_attempt(
                ledger,
                attempt,
                provider,
                ReconciliationAttemptOutcome.ERROR,
                started.revision,
                error=f"{type(exc).__name__}: provider did not return a conclusion",
            )
            return await read_head_with_audit(
                event_type="attempt_finished",
                provider=provider,
                attempt_id=attempt.attempt_id,
                outcome=ReconciliationAttemptOutcome.ERROR,
            )

        finished = await self._finalize_reconciliation_attempt(
            ledger,
            attempt,
            provider,
            ReconciliationAttemptOutcome.SUCCESS,
            started.revision,
            finding=finding,
        )
        if finished is None:
            # A CAS loss has no durable reconciliation mutation. Do not emit a
            # synthetic audit event that cannot be replayed from the ledger.
            return await read_head_with_audit()
        try:
            transitioned = await self._run_reconciliation_operation(
                ledger.compare_and_append_transition,
                execution_record_id,
                ReconciliationState.UNKNOWN,
                finished.revision,
                finding,
                provider=provider,
                attempt_id=attempt.attempt_id,
                deadline=deadline,
                stage="reconciliation append transition",
            )
            await self._write_reconciliation_audit(
                transitioned,
                event_type="transition_recorded",
                provider=provider,
                attempt_id=attempt.attempt_id,
                outcome=ReconciliationAttemptOutcome.SUCCESS,
                finding=finding,
                deadline=deadline,
            )
            return transitioned
        except ReconciliationConflictError:
            # See the matching finish-conflict path above: only committed
            # ledger mutations enter the transactional audit outbox.
            return await read_head_with_audit()

    async def adrain_reconciliation_audit_outbox(
        self,
        *,
        limit: int = 128,
        identity_claims: Mapping[str, Any] | None = None,
        deadline: datetime | None = None,
    ) -> int:
        """Run one tracked global audit-recovery workflow."""

        workflow = self._begin_reconciliation_workflow()
        try:
            return await self._adrain_reconciliation_audit_outbox(
                limit=limit,
                identity_claims=identity_claims,
                deadline=deadline,
            )
        finally:
            self._end_reconciliation_workflow(workflow)

    async def _adrain_reconciliation_audit_outbox(
        self,
        *,
        limit: int,
        identity_claims: Mapping[str, Any] | None,
        deadline: datetime | None,
    ) -> int:
        """Deliver pending audit envelopes for all persisted executions.

        This is the recovery-worker entry point for deployments that need to
        resume durable outbox delivery after a process restart. It executes no
        provider and applies per-execution revision ordering before every sink
        write. Deployment access to this control-plane method must be limited
        to the trusted runtime worker.
        """

        self._assert_accepting_work()
        if self.production_profile is not None and not self._production_sealed:
            raise ProductionReadinessError(self.production_readiness())
        if type(limit) is not int or not 1 <= limit <= 1_000:
            raise ValueError("audit outbox limit must be between 1 and 1000")
        ledger = self.reconciliation_ledger
        if not isinstance(ledger, SQLiteReconciliationLedger):
            raise ReconciliationNotFoundError(
                "a durable SQLite reconciliation ledger is required for audit delivery"
            )
        await self._verify_reconciliation_principal(
            identity_claims,
            deadline=deadline,
            operation="drain",
        )
        return await self._drain_reconciliation_audit_outbox(
            ledger, limit=limit, deadline=deadline
        )

    async def aresolve_reconciliation(
        self,
        execution_record_id: str,
        *,
        expected_state: ReconciliationState,
        expected_revision: int,
        new_state: ReconciliationState,
        reason: str,
        evidence_kind: str,
        evidence: Mapping[str, Any],
        identity_claims: Mapping[str, Any] | None = None,
        retry_safe: bool = False,
        resolved_result_available: bool = False,
        resolved_result: Any = None,
        deadline: datetime | None = None,
    ) -> ReconciliationHead:
        """Run one tracked manual reconciliation workflow."""

        workflow = self._begin_reconciliation_workflow()
        try:
            return await self._aresolve_reconciliation(
                execution_record_id,
                expected_state=expected_state,
                expected_revision=expected_revision,
                new_state=new_state,
                reason=reason,
                evidence_kind=evidence_kind,
                evidence=evidence,
                identity_claims=identity_claims,
                retry_safe=retry_safe,
                resolved_result_available=resolved_result_available,
                resolved_result=resolved_result,
                deadline=deadline,
            )
        finally:
            self._end_reconciliation_workflow(workflow)

    async def _aresolve_reconciliation(
        self,
        execution_record_id: str,
        *,
        expected_state: ReconciliationState,
        expected_revision: int,
        new_state: ReconciliationState,
        reason: str,
        evidence_kind: str,
        evidence: Mapping[str, Any],
        identity_claims: Mapping[str, Any] | None = None,
        retry_safe: bool = False,
        resolved_result_available: bool = False,
        resolved_result: Any = None,
        deadline: datetime | None = None,
    ) -> ReconciliationHead:
        """Apply a verified operator decision to a MANUAL_REVIEW execution."""

        self._assert_accepting_work()
        if self.production_profile is not None and not self._production_sealed:
            raise ProductionReadinessError(self.production_readiness())
        ledger = self.reconciliation_ledger
        if ledger is None:
            raise ReconciliationNotFoundError("reconciliation ledger is not configured")
        profile = self.production_profile
        principal = await self._verify_reconciliation_principal(
            identity_claims,
            deadline=deadline,
            operation="resolve",
        )
        if (
            profile is None
            or profile.identity_digest_key_provider is None
            or profile.identity_digest_key_version is None
        ):
            raise PermissionError(
                "manual reconciliation requires a production identity digest key"
            )
        if principal is None:
            raise PermissionError("manual reconciliation requires a trusted identity provider")
        current = await self._run_reconciliation_operation(
            ledger.current,
            execution_record_id,
            deadline=deadline,
            stage="reconciliation read head",
        )
        self._assert_reconciliation_tenant_access(principal, current.action)
        key = await self._call_binding_provider(
            profile.identity_digest_key_provider.get_key,
            stage="manual reconciliation identity digest key",
            deadline=deadline,
            tenant=principal.tenant,
            version=profile.identity_digest_key_version,
        )
        if not isinstance(key, bytes):
            raise PermissionError("identity digest key provider returned invalid key data")
        operator_digest = hmac.new(
            key,
            canonical_json_bytes(
                {
                    "domain": "arg.reconciliation-operator",
                    "version": 1,
                    "issuer": principal.issuer,
                    "subject": principal.subject,
                    "tenant": principal.tenant,
                },
                label="manual reconciliation operator",
            ),
            hashlib.sha256,
        ).hexdigest()
        resolution = ManualResolution(
            execution_record_id=execution_record_id,
            operator_identity_digest=operator_digest,
            reason=reason,
            expected_state=expected_state,
            expected_revision=expected_revision,
            new_state=new_state,
            resolved_at=datetime.now(timezone.utc),
            evidence_kind=evidence_kind,
            evidence=evidence,
            retry_safe=retry_safe,
            resolved_result_available=resolved_result_available,
            resolved_result=resolved_result,
        )
        head = await self._run_reconciliation_operation(
            ledger.compare_and_append_transition,
            execution_record_id,
            expected_state,
            expected_revision,
            resolution,
            deadline=deadline,
            stage="reconciliation manual resolution",
        )
        await self._write_reconciliation_audit(
            head,
            event_type="manual_transition_recorded",
            evidence_kind=resolution.evidence_kind,
            evidence=resolution.evidence,
            operator_identity_digest=operator_digest,
            deadline=deadline,
        )
        return head

    async def _verify_reconciliation_principal(
        self,
        identity_claims: Mapping[str, Any] | None,
        *,
        deadline: datetime | None,
        operation: str,
    ) -> VerifiedPrincipal | None:
        """Verify control-plane callers whenever identity enforcement is enabled."""

        profile = self.production_profile
        if profile is None and not self.require_verified_identity:
            return None
        if self.identity_provider is None:
            raise PermissionError("reconciliation requires a trusted identity provider")
        try:
            principal = await self._invoke_identity_provider(identity_claims, deadline)
        except StageTimeoutError:
            # Deadline expiry is operationally distinct from a denied identity
            # and must not create an attempt or fall through to ledger work.
            raise
        except Exception as exc:
            raise PermissionError("reconciliation authorization denied") from exc
        if not isinstance(principal, VerifiedPrincipal):
            raise PermissionError("reconciliation authorization denied")
        if operation not in {"probe", "resolve", "drain"}:
            raise RuntimeError(f"unsupported reconciliation operation {operation!r}")
        authorization_profile = profile or ProductionProfile()
        required_permission = {
            "probe": authorization_profile.reconciliation_probe_permission,
            "resolve": authorization_profile.reconciliation_resolve_permission,
            "drain": authorization_profile.reconciliation_audit_drain_permission,
        }[operation]
        if required_permission not in principal.permissions:
            raise PermissionError("reconciliation authorization denied")
        return principal

    @staticmethod
    def _assert_reconciliation_tenant_access(
        principal: VerifiedPrincipal | None,
        action: UnknownAction,
    ) -> None:
        if principal is None:
            return
        expected = action.tenant_partition_digest
        # Earlier pre-release records encoded an absent tenant as the digest of
        # "global". That value is indistinguishable from a real legacy global
        # tenant, so deny the ambiguous case rather than authorizing an
        # unbound record. New runtime-created actions persist ``None`` when no
        # tenant is bound and explicitly mark bound partitions in metadata.
        if (
            expected is not None
            and principal.tenant == "global"
            and action.metadata.get(_TENANT_PARTITION_BOUND_METADATA_KEY) is not True
        ):
            raise PermissionError("reconciliation authorization denied")
        actual = tenant_partition_digest(principal.tenant)
        if expected is None or not hmac.compare_digest(expected, actual):
            raise PermissionError("reconciliation authorization denied")

    @staticmethod
    def _unavailable_provider_descriptor() -> ProviderDescriptor:
        async def unavailable(
            _context: ReconciliationAttemptContext,
        ) -> ReconciliationFinding:
            raise RuntimeError("unavailable provider sentinel must not be called")

        return ProviderDescriptor(
            provider_id="runtime.unavailable",
            protocol_version="1",
            supported_evidence_kinds=("runtime",),
            provider=unavailable,
        )

    def _provider_for_reconciliation_action(
        self, action: UnknownAction
    ) -> tuple[ProviderDescriptor | None, str | None]:
        """Return only the provider durably bound to an UNKNOWN action.

        A restarted runtime may register a tool with the same name but a
        different reconciliation implementation.  That configuration drift
        must never authorize a new external probe for a persisted action.
        """

        try:
            spec = self.registry.get(action.tool_name)
        except RegistryError:
            return None, "the tool registered for this unresolved action is unavailable"

        contract = spec.action_contract
        contract_id = (
            contract.contract_id if contract is not None else f"runtime.{spec.name}"
        )
        contract_version = contract.contract_version if contract is not None else 1
        if (
            spec.execution_mode is not ExecutionMode.IDEMPOTENT
            or contract_id != action.contract_id
            or contract_version != action.contract_version
        ):
            return None, "the registered tool identity no longer matches this unresolved action"

        provider = spec.reconciliation_provider
        if action.reconciliation_provider_id is None:
            if provider is None:
                return None, None
            return (
                None,
                "the unresolved action has no persisted reconciliation provider binding",
            )
        if provider is None:
            return None, "the persisted reconciliation provider is not registered"
        if (
            provider.provider_id != action.reconciliation_provider_id
            or provider.protocol_version != action.reconciliation_protocol_version
            or provider.supported_evidence_kinds
            != action.reconciliation_supported_evidence_kinds
        ):
            return (
                None,
                "the registered reconciliation provider does not match the unresolved action",
            )
        return provider, None

    async def _write_reconciliation_audit(
        self,
        head: ReconciliationHead,
        *,
        event_type: str,
        provider: ProviderDescriptor | None = None,
        attempt_id: str | None = None,
        outcome: ReconciliationAttemptOutcome | None = None,
        finding: ReconciliationFinding | None = None,
        evidence_kind: str | None = None,
        evidence: Mapping[str, Any] | None = None,
        operator_identity_digest: str | None = None,
        deadline: datetime | None = None,
    ) -> None:
        ledger = self.reconciliation_ledger
        if isinstance(ledger, SQLiteReconciliationLedger):
            await self._drain_reconciliation_audit_outbox(
                ledger,
                execution_record_id=head.execution_record_id,
                deadline=deadline,
            )
            return
        middleware = next(
            (
                item
                for item in self.pipeline
                if isinstance(item, AuditMiddleware)
            ),
            None,
        )
        if middleware is None:
            return
        event = reconciliation_event(
            head,
            event_type=event_type,
            provider=provider,
            attempt_id=attempt_id,
            outcome=None if outcome is None else outcome.value,
            evidence_kind=(
                finding.evidence_kind if finding is not None else evidence_kind
            ),
            evidence=finding.evidence if finding is not None else evidence,
            operator_identity_digest=operator_identity_digest,
        )
        try:
            await self._run_reconciliation_audit_delivery(
                middleware.sink.write,
                event,
                deadline=deadline,
            )
        except Exception:
            if middleware.fail_closed:
                raise

    async def _drain_reconciliation_audit_outbox(
        self,
        ledger: SQLiteReconciliationLedger,
        *,
        execution_record_id: str | None = None,
        limit: int | None = None,
        deadline: datetime | None = None,
    ) -> int:
        """Deliver committed reconciliation audit envelopes in revision order."""

        if limit is not None and (type(limit) is not int or limit < 1):
            raise ValueError("audit outbox limit must be a positive integer")
        middleware = next(
            (item for item in self.pipeline if isinstance(item, AuditMiddleware)),
            None,
        )
        if middleware is None:
            return 0
        delivered = 0
        while limit is None or delivered < limit:
            batch_limit = 128 if limit is None else min(128, limit - delivered)
            envelopes = await self._run_reconciliation_operation(
                ledger.pending_audit_events,
                execution_record_id=execution_record_id,
                limit=batch_limit,
                deadline=deadline,
                stage="reconciliation audit outbox read",
            )
            if not envelopes:
                return delivered
            for envelope in envelopes:
                assert isinstance(envelope, ReconciliationAuditEnvelope)
                event = _thaw(envelope.event)
                event["reconciliation_audit_id"] = envelope.outbox_id
                try:
                    await self._run_reconciliation_audit_delivery(
                        self._deliver_reconciliation_audit_envelope,
                        middleware.sink,
                        envelope.outbox_id,
                        event,
                        deadline=deadline,
                        stage="reconciliation audit delivery",
                    )
                    await self._run_reconciliation_operation(
                        ledger.mark_audit_event_delivered,
                        envelope.outbox_id,
                        deadline=deadline,
                        stage="reconciliation audit acknowledgement",
                    )
                    delivered += 1
                    if limit is not None and delivered >= limit:
                        return delivered
                except asyncio.CancelledError:
                    # Delivery may still be draining in the isolated executor.
                    # The durable outbox remains pending and the caller's
                    # cancellation must not be reclassified as an audit failure
                    # or poison the reconciliation channel.
                    raise
                except Exception as exc:
                    try:
                        await self._run_reconciliation_operation(
                            ledger.record_audit_delivery_failure,
                            envelope.outbox_id,
                            exc,
                            deadline=deadline,
                            stage="reconciliation audit delivery failure record",
                        )
                    except StageTimeoutError:
                        # Caller deadlines are not a storage corruption signal.
                        # The outbox remains pending for a later worker.
                        pass
                    except Exception as recording_error:
                        self._poison_reconciliation(recording_error)
                    if isinstance(exc, StageTimeoutError) and deadline is not None:
                        # A sink may hit its own bounded delivery budget while
                        # the caller still has time remaining. Preserve the
                        # recoverable envelope identity in that case; only an
                        # expired caller deadline is surfaced as a raw stage
                        # timeout to the control-plane caller.
                        try:
                            self._bounded_timeout(
                                deadline,
                                self.limits.reconciliation_audit_delivery_timeout_seconds,
                                "reconciliation audit delivery",
                            )
                        except StageTimeoutError:
                            raise exc
                    if middleware.fail_closed:
                        raise ReconciliationAuditDeliveryPendingError(
                            envelope.execution_record_id, envelope.outbox_id, exc
                        ) from exc
                    return delivered
        return delivered

    @staticmethod
    def _deliver_reconciliation_audit_envelope(
        sink: Any,
        outbox_id: str,
        event: Mapping[str, Any],
    ) -> Any:
        idempotent_writer = getattr(sink, "write_idempotent", None)
        if callable(idempotent_writer):
            return idempotent_writer(outbox_id, event)
        return sink.write(event)

    async def _finalize_reconciliation_attempt(
        self,
        ledger: ReconciliationLedger,
        attempt: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        outcome: ReconciliationAttemptOutcome,
        expected_revision: int,
        *,
        finding: ReconciliationFinding | None = None,
        error: str | None = None,
    ) -> Any | None:
        """Persist a started attempt's terminal event despite caller cancellation.

        Once ``ATTEMPT_STARTED`` is durable, a paired terminal event is an
        integrity requirement rather than optional request work.  The task is
        therefore shielded from the caller and uses a bounded internal budget.
        A background failure is consumed and poisons reconciliation, preventing
        a later caller from treating an incomplete ledger as authoritative.
        """

        task = asyncio.create_task(
            self._finish_reconciliation_attempt(
                ledger,
                attempt,
                provider,
                outcome,
                expected_revision,
                finding=finding,
                error=error,
            ),
            name=f"reconciliation-finalize:{attempt.attempt_id}",
        )
        with self._lifecycle_lock:
            self._reconciliation_finalizers.add(task)
        task.add_done_callback(self._forget_reconciliation_finalizer)
        return await asyncio.shield(task)

    def _forget_reconciliation_finalizer(self, task: asyncio.Task[Any]) -> None:
        with self._lifecycle_lock:
            self._reconciliation_finalizers.discard(task)
        if task.cancelled():
            self._poison_reconciliation(
                RuntimeError("reconciliation finalization was cancelled")
            )
            return
        try:
            task.result()
        except BaseException as exc:
            self._poison_reconciliation(exc)

    async def _finish_reconciliation_attempt(
        self,
        ledger: ReconciliationLedger,
        attempt: ReconciliationAttemptContext,
        provider: ProviderDescriptor,
        outcome: ReconciliationAttemptOutcome,
        expected_revision: int,
        *,
        finding: ReconciliationFinding | None = None,
        error: str | None = None,
    ) -> Any | None:
        deadline = datetime.now(timezone.utc) + timedelta(
            seconds=self.limits.reconciliation_finalization_timeout_seconds
        )
        try:
            return await self._run_reconciliation_operation(
                ledger.finish_attempt,
                attempt,
                provider,
                outcome,
                expected_revision,
                finding=finding,
                error=error,
                deadline=deadline,
                stage="reconciliation finish attempt",
            )
        except ReconciliationConflictError:
            # A CAS conflict is normal only when another writer demonstrably
            # advanced the durable head. Treating an unchanged head as a
            # harmless conflict would leave this started attempt unpaired and
            # permit a restart to re-probe it.
            self._raise_if_reconciliation_poisoned()
            current = await self._run_reconciliation_operation(
                ledger.current,
                attempt.action.execution_record_id,
                deadline=deadline,
                stage="reconciliation verify finalization conflict",
            )
            if (
                current.state is not ReconciliationState.UNKNOWN
                or current.revision > expected_revision
            ):
                return None
            raise

    async def _invoke_reconciliation_provider(
        self,
        provider: ProviderDescriptor,
        attempt: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        self._raise_if_reconciliation_provider_available(provider.provider_id)
        callback = getattr(provider.provider, "reconcile", provider.provider)
        candidate = callback(attempt)
        if not inspect.isawaitable(candidate):
            raise TypeError("reconciliation provider must return an awaitable")
        task = asyncio.create_task(
            candidate,
            name=(
                f"reconciliation-provider:{provider.provider_id}:{attempt.attempt_id}"
            ),
        )
        with self._lifecycle_lock:
            self._reconciliation_tasks.add(task)
        task.add_done_callback(self._forget_reconciliation_task)
        timeout = self._bounded_timeout(
            attempt.deadline,
            self.limits.reconciliation_provider_timeout_seconds,
            "reconciliation provider",
        )
        try:
            done, _ = await asyncio.wait({task}, timeout=timeout)
            if task in done:
                return task.result()
            timeout_error = StageTimeoutError("reconciliation provider", timeout)
            task.cancel()
            done, _ = await asyncio.wait(
                {task}, timeout=self.limits.cancellation_grace_seconds
            )
            if task not in done:
                self._poison_reconciliation_provider(provider.provider_id, timeout_error)
            raise timeout_error
        except asyncio.CancelledError:
            if not task.done():
                task.cancel()
                done, _ = await asyncio.wait(
                    {task}, timeout=self.limits.cancellation_grace_seconds
                )
                if task not in done:
                    self._poison_reconciliation_provider(
                        provider.provider_id,
                        RuntimeError("reconciliation provider ignored cancellation"),
                    )
            raise

    def _forget_reconciliation_task(self, task: asyncio.Task[Any]) -> None:
        with self._lifecycle_lock:
            self._reconciliation_tasks.discard(task)
        self._consume_background_result(task)

    def _raise_if_reconciliation_provider_available(self, provider_id: str) -> None:
        with self._reconciliation_provider_lock:
            cause = self._reconciliation_provider_poison.get(provider_id)
            draining = provider_id in self._reconciliation_provider_draining
        if cause is not None:
            raise ReconciliationConflictError(
                "reconciliation provider is disabled after a hard deadline breach"
            ) from cause
        if draining:
            raise ReconciliationConflictError(
                "reconciliation provider has a detached task still draining"
            )

    def _poison_reconciliation_provider(
        self, provider_id: str, cause: BaseException
    ) -> None:
        with self._reconciliation_provider_lock:
            self._reconciliation_provider_poison.setdefault(provider_id, cause)

    async def _create_context(
        self,
        spec: ToolSpec[Any, Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        options_value: InvocationOptions | None,
    ) -> ExecutionContext:
        options = options_value or InvocationOptions()
        principal, identity_error = await self._verify_identity(options)
        metadata = _caller_metadata(options.metadata)
        if principal is not None:
            metadata.update(
                {
                    "identity_verified": True,
                    "identity_issuer": principal.issuer,
                    "identity_subject": principal.subject,
                    "identity_source": principal.source,
                    "identity_verified_at": principal.verified_at,
                }
            )
        elif identity_error is not None:
            metadata.update(
                {
                    "identity_verified": False,
                    "identity_error": identity_error,
                }
            )
        if principal is not None:
            user = principal.subject
            tenant = principal.tenant
            permissions = principal.permissions
        elif identity_error is not None:
            user = None
            tenant = None
            permissions = frozenset()
        else:
            user = options.user
            tenant = options.tenant
            permissions = options.permissions
        context = ExecutionContext.create(
            ToolCall(name=spec.name, args=args, kwargs=kwargs),
            input_text=options.input_text,
            request_id=options.request_id,
            user=user,
            tenant=tenant,
            permissions=permissions,
            task_id=options.task_id,
            conversation_id=options.conversation_id,
            execution_mode=spec.execution_mode,
            idempotency_key=options.idempotency_key,
            deadline=options.deadline,
            risk_tier=spec.risk,
            requires_approval=spec.requires_approval,
            metadata=metadata,
        )
        if identity_error is None:
            return context
        decision = DecisionRecord(
            DecisionOutcome.DENY,
            identity_error,
            "identity",
        )
        return context.with_decision(decision).append_history(
            HistoryEntry(
                "identity",
                "deny",
                identity_error,
                data={"verified": False},
            )
        )

    async def _record_admission_failure(
        self,
        spec: ToolSpec[Any, Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        options: InvocationOptions,
        error: CapacityExceededError | StageTimeoutError,
    ) -> None:
        metadata = _caller_metadata(options.metadata)
        identity_pending = (
            self.identity_provider is not None or self.require_verified_identity
        )
        if identity_pending:
            metadata.update(
                {
                    "identity_verified": False,
                    "identity_error": "request rejected before identity verification",
                }
            )
        reason = (
            "capacity_exceeded"
            if isinstance(error, CapacityExceededError)
            else "deadline_exceeded"
        )
        context = ExecutionContext.create(
            ToolCall(name=spec.name, args=args, kwargs=kwargs),
            input_text=options.input_text,
            request_id=options.request_id,
            user=None if identity_pending else options.user,
            tenant=None if identity_pending else options.tenant,
            permissions=frozenset() if identity_pending else options.permissions,
            task_id=options.task_id,
            conversation_id=options.conversation_id,
            execution_mode=spec.execution_mode,
            idempotency_key=options.idempotency_key,
            deadline=options.deadline,
            risk_tier=spec.risk,
            requires_approval=spec.requires_approval,
            metadata=metadata,
        ).evolve(
            status=ExecutionStatus.FAILED,
            error=f"{type(error).__name__}: {error}",
        )
        context = context.append_history(
            HistoryEntry(
                "admission",
                "reject",
                reason,
                data={"error_type": type(error).__name__},
            )
        )
        for middleware in self.pipeline:
            if middleware.kind is not MiddlewareKind.OBSERVING:
                continue
            recorder = getattr(middleware, "record_external_failure", None)
            if not callable(recorder):
                continue
            try:
                recorder("admission", outcome="reject", reason=reason)
            except Exception:
                continue
        try:
            context = await self._run_observers(
                context,
                post=True,
                ignore_deadline=True,
            )
        except AuditDeliveryError as audit_error:
            context = audit_error.context
        error.context = context

    async def _verify_identity(
        self, options: InvocationOptions
    ) -> tuple[VerifiedPrincipal | None, str | None]:
        if self.identity_provider is None:
            if self.require_verified_identity:
                return None, "verified identity is required"
            return None, None
        if options.identity_claims is None:
            try:
                principal = await self._invoke_identity_provider(None, options.deadline)
            except Exception:
                return None, "identity verification failed"
            if not isinstance(principal, VerifiedPrincipal):
                return None, "identity provider returned an invalid principal"
            return principal, None
        try:
            principal = await self._invoke_identity_provider(
                options.identity_claims, options.deadline
            )
        except Exception:
            return None, "identity verification failed"
        if not isinstance(principal, VerifiedPrincipal):
            return None, "identity provider returned an invalid principal"
        return principal, None

    async def _invoke_identity_provider(
        self,
        claims: Mapping[str, Any] | None,
        deadline: datetime | None,
    ) -> VerifiedPrincipal:
        assert self.identity_provider is not None
        timeout = self._bounded_timeout(
            deadline,
            self.limits.middleware_timeout_seconds,
            "identity verification",
        )
        return await self._await_runtime_stage(
            self._invoke_extension(self.identity_provider.verify, claims),
            stage="identity verification",
            timeout_seconds=timeout,
            cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
        )

    async def _with_deadline(
        self, context: ExecutionContext, call: ExecutionCall
    ) -> tuple[ExecutionContext, Any]:
        timeout = self._bounded_timeout(
            context.deadline,
            self.limits.execution_timeout_seconds,
            "tool execution",
        )
        return await self._await_runtime_stage(
            call(context),
            stage="tool execution",
            timeout_seconds=timeout,
            cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
        )

    async def _await_runtime_stage(
        self,
        awaitable: Awaitable[Any],
        *,
        stage: str,
        timeout_seconds: float,
        cancellation_grace_seconds: float,
    ) -> Any:
        """Bound a stage and retain any coroutine that ignores cancellation."""

        return await await_stage(
            awaitable,
            stage=stage,
            timeout_seconds=timeout_seconds,
            cancellation_grace_seconds=cancellation_grace_seconds,
            on_detached=self._track_detached_stage,
        )

    async def _run_blocking_extension(
        self,
        callback: Callable[..., Any],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Run a known-synchronous callback in the owned extension worker pool."""

        return await self._extension_dispatcher.invoke_sync(callback, *args, **kwargs)

    async def _invoke_extension(
        self,
        callback: Callable[..., Any],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Dispatch a third-party adapter through the async-first runtime boundary."""

        return await self._extension_dispatcher.invoke(callback, *args, **kwargs)

    async def _run_sync_tool(
        self,
        function: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        deadline: datetime | None,
        on_submitted: Callable[[], None],
    ) -> Any:
        timeout = self._bounded_timeout(
            deadline,
            self.limits.execution_timeout_seconds,
            "synchronous tool capacity",
        )
        lease = await self._sync_bulkhead.acquire(timeout)
        try:
            inherited_context = copy_context()
            future = self._sync_executor.submit(
                inherited_context.run,
                function,
                *args,
                **kwargs,
            )
        except BaseException:
            lease.release()
            raise
        future.add_done_callback(lambda _future: lease.release())
        self._track_sync_tool_future(future)
        on_submitted()
        return await asyncio.wrap_future(future)

    async def _run_async_tool(
        self,
        function: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        deadline: datetime | None,
        on_submitted: Callable[[], None],
    ) -> Any:
        timeout = self._bounded_timeout(
            deadline,
            self.limits.execution_timeout_seconds,
            "asynchronous tool capacity",
        )
        lease = await self._async_tool_bulkhead.acquire(timeout)
        try:
            task = asyncio.create_task(function(*args, **kwargs))
        except BaseException:
            lease.release()
            raise
        task.add_done_callback(lambda _task: lease.release())
        on_submitted()
        return await task

    @contextmanager
    def _execution_scopes(self, context: ExecutionContext):
        with ExitStack() as stack:
            for middleware in self.pipeline:
                factory = getattr(middleware, "execution_scope", None)
                if callable(factory):
                    stack.enter_context(factory(context.trace_id))
            yield

    @staticmethod
    def _bounded_timeout(
        deadline: datetime | None, configured: float, stage: str
    ) -> float:
        if deadline is None:
            return configured
        if (
            not isinstance(deadline, datetime)
            or deadline.tzinfo is None
            or deadline.utcoffset() is None
        ):
            raise ValueError("deadline must be timezone-aware")
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise StageTimeoutError(stage, 0.0)
        return min(configured, remaining)

    @classmethod
    def _enforce_size_limit(cls, label: str, value: Any, limit: int | None) -> None:
        if limit is None:
            return
        actual = len(canonical_json_bytes(value, label=label))
        if actual > limit:
            verb = "exceeds" if label == "result" else "exceed"
            raise ValueError(f"{label} {verb} {limit} bytes ({actual} bytes)")

    def _prepare_parameters(
        self,
        spec: ToolSpec[Any, Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        deadline: datetime | None,
    ) -> dict[str, Any]:
        # Validate the absolute deadline even for an empty middleware pipeline.
        self._bounded_timeout(
            deadline, self.limits.middleware_timeout_seconds, "request"
        )
        bound_parameters = bind_arguments(spec.function, args, kwargs)
        if (
            spec.parameters_schema is not None
            or spec.max_parameters_bytes is not None
            or spec.execution_mode is ExecutionMode.IDEMPOTENT
        ):
            normalized = validate_instance(
                bound_parameters,
                spec.parameters_schema,
                label="parameters",
            )
        else:
            normalized = bound_parameters
        self._enforce_size_limit("parameters", normalized, spec.max_parameters_bytes)
        return normalized

    async def _bind_action(
        self,
        spec: ToolSpec[Any, Any],
        context: ExecutionContext,
        parameters: Mapping[str, Any],
    ) -> ExecutionContext:
        if spec.action_contract is None or context.denied:
            return context
        try:
            action = await self._build_bound_action(spec, context, parameters)
            return context.bind_action(action).evolve(
                metadata={
                    **context.metadata,
                    "policy_version": action.policy_version,
                    "policy_digest": action.policy_digest,
                }
            )
        except (ContractValidationError, TypeError, ValueError, StageTimeoutError) as exc:
            raise _ActionBindingError("action.binding_failed") from exc
        except Exception as exc:
            raise _ActionBindingError("action.binding_provider_failed") from exc

    async def _build_bound_action(
        self,
        spec: ToolSpec[Any, Any],
        context: ExecutionContext,
        parameters: Mapping[str, Any],
    ) -> BoundAction:
        contract = spec.action_contract
        profile = self.production_profile
        if contract is None:
            raise ValueError("action contract is not configured")
        if profile is None:
            raise ValueError("production profile is required for contracted tools")
        key_provider = profile.identity_digest_key_provider
        key_version = profile.identity_digest_key_version
        issuer = _metadata_text(context.metadata, "identity_issuer")
        if (
            key_provider is None
            or key_version is None
            or profile.policy_version is None
            or profile.policy_digest is None
            or issuer is None
            or context.user is None
            or context.tenant is None
        ):
            raise ValueError("contract binding prerequisites are unavailable")
        key = await self._call_binding_provider(
            key_provider.get_key,
            stage="identity digest key",
            deadline=context.deadline,
            tenant=context.tenant,
            version=key_version,
        )
        precondition_digest: str | None = None
        if contract.precondition_requirements:
            provider = profile.precondition_digest_provider
            if provider is None:
                raise ValueError("precondition digest provider is required")
            precondition_digest = await self._call_binding_provider(
                provider.get_digest,
                stage="action precondition",
                deadline=context.deadline,
                contract=contract,
                parameters=parameters,
                principal=context.user,
                tenant=context.tenant,
            )
        return contract.bind(
            parameters,
            identity_issuer=issuer,
            principal=context.user,
            tenant=context.tenant,
            identity_digest_key=key,
            identity_digest_key_version=key_version,
            policy_version=profile.policy_version,
            policy_digest=profile.policy_digest,
            precondition_digest=precondition_digest,
        )

    async def _call_binding_provider(
        self,
        callback: Callable[..., Any],
        *,
        stage: str,
        deadline: datetime | None,
        **kwargs: Any,
    ) -> Any:
        timeout = self._bounded_timeout(
            deadline,
            self.limits.middleware_timeout_seconds,
            stage,
        )
        return await self._await_runtime_stage(
            self._invoke_extension(callback, **kwargs),
            stage=stage,
            timeout_seconds=timeout,
            cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
        )

    async def _revalidate_bound_action(
        self,
        spec: ToolSpec[Any, Any],
        context: ExecutionContext,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> ExecutionContext:
        expected = context.bound_action
        if expected is None:
            return context
        try:
            actual_parameters = self._prepare_parameters(
                spec, args, kwargs, context.deadline
            )
            actual = await self._build_bound_action(
                spec, context, _thaw(actual_parameters)
            )
        except Exception as exc:
            denied = self._deny_action_binding(
                context, "action.executor_revalidation_failed"
            )
            raise GovernanceDenied(denied) from exc
        if actual.action_digest != expected.action_digest:
            denied = self._deny_action_binding(
                context, "action.executor_digest_mismatch"
            )
            raise GovernanceDenied(denied)
        return context

    @staticmethod
    def _deny_action_binding(
        context: ExecutionContext, reason: str
    ) -> ExecutionContext:
        decision = DecisionRecord(DecisionOutcome.DENY, reason, "action_contract")
        return context.with_decision(decision).append_history(
            HistoryEntry(
                "action_contract",
                "deny",
                reason,
                data={
                    "action_digest": (
                        context.bound_action.action_digest
                        if context.bound_action is not None
                        else None
                    )
                },
            )
        )

    @classmethod
    def _fingerprint(cls, name: str, parameters: dict[str, Any]) -> str:
        payload = canonical_json_bytes(
            {"tool": name, "parameters": parameters}, label="idempotency fingerprint"
        )
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def _idempotency_fingerprint(
        cls,
        context: ExecutionContext,
        name: str,
        parameters: Mapping[str, Any],
    ) -> str:
        if context.bound_action is not None:
            return context.bound_action.action_digest
        return cls._fingerprint(name, dict(parameters))

    @staticmethod
    def _idempotency_namespace(context: ExecutionContext) -> str:
        if context.bound_action is not None:
            action = context.bound_action
            tenant = context.tenant
            if tenant is None:
                raise ValueError("verified tenant is required for action idempotency")
            tenant_partition = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "domain": "arg.idempotency-tenant-partition",
                        "version": 1,
                        "tenant": tenant,
                    },
                    label="idempotency tenant partition",
                )
            ).hexdigest()
            contract_partition = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "domain": "arg.idempotency-contract-partition",
                        "version": 1,
                        "contract_id": action.contract.contract_id,
                    },
                    label="idempotency contract partition",
                )
            ).hexdigest()
            return (
                "action/v1:"
                f"{tenant_partition}:{contract_partition}"
            )
        tenant = context.tenant or "global"
        return f"{tenant}:{context.tool_call.name}"

    def _supports_atomic_reconciliation_preparation(self) -> bool:
        """Return whether a claim and recovery descriptor share one SQLite DB."""

        with self._production_seal_lock:
            cached = self._atomic_reconciliation_preparation
            if cached is not None:
                return cached
            store = self.idempotency_store
            ledger = self.reconciliation_ledger
            cached = (
                isinstance(store, SQLiteIdempotencyStore)
                and isinstance(ledger, SQLiteReconciliationLedger)
                and _same_sqlite_database(store, ledger)
            )
            self._atomic_reconciliation_preparation = cached
            return cached

    @staticmethod
    def _normalize_result(
        spec: ToolSpec[Any, Any],
        value: Any,
        action: BoundAction | None = None,
    ) -> Any:
        if (
            spec.result_schema is not None
            or spec.max_result_bytes is not None
            or spec.execution_mode is ExecutionMode.IDEMPOTENT
            or (
                action is not None
                and action.contract.receipt_schema is not None
            )
        ):
            normalized = validate_instance(value, spec.result_schema, label="result")
            if action is not None and action.contract.receipt_schema is not None:
                normalized = validate_instance(
                    normalized,
                    action.contract.receipt_schema,
                    label="action receipt",
                )
            return normalized
        return value

    async def _acquire_idempotency(
        self,
        namespace: str,
        key: str,
        fingerprint: str,
        deadline: datetime | None,
        *,
        prepared_action: UnknownAction | None = None,
    ) -> IdempotencyClaim:
        self._raise_if_idempotency_store_poisoned()
        timeout = self._bounded_timeout(
            deadline,
            self.limits.idempotency_operation_timeout_seconds,
            "idempotency acquire",
        )
        lease = await self._idempotency_bulkhead.acquire(timeout)
        try:
            timeout = self._bounded_timeout(
                deadline,
                self.limits.idempotency_operation_timeout_seconds,
                "idempotency acquire",
            )
            poison_on_timeout = (
                timeout >= self.limits.idempotency_operation_timeout_seconds
            )
            if prepared_action is None:
                future = self._idempotency_executor.submit(
                    self.idempotency_store.acquire,
                    namespace,
                    key,
                    fingerprint,
                )
            else:
                store = self.idempotency_store
                if not isinstance(store, SQLiteIdempotencyStore):
                    raise RuntimeError(
                        "atomic reconciliation preparation requires SQLite idempotency"
                    )
                future = self._idempotency_executor.submit(
                    store.acquire_prepared,
                    namespace,
                    key,
                    fingerprint,
                    prepared_action,
                )
        except BaseException:
            lease.release()
            raise
        wrapped = asyncio.wrap_future(future)

        def settle_orphaned_claim(completed) -> None:
            try:
                claim = completed.result()
            except BaseException:
                return
            if not claim.owner:
                return
            try:
                error = TimeoutError("request stopped waiting during acquisition")
                if (
                    prepared_action is not None
                    and isinstance(self.reconciliation_ledger, SQLiteReconciliationLedger)
                ):
                    # The descriptor and claim were committed together. Preserve
                    # that invariant when an abandoned acquisition is settled.
                    self.reconciliation_ledger.record_unknown(
                        claim, prepared_action, error
                    )
                else:
                    self.idempotency_store.mark_unknown(claim, error)
            except BaseException:
                return

        def finish_orphaned_claim(completed, *, resume: bool) -> None:
            try:
                settle_orphaned_claim(completed)
            finally:
                lease.release()
                if resume:
                    self._resume_idempotency_store()

        try:
            done, _ = await asyncio.wait({wrapped}, timeout=timeout)
            if wrapped in done:
                return wrapped.result()
            exc = StageTimeoutError("idempotency acquire", timeout)
            if poison_on_timeout:
                self._poison_idempotency_store(exc)
            else:
                self._suspend_idempotency_store()
            future.add_done_callback(
                lambda completed: finish_orphaned_claim(
                    completed, resume=not poison_on_timeout
                )
            )
            wrapped.add_done_callback(self._consume_background_result)
            raise exc
        except StageTimeoutError:
            raise
        except BaseException:
            if not wrapped.done():
                self._suspend_idempotency_store()
                future.add_done_callback(
                    lambda completed: finish_orphaned_claim(completed, resume=True)
                )
                wrapped.add_done_callback(self._consume_background_result)
            else:
                lease.release()
            raise
        finally:
            if wrapped.done():
                lease.release()

    @staticmethod
    def _consume_background_result(task: asyncio.Task[Any]) -> None:
        try:
            task.result()
        except BaseException:
            pass

    async def _run_critical_store_operation(
        self,
        function: Callable[..., Any],
        *args: Any,
        deadline: datetime | None = None,
        stage: str = "idempotency store operation",
    ) -> Any:
        self._raise_if_idempotency_store_poisoned()
        timeout = self._bounded_timeout(
            deadline,
            self.limits.idempotency_operation_timeout_seconds,
            stage,
        )
        lease = await self._idempotency_bulkhead.acquire(timeout)
        try:
            timeout = self._bounded_timeout(
                deadline,
                self.limits.idempotency_operation_timeout_seconds,
                stage,
            )
            poison_on_timeout = (
                timeout >= self.limits.idempotency_operation_timeout_seconds
            )
            loop = asyncio.get_running_loop()
            future = self._idempotency_executor.submit(partial(function, *args))
        except BaseException:
            lease.release()
            raise
        task = asyncio.wrap_future(future, loop=loop)
        started = perf_counter()
        deferred_release = False

        def finish_detached_operation(_completed, *, resume: bool) -> None:
            lease.release()
            if resume:
                self._resume_idempotency_store()

        try:
            done, _ = await asyncio.wait({task}, timeout=timeout)
            if task in done:
                return task.result()
            exc = StageTimeoutError(stage, timeout)
            if poison_on_timeout:
                self._poison_idempotency_store(exc)
            else:
                self._suspend_idempotency_store()
            deferred_release = True
            future.add_done_callback(
                lambda completed: finish_detached_operation(
                    completed, resume=not poison_on_timeout
                )
            )
            task.add_done_callback(self._consume_background_result)
            raise exc
        except asyncio.CancelledError:
            remaining = max(0.0, timeout - (perf_counter() - started))
            try:
                done, _ = await asyncio.wait({task}, timeout=remaining)
            except asyncio.CancelledError:
                done = set()
            if task in done:
                self._consume_background_result(task)
            else:
                exc = StageTimeoutError(stage, timeout)
                if poison_on_timeout:
                    self._poison_idempotency_store(exc)
                else:
                    self._suspend_idempotency_store()
                deferred_release = True
                future.add_done_callback(
                    lambda completed: finish_detached_operation(
                        completed, resume=not poison_on_timeout
                    )
                )
                task.add_done_callback(self._consume_background_result)
            raise
        finally:
            if not deferred_release:
                lease.release()

    async def _run_reconciliation_audit_delivery(
        self,
        function: Callable[..., Any],
        *args: Any,
        deadline: datetime | None = None,
        stage: str = "reconciliation audit delivery",
        **kwargs: Any,
    ) -> Any:
        """Run a best-retryable sink write without poisoning the ledger.

        The outbox is the authority for delivery intent. A remote or stalled
        sink can exhaust only its own capacity; it must not make committed
        reconciliation state unreadable or prevent a later retry.
        """

        timeout = self._bounded_timeout(
            deadline,
            self.limits.reconciliation_audit_delivery_timeout_seconds,
            stage,
        )
        started = perf_counter()
        lease = await self._reconciliation_audit_bulkhead.acquire(timeout)
        task: asyncio.Future[Any] | None = None
        deferred_release = False
        try:
            loop = asyncio.get_running_loop()
            future = self._reconciliation_audit_executor.submit(
                partial(function, *args, **kwargs)
            )
            task = asyncio.wrap_future(future, loop=loop)
            done, _ = await asyncio.wait({task}, timeout=timeout)
            if task in done:
                result = task.result()
                if not inspect.isawaitable(result):
                    return result

                def retain_async_delivery(
                    detached: asyncio.Future[Any],
                ) -> None:
                    nonlocal deferred_release
                    deferred_release = True
                    detached.add_done_callback(lambda _completed: lease.release())
                    self._track_detached_stage(detached)

                remaining = max(0.0, timeout - (perf_counter() - started))
                return await await_stage(
                    result,
                    stage=stage,
                    timeout_seconds=remaining,
                    cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
                    on_detached=retain_async_delivery,
                )
            error = StageTimeoutError(stage, timeout)
            deferred_release = True
            future.add_done_callback(lambda _completed: lease.release())
            task.add_done_callback(self._consume_background_result)
            raise error
        except StageTimeoutError:
            raise
        except BaseException:
            if task is not None and not task.done():
                deferred_release = True
                task.add_done_callback(lambda _completed: lease.release())
                task.add_done_callback(self._consume_background_result)
            raise
        finally:
            if not deferred_release:
                lease.release()

    async def _run_reconciliation_operation(
        self,
        function: Callable[..., Any],
        *args: Any,
        deadline: datetime | None = None,
        stage: str = "reconciliation ledger operation",
        **kwargs: Any,
    ) -> Any:
        self._raise_if_reconciliation_poisoned()
        timeout = self._bounded_timeout(
            deadline,
            self.limits.reconciliation_operation_timeout_seconds,
            stage,
        )
        lease = await self._reconciliation_bulkhead.acquire(timeout)
        task: asyncio.Future[Any] | None = None
        deferred_release = False
        try:
            loop = asyncio.get_running_loop()
            future = self._reconciliation_executor.submit(
                partial(function, *args, **kwargs)
            )
            task = asyncio.wrap_future(future, loop=loop)
            done, _ = await asyncio.wait({task}, timeout=timeout)
            if task in done:
                return task.result()
            error = StageTimeoutError(stage, timeout)
            self._poison_reconciliation(error)
            deferred_release = True
            future.add_done_callback(
                lambda _completed: self._finish_detached_reconciliation(lease)
            )
            task.add_done_callback(self._consume_background_result)
            raise error
        except StageTimeoutError:
            raise
        except BaseException:
            if task is not None and not task.done():
                self._suspend_reconciliation()
                deferred_release = True
                task.add_done_callback(
                    lambda _completed: self._finish_detached_reconciliation(
                        lease, resume=True
                    )
                )
                task.add_done_callback(self._consume_background_result)
            raise
        finally:
            if not deferred_release:
                lease.release()

    def _finish_detached_reconciliation(
        self, lease: Any, *, resume: bool = False
    ) -> None:
        lease.release()
        if resume:
            self._resume_reconciliation()

    def _raise_if_reconciliation_poisoned(self) -> None:
        with self._reconciliation_poison_lock:
            cause = self._reconciliation_poison
            draining = self._reconciliation_draining
        if cause is not None:
            raise ReconciliationConflictError(
                "reconciliation ledger was disabled after an operation exceeded "
                "its bounded execution contract"
            ) from cause
        if draining:
            raise ReconciliationConflictError(
                "reconciliation ledger has a detached operation still draining"
            )

    def _poison_reconciliation(self, cause: BaseException) -> None:
        with self._reconciliation_poison_lock:
            if self._reconciliation_poison is None:
                self._reconciliation_poison = cause

    def _suspend_reconciliation(self) -> None:
        with self._reconciliation_poison_lock:
            if self._reconciliation_poison is None:
                self._reconciliation_draining += 1

    def _resume_reconciliation(self) -> None:
        with self._reconciliation_poison_lock:
            if self._reconciliation_draining > 0:
                self._reconciliation_draining -= 1

    async def _finish_idempotency(
        self,
        claim: IdempotencyClaim | None,
        context: ExecutionContext,
        error: BaseException | None,
        value: Any = None,
        *,
        spec: ToolSpec[Any, Any] | None = None,
    ) -> ReconciliationHead | None:
        if claim is None:
            return None
        if error is None:
            await self._run_critical_store_operation(
                self.idempotency_store.complete,
                claim,
                value,
                deadline=context.deadline,
                stage="idempotency complete",
            )
            return None
        if context.status is ExecutionStatus.UNKNOWN:
            if spec is not None and self.reconciliation_ledger is not None:
                return await self._record_unknown_reconciliation(
                    claim, spec, context, error
                )
            await self._run_critical_store_operation(
                self.idempotency_store.mark_unknown,
                claim,
                error,
                deadline=context.deadline,
                stage="idempotency mark unknown",
            )
            return None
        await self._run_critical_store_operation(
            self.idempotency_store.fail,
            claim,
            error,
            deadline=context.deadline,
            stage="idempotency fail",
        )
        return None

    async def _record_unknown_reconciliation(
        self,
        claim: IdempotencyClaim,
        spec: ToolSpec[Any, Any],
        context: ExecutionContext,
        error: BaseException,
    ) -> ReconciliationHead:
        ledger = self.reconciliation_ledger
        assert ledger is not None
        action = self._unknown_action(spec, context, claim, error)
        if isinstance(ledger, SQLiteReconciliationLedger):
            head = await self._run_reconciliation_operation(
                ledger.record_unknown,
                claim,
                action,
                error,
                deadline=context.deadline,
                stage="reconciliation record unknown",
            )
        else:
            # Process-local adapters are intentionally not promoted as a
            # durable atomic boundary. They retain compatibility for local
            # development, while production sealing rejects them.
            await self._run_critical_store_operation(
                self.idempotency_store.mark_unknown,
                claim,
                error,
                deadline=context.deadline,
                stage="idempotency mark unknown",
            )
            head = await self._run_reconciliation_operation(
                ledger.create_unknown,
                action,
                deadline=context.deadline,
                stage="reconciliation create unknown",
            )
        await self._write_reconciliation_audit(
            head,
            event_type="unknown_recorded",
            deadline=context.deadline,
        )
        return head

    @staticmethod
    def _unknown_action(
        spec: ToolSpec[Any, Any],
        context: ExecutionContext,
        claim: IdempotencyClaim,
        error: BaseException | None = None,
    ) -> UnknownAction:
        if claim.execution_record_id is None:
            raise ReconciliationConflictError(
                "idempotency claim has no execution record identifier"
            )
        return Runtime._prepared_unknown_action(
            spec,
            context,
            execution_record_id=claim.execution_record_id,
            action_digest=claim.fingerprint,
            namespace=claim.namespace,
            error=error,
        )

    @staticmethod
    def _prepared_unknown_action(
        spec: ToolSpec[Any, Any],
        context: ExecutionContext,
        *,
        execution_record_id: str,
        action_digest: str,
        namespace: str,
        error: BaseException | None = None,
    ) -> UnknownAction:
        bound_action = context.bound_action
        contract = None if bound_action is None else bound_action.contract
        provider = spec.reconciliation_provider
        return UnknownAction(
            execution_record_id=execution_record_id,
            action_digest=action_digest,
            tool_name=spec.name,
            contract_id=(
                contract.contract_id if contract is not None else f"runtime.{spec.name}"
            ),
            contract_version=(contract.contract_version if contract is not None else 1),
            idempotency_namespace_digest=idempotency_namespace_digest(namespace),
            tenant_partition_digest=(
                None
                if context.tenant is None
                else tenant_partition_digest(context.tenant)
            ),
            uncertainty_reason=(
                "execution outcome may require explicit reconciliation"
                if error is None
                else f"{type(error).__name__}: execution outcome is unknown"
            ),
            attempted_at=datetime.now(timezone.utc),
            receipt_schema=(None if contract is None else contract.receipt_schema),
            probe_schema=spec.reconciliation_probe_schema,
            result_schema=(
                spec.result_schema
                if spec.result_schema is not None
                else (None if contract is None else contract.receipt_schema)
            ),
            reconciliation_provider_id=(
                None if provider is None else provider.provider_id
            ),
            reconciliation_protocol_version=(
                None if provider is None else provider.protocol_version
            ),
            reconciliation_supported_evidence_kinds=(
                () if provider is None else provider.supported_evidence_kinds
            ),
            max_result_bytes=spec.max_result_bytes or 1_048_576,
            metadata={
                "trace_id": context.trace_id,
                "request_id": context.request_id,
                _TENANT_PARTITION_BOUND_METADATA_KEY: bool(context.tenant),
            },
        )

    def _start_idempotency_heartbeat(
        self, claim: IdempotencyClaim
    ) -> asyncio.Task[None] | None:
        if not claim.owner or claim.lease_seconds is None:
            return None

        async def heartbeat() -> None:
            interval = max(0.001, min(30.0, claim.lease_seconds / 3))
            while True:
                await asyncio.sleep(interval)
                await self._run_critical_store_operation(
                    self.idempotency_store.renew,
                    claim,
                    stage="idempotency renew",
                )

        return asyncio.create_task(
            heartbeat(),
            name=f"idempotency-heartbeat:{claim.namespace}:{claim.key}",
        )

    @staticmethod
    async def _stop_idempotency_heartbeat(
        task: asyncio.Task[None] | None,
        *,
        raise_on_failure: bool,
    ) -> None:
        if task is None:
            return
        if not task.done():
            task.cancel()
        results = await asyncio.gather(task, return_exceptions=True)
        result = results[0]
        if (
            raise_on_failure
            and isinstance(result, BaseException)
            and not isinstance(result, asyncio.CancelledError)
        ):
            raise IdempotencyOutcomeUnknownError(
                "idempotency lease renewal failed"
            ) from result

    async def _settle_idempotency(
        self,
        claim: IdempotencyClaim | None,
        context: ExecutionContext,
        error: BaseException | None,
        value: Any = None,
        *,
        spec: ToolSpec[Any, Any] | None = None,
    ) -> ExecutionContext:
        try:
            head = await self._finish_idempotency(
                claim, context, error, value, spec=spec
            )
        except Exception as settlement_error:
            changes: dict[str, Any] = {
                "error": (
                    f"{type(settlement_error).__name__}: idempotency ledger "
                    "could not record the final outcome"
                )
            }
            if isinstance(
                settlement_error, ReconciliationAuditDeliveryPendingError
            ):
                changes["metadata"] = {
                    **context.metadata,
                    "execution_record_id": settlement_error.execution_record_id,
                    "reconciliation_audit_outbox_id": settlement_error.outbox_id,
                }
            if not context.denied:
                changes["status"] = ExecutionStatus.UNKNOWN
            return context.evolve(**changes).append_history(
                HistoryEntry(
                    "idempotency",
                    "unknown",
                    f"ledger settlement failed: {settlement_error}",
                )
            )
        if head is not None:
            context = context.evolve(
                metadata={
                    **context.metadata,
                    "execution_record_id": head.execution_record_id,
                }
            ).append_history(
                HistoryEntry(
                    "reconciliation",
                    "recorded",
                    "UNKNOWN outcome was recorded for explicit reconciliation",
                    data={"execution_record_id": head.execution_record_id},
                )
            )
        return context

    def _raise_if_idempotency_store_poisoned(self) -> None:
        with self._idempotency_poison_lock:
            cause = self._idempotency_poison
            draining = self._idempotency_draining
        if cause is not None:
            raise IdempotencyOutcomeUnknownError(
                "idempotency store was disabled after an operation exceeded its "
                "bounded execution contract"
            ) from cause
        if draining:
            raise IdempotencyOutcomeUnknownError(
                "idempotency store has a detached operation still draining"
            )

    def _poison_idempotency_store(self, cause: BaseException) -> None:
        with self._idempotency_poison_lock:
            if self._idempotency_poison is None:
                self._idempotency_poison = cause

    def _suspend_idempotency_store(self) -> None:
        with self._idempotency_poison_lock:
            if self._idempotency_poison is None:
                self._idempotency_draining += 1

    def _resume_idempotency_store(self) -> None:
        with self._idempotency_poison_lock:
            if self._idempotency_draining > 0:
                self._idempotency_draining -= 1

    async def _run_pre_pipeline(
        self, context: ExecutionContext, *, replayable_only: bool = False
    ) -> ExecutionContext:
        def include(middleware: Middleware, current: ExecutionContext) -> bool:
            if middleware.kind is MiddlewareKind.EXECUTION:
                return False
            if replayable_only and not middleware.metadata.replayable:
                return False
            return not (current.denied and middleware.kind is MiddlewareKind.GATING)

        async def invoke(
            middleware: Middleware, current: ExecutionContext
        ) -> ExecutionContext:
            try:
                current = await self._emit_middleware_hook(
                    middleware.name, current, before=True
                )
                if current.denied and middleware.kind is MiddlewareKind.GATING:
                    return current
                timeout = self._bounded_timeout(
                    current.deadline,
                    (
                        self.limits.observer_timeout_seconds
                        if middleware.kind is MiddlewareKind.OBSERVING
                        else self.limits.middleware_timeout_seconds
                    ),
                    f"middleware:{middleware.name}",
                )
                candidate = await self._await_runtime_stage(
                    middleware.process(current),
                    stage=f"middleware:{middleware.name}",
                    timeout_seconds=timeout,
                    cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
                )
                current = validate_middleware_transition(
                    current, candidate, middleware.kind
                )
                return await self._emit_middleware_hook(
                    middleware.name, current, before=False
                )
            except Exception as exc:
                if middleware.kind is MiddlewareKind.OBSERVING:
                    if self._is_critical_observer(middleware, current):
                        decision = DecisionRecord(
                            DecisionOutcome.DENY,
                            f"critical observer {middleware.name!r} failed closed",
                            f"observer:{middleware.name}",
                        )
                        return current.with_decision(decision).append_history(
                            HistoryEntry(middleware.name, "error", str(exc))
                        )
                    return current.append_history(
                        HistoryEntry(
                            middleware.name, "error", f"observer ignored: {exc}"
                        )
                    )
                decision = DecisionRecord(
                    DecisionOutcome.DENY,
                    f"gating middleware {middleware.name!r} failed closed",
                    "runtime",
                )
                return current.with_decision(decision).append_history(
                    HistoryEntry(middleware.name, "error", str(exc))
                )
        context = await self._pipeline_runner.run(
            context,
            invoke=invoke,
            include=include,
        )
        if not context.denied:
            context = context.evolve(status=ExecutionStatus.ALLOWED)
        return context

    async def _commit_approvals(self, context: ExecutionContext) -> ExecutionContext:
        for middleware in self.pipeline:
            commit = getattr(middleware, "commit_approval", None)
            if callable(commit):
                timeout = self._bounded_timeout(
                    context.deadline,
                    self.limits.middleware_timeout_seconds,
                    "approval commit",
                )
                context = await self._await_runtime_stage(
                    commit(context),
                    stage="approval commit",
                    timeout_seconds=timeout,
                    cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
                )
                if context.denied:
                    break
        return context

    async def _release_approvals(self, context: ExecutionContext) -> ExecutionContext:
        for middleware in self.pipeline:
            release = getattr(middleware, "release_approval", None)
            if callable(release):
                try:
                    timeout = self._bounded_timeout(
                        context.deadline,
                        self.limits.middleware_timeout_seconds,
                        "approval release",
                    )
                    context = await self._await_runtime_stage(
                        release(context),
                        stage="approval release",
                        timeout_seconds=timeout,
                        cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
                    )
                except Exception as exc:
                    # Cleanup is bounded and fail-closed: a durable lease can
                    # recover the reservation, but a stalled release must not
                    # hold the request open indefinitely.
                    context = context.append_history(
                        HistoryEntry(
                            "runtime",
                            "approval_cleanup_error",
                            f"approval release bounded: {type(exc).__name__}",
                        )
                    )
        return context

    @staticmethod
    def _enforce_required_approval(context: ExecutionContext) -> ExecutionContext:
        if (
            context.requires_approval
            and not context.denied
            and not Runtime._has_bound_approval(context)
        ):
            decision = DecisionRecord(
                DecisionOutcome.DENY,
                "required human decision was not granted",
                "runtime",
            )
            return context.with_decision(decision).append_history(
                HistoryEntry("runtime", "deny", decision.reason)
            )
        return context

    @staticmethod
    def _has_bound_approval(context: ExecutionContext) -> bool:
        decision = context.decision
        identity_issuer = context.metadata.get("identity_issuer")
        expected_identity_issuer = (
            None if identity_issuer is None else str(identity_issuer)
        )
        if (
            not context.approval_granted
            or decision is None
            or decision.outcome is not DecisionOutcome.ALLOW
            or decision.is_expired()
            or context.approval_request_id != context.request_id
            or context.approval_decision_id != decision.decision_id
            or decision.request_id != context.request_id
            or decision.tool_name != context.tool_call.name
            or decision.risk_tier != context.risk_tier.name
            or decision.policy_version
            != _metadata_text(context.metadata, "policy_version")
            or decision.policy_digest
            != _metadata_text(context.metadata, "policy_digest")
            or decision.subject != context.user
            or decision.tenant != context.tenant
            or decision.identity_issuer != expected_identity_issuer
            or (
                context.bound_action is not None
                and decision.action_digest
                != context.bound_action.action_digest
            )
        ):
            return False
        if context.bound_action is not None:
            return True
        expected_digest = digest_arguments(
            {
                "args": list(context.tool_call.args),
                "kwargs": dict(context.tool_call.kwargs),
            }
        )
        return decision.arguments_digest == expected_digest

    @staticmethod
    def _enforce_idempotency_key(context: ExecutionContext) -> ExecutionContext:
        if (
            context.execution_mode is not ExecutionMode.IDEMPOTENT
            or context.idempotency_key
        ):
            return context
        decision = DecisionRecord(
            DecisionOutcome.DENY,
            "idempotent tool execution requires an idempotency key",
            "idempotency",
        )
        return context.with_decision(decision).append_history(
            HistoryEntry("idempotency", "deny", decision.reason)
        )

    async def _run_observers(
        self,
        context: ExecutionContext,
        *,
        post: bool,
        ignore_deadline: bool = False,
    ) -> ExecutionContext:
        if not post:
            return context
        critical_failure: tuple[Middleware, BaseException] | None = None
        for middleware in self.pipeline:
            if middleware.kind is not MiddlewareKind.OBSERVING:
                continue
            try:
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=True
                )
                timeout = self._bounded_timeout(
                    None if ignore_deadline else context.deadline,
                    self.limits.observer_timeout_seconds,
                    f"observer:{middleware.name}",
                )
                candidate = await self._await_runtime_stage(
                    middleware.process(context),
                    stage=f"observer:{middleware.name}",
                    timeout_seconds=timeout,
                    cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
                )
                context = validate_middleware_transition(
                    context, candidate, MiddlewareKind.OBSERVING
                )
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=False
                )
            except Exception as exc:
                if self._is_critical_observer(middleware, context):
                    context = context.append_history(
                        HistoryEntry(
                            middleware.name,
                            "critical_error",
                            f"critical observer failed: {exc}",
                        )
                    )
                    critical_failure = critical_failure or (middleware, exc)
                    continue
                context = context.append_history(
                    HistoryEntry(middleware.name, "error", f"observer ignored: {exc}")
                )
        if critical_failure is not None:
            middleware, exc = critical_failure
            post_execution = context.status in {
                ExecutionStatus.EXECUTING,
                ExecutionStatus.SUCCEEDED,
                ExecutionStatus.FAILED,
                ExecutionStatus.UNKNOWN,
            }
            if post_execution and not context.denied:
                context = context.evolve(
                    status=ExecutionStatus.UNKNOWN,
                    error=f"{type(exc).__name__}: critical observer failed",
                )
            raise AuditDeliveryError(
                context,
                exc,
                post_execution=post_execution,
            )
        return context

    async def _handle_cancellation(
        self,
        context: ExecutionContext,
        started: float,
        *,
        uncertain: bool,
        claim: IdempotencyClaim | None = None,
        spec: ToolSpec[Any, Any] | None = None,
    ) -> ExecutionContext:
        if not context.denied:
            context = context.evolve(
                status=(
                    ExecutionStatus.UNKNOWN if uncertain else ExecutionStatus.FAILED
                ),
                error=(
                    "CancelledError: execution outcome is unknown"
                    if uncertain
                    else "CancelledError: request cancelled before tool execution"
                ),
                metadata={
                    **context.metadata,
                    "duration_ms": (perf_counter() - started) * 1000,
                },
            )
        context = context.append_history(
            HistoryEntry(
                "runtime",
                "cancelled",
                (
                    "cancellation propagated; execution outcome is unknown"
                    if uncertain
                    else "cancellation propagated before tool execution"
                ),
            )
        )
        context = await self._settle_idempotency(
            claim, context, asyncio.CancelledError(), spec=spec
        )
        context = await self._abort_observers(context)
        try:
            context = await asyncio.shield(
                self._run_observers(
                    context,
                    post=True,
                    ignore_deadline=True,
                )
            )
        except BaseException:
            context = context.append_history(
                HistoryEntry(
                    "runtime",
                    "error",
                    "cancellation finalization could not be fully persisted",
                )
            )
        return context

    async def _abort_observers(self, context: ExecutionContext) -> ExecutionContext:
        for middleware in self.pipeline:
            abort = getattr(middleware, "aabort", None)
            if not callable(abort):
                abort = getattr(middleware, "abort", None)
            if not callable(abort):
                continue
            try:
                result = abort(context.trace_id)
                if inspect.isawaitable(result):
                    await self._await_runtime_stage(
                        result,
                        stage=f"observer:{middleware.name}:abort",
                        timeout_seconds=self.limits.observer_timeout_seconds,
                        cancellation_grace_seconds=(
                            self.limits.cancellation_grace_seconds
                        ),
                    )
            except BaseException:
                context = context.append_history(
                    HistoryEntry(
                        middleware.name,
                        "error",
                        "observer cancellation cleanup failed",
                    )
                )
        return context

    @staticmethod
    def _is_critical_observer(
        middleware: Middleware, context: ExecutionContext
    ) -> bool:
        checker = getattr(middleware, "is_critical", None)
        if callable(checker):
            return bool(checker(context))
        return bool(getattr(middleware, "critical", False))

    async def _emit_middleware_hook(
        self, name: str, context: ExecutionContext, *, before: bool
    ) -> ExecutionContext:
        points = {
            ("llm", True): HookPoint.BEFORE_LLM,
            ("llm", False): HookPoint.AFTER_LLM,
            ("decision", True): HookPoint.BEFORE_DECISION,
            ("decision", False): HookPoint.AFTER_DECISION,
            ("audit", True): HookPoint.BEFORE_AUDIT,
            ("audit", False): HookPoint.AFTER_AUDIT,
        }
        point = points.get((name, before))
        if point is None:
            return context
        return await self._emit_hook(point, context, allow_critical=before)

    async def _emit_hook(
        self, point: HookPoint, context: ExecutionContext, *, allow_critical: bool
    ) -> ExecutionContext:
        try:
            timeout = self._bounded_timeout(
                context.deadline,
                self.limits.hook_timeout_seconds,
                f"hook:{point.value}",
            )
            return await self._await_runtime_stage(
                self.hooks.emit(point, context, allow_critical=allow_critical),
                stage=f"hook:{point.value}",
                timeout_seconds=timeout,
                cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
            )
        except (CriticalHookError, StageTimeoutError) as exc:
            if not allow_critical:
                return context.append_history(
                    HistoryEntry(f"hook:{point.value}", "error", str(exc))
                )
            decision = DecisionRecord(
                DecisionOutcome.DENY, str(exc), f"hook:{point.value}"
            )
            return context.with_decision(decision).append_history(
                HistoryEntry(f"hook:{point.value}", "deny", str(exc))
            )

    @staticmethod
    def _failed_context(
        context: ExecutionContext,
        exc: Exception,
        started: float,
        *,
        uncertain: bool = False,
    ) -> ExecutionContext:
        metadata = {
            **context.metadata,
            "duration_ms": (perf_counter() - started) * 1000,
        }
        status = (
            ExecutionStatus.UNKNOWN
            if isinstance(
                exc,
                (
                    TimeoutError,
                    IdempotencyOutcomeUnknownError,
                    IdempotencyInProgressError,
                ),
            )
            or uncertain
            else ExecutionStatus.FAILED
        )
        changes: dict[str, Any] = {
            "error": f"{type(exc).__name__}: {exc}",
            "metadata": metadata,
        }
        if not context.denied:
            changes["status"] = status
        return context.evolve(**changes).append_history(
            HistoryEntry(
                "executor",
                "unknown" if status is ExecutionStatus.UNKNOWN else "failed",
                str(exc),
            )
        )


def _caller_metadata(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        key: item
        for key, item in (value or {}).items()
        if not isinstance(key, str)
        or (
            key.lower() not in _RUNTIME_METADATA_KEYS
            and not key.lower().startswith(_GOVERNANCE_METADATA_PREFIXES)
        )
    }


Harness = Runtime
