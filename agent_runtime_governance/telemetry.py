from __future__ import annotations

import asyncio
import inspect
import threading
import warnings
from concurrent.futures import Future as ConcurrentFuture
from contextlib import contextmanager, nullcontext
from contextvars import Context, copy_context
from dataclasses import dataclass
from typing import Any, Awaitable, Protocol

from ._blocking import (
    extension_lifecycle_scope,
    invoke_extension,
    schedule_extension_cleanup,
)
from ._extensions import is_native_async_callable
from .context import ExecutionContext, ExecutionStatus, HistoryEntry
from .middleware.base import ObservingMiddleware

_STATUS_WARNING_LOCK = threading.Lock()
_STATUS_WARNING_EMITTED = False


class Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None | Awaitable[None]: ...
    def end(self) -> None | Awaitable[None]: ...


class Tracer(Protocol):
    def start_span(
        self, name: str, *, attributes: dict[str, Any]
    ) -> Span | Awaitable[Span]: ...


@dataclass(slots=True)
class _SpanHandle:
    span: Span
    manager: Any = None
    manager_owner_task: asyncio.Task[Any] | None = None
    status_cls: Any = None
    status_code_cls: Any = None
    ended: bool = False

    def finish(self, context: ExecutionContext) -> None:
        if self.ended:
            return
        _set_span_terminal_state(
            self.span,
            context,
            status_cls=self.status_cls,
            status_code_cls=self.status_code_cls,
        )
        self._end()
        self.ended = True

    def abort(self, description: str) -> None:
        if self.ended:
            return
        _record_exception(self.span, RuntimeError(description))
        _set_status(
            self.span,
            "ERROR",
            description,
            status_cls=self.status_cls,
            status_code_cls=self.status_code_cls,
        )
        self._end()
        self.ended = True

    async def afinish(self, context: ExecutionContext) -> None:
        """Finish a normal span through the extension dispatcher."""

        if self.ended:
            return
        if self.manager is not None:
            # A legacy ``start_as_current_span`` manager owns a ContextVar token
            # that can only be exited by its creating task.
            self.finish(context)
            return
        await _aset_span_terminal_state(
            self.span,
            context,
            status_cls=self.status_cls,
            status_code_cls=self.status_code_cls,
        )
        await invoke_extension(self.span.end)
        self.ended = True

    async def aabort(self, description: str) -> None:
        """Abort a normal span through the extension dispatcher."""

        if self.ended:
            return
        if self.manager is not None:
            self.abort(description)
            return
        await _arecord_exception(self.span, RuntimeError(description))
        await _aset_status(
            self.span,
            "ERROR",
            description,
            status_cls=self.status_cls,
            status_code_cls=self.status_code_cls,
        )
        await invoke_extension(self.span.end)
        self.ended = True

    def _end(self) -> None:
        if self.manager is not None and self._owns_manager_context():
            self.manager.__exit__(None, None, None)
        else:
            self.span.end()

    def _owns_manager_context(self) -> bool:
        if self.manager_owner_task is None:
            return False
        try:
            return asyncio.current_task() is self.manager_owner_task
        except RuntimeError:
            return False

@dataclass(slots=True)
class _SpanEntry:
    """Own a span from asynchronous admission through terminal cleanup."""

    start_task: asyncio.Task[Any] | None = None
    owner_loop: asyncio.AbstractEventLoop | None = None
    owner_context: Context | None = None
    ready: asyncio.Future[_SpanHandle] | None = None
    legacy_terminal: asyncio.Future[None] | None = None
    native_start: bool = False
    start_result_awaitable: bool = False
    handle: _SpanHandle | None = None
    terminal_context: ExecutionContext | None = None
    abort_description: str | None = None
    finalizer: asyncio.Task[Any] | None = None
    direct_terminal: bool = False


class OpenTelemetryMiddleware(ObservingMiddleware):
    """Exports runtime lifecycle data through an injected or global OTel tracer."""

    name = "opentelemetry"
    priority = 950
    replayable = False

    def __init__(self, tracer: Tracer | None = None, *, parent_context: Any = None) -> None:
        self._status_cls = None
        self._status_code_cls = None
        if tracer is None:
            try:
                from opentelemetry import trace
                from opentelemetry.trace import Status, StatusCode
            except ImportError as exc:
                raise RuntimeError(
                    "install agent-runtime-governance[otel] to enable OpenTelemetry"
                ) from exc
            tracer = trace.get_tracer("agent_runtime_governance")
            self._status_cls = Status
            self._status_code_cls = StatusCode
        else:
            try:
                from opentelemetry.trace import Status, StatusCode
            except ImportError:
                Status = StatusCode = None  # type: ignore[assignment]
            self._status_cls = Status
            self._status_code_cls = StatusCode
        self._status_cls = self._status_cls or _exposed_type(
            tracer, "Status", "status_cls"
        )
        self._status_code_cls = self._status_code_cls or _exposed_type(
            tracer, "StatusCode", "status_code_cls"
        )
        self._tracer = tracer
        self._parent_context = parent_context
        self._spans: dict[str, _SpanEntry] = {}
        self._lock = threading.Lock()

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if any(
            entry.middleware == self.name and entry.outcome == context.status.value
            for entry in context.history
        ):
            return context
        entry = self._admit_span(context)
        try:
            handle = await self._await_handle(context.trace_id, entry)
            await _aset_span_attribute(handle.span, "arg.status", context.status.value)
            await _aset_span_attribute(handle.span, "arg.risk.score", context.risk_score)
            if context.decision:
                await _aset_span_attribute(
                    handle.span, "arg.decision", context.decision.outcome.value
                )
                await _aset_span_attribute(
                    handle.span, "arg.decision.source", context.decision.source
                )
            if context.status in {
                ExecutionStatus.SUCCEEDED,
                ExecutionStatus.FAILED,
                ExecutionStatus.DENIED,
                ExecutionStatus.UNKNOWN,
            }:
                await self.afinish(context)
            return context.append_history(
                HistoryEntry(self.name, context.status.value, "telemetry exported")
            )
        except BaseException:
            # The observer task can time out after a synchronous tracer has
            # started its span but before the awaiting task resumes. Keep the
            # admission record until the owned cleanup task has ended it.
            self._request_terminal(
                context.trace_id,
                entry,
                description="telemetry observer did not complete",
            )
            raise

    def finish(self, context: ExecutionContext) -> bool:
        """Finish and forget the active span for a terminal context."""

        with self._lock:
            entry = self._spans.get(context.trace_id)
        if entry is None:
            return False
        if entry.legacy_terminal is not None:
            return self._request_legacy_terminal_sync(
                context.trace_id, entry, context=context
            )
        return self._request_terminal_sync(context.trace_id, entry, context=context)

    async def afinish(self, context: ExecutionContext) -> bool:
        """Finish and forget a Runtime lifecycle span without blocking its loop."""

        with self._lock:
            entry = self._spans.get(context.trace_id)
        if entry is None:
            return False
        return await self._request_terminal_async(
            context.trace_id, entry, context=context
        )

    def abort(
        self,
        trace_id: str,
        *,
        description: str = "runtime pipeline cancelled",
    ) -> bool:
        """Abort an active span when execution cannot produce a terminal context."""

        with self._lock:
            entry = self._spans.get(trace_id)
        if entry is None:
            return False
        if entry.legacy_terminal is not None:
            return self._request_legacy_terminal_sync(
                trace_id, entry, description=description
            )
        return self._request_terminal_sync(trace_id, entry, description=description)

    async def aabort(
        self,
        trace_id: str,
        *,
        description: str = "runtime pipeline cancelled",
    ) -> bool:
        """Abort a Runtime lifecycle span without blocking its event loop."""

        with self._lock:
            entry = self._spans.get(trace_id)
        if entry is None:
            return False
        return await self._request_terminal_async(
            trace_id, entry, description=description
        )

    def _admit_span(self, context: ExecutionContext) -> _SpanEntry:
        """Record ownership before an asynchronous tracer call can suspend."""

        with self._lock:
            existing = self._spans.get(context.trace_id)
            if existing is not None:
                return existing
            entry = _SpanEntry(
                owner_loop=asyncio.get_running_loop(),
                owner_context=copy_context(),
            )
            start_span = getattr(self._tracer, "start_span", None)
            if callable(start_span):
                entry.native_start = is_native_async_callable(start_span)
                entry.start_task = asyncio.create_task(
                    self._run_start_span_lifecycle(context, entry),
                    name=f"opentelemetry-start:{context.trace_id}",
                )
            else:
                loop = asyncio.get_running_loop()
                entry.ready = loop.create_future()
                entry.legacy_terminal = loop.create_future()
                entry.start_task = asyncio.create_task(
                    self._run_current_span_manager(context, entry),
                    name=f"opentelemetry-legacy:{context.trace_id}",
                )
            self._spans[context.trace_id] = entry
            return entry

    async def _await_handle(
        self, trace_id: str, entry: _SpanEntry
    ) -> _SpanHandle:
        """Wait for admission without allowing the observer waiter to cancel it."""

        if entry.ready is not None:
            return await asyncio.shield(entry.ready)
        if entry.handle is not None:
            return entry.handle
        if entry.start_task is None:
            raise RuntimeError("telemetry span admission has no start task")
        try:
            handle = await asyncio.shield(entry.start_task)
        except asyncio.CancelledError:
            raise
        except BaseException:
            with self._lock:
                if (
                    self._spans.get(trace_id) is entry
                    and entry.finalizer is None
                ):
                    self._spans.pop(trace_id, None)
            raise
        with self._lock:
            if entry.handle is None:
                entry.handle = handle
            return entry.handle

    def _request_terminal(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> asyncio.Task[Any] | None:
        """Claim an admitted span on the loop that owns its start task."""

        if not self._runs_on_owner_loop(entry):
            return None
        with self._lock:
            if self._spans.get(trace_id) is not entry:
                return None
            if description is not None:
                # Cancellation is more authoritative than a concurrently
                # observed successful status.
                entry.abort_description = description
                if (
                    (entry.native_start or entry.start_result_awaitable)
                    and entry.start_task is not None
                ):
                    entry.start_task.cancel()
            elif entry.abort_description is None and entry.terminal_context is None:
                entry.terminal_context = context
            if entry.finalizer is None:
                finalizer = schedule_extension_cleanup(
                    self._finalize_entry(trace_id, entry)
                )
                if finalizer is None:
                    if self._spans.get(trace_id) is entry:
                        self._spans.pop(trace_id, None)
                    return None
                entry.finalizer = finalizer
            return entry.finalizer

    def _request_terminal_sync(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> bool:
        """Bridge the compatibility API without crossing Task ownership."""

        if self._runs_on_owner_loop(entry):
            return self._request_terminal(
                trace_id,
                entry,
                context=context,
                description=description,
            ) is not None

        terminal = self._submit_terminal_to_owner(
            trace_id,
            entry,
            context=context,
            description=description,
        )
        if terminal is not None:
            terminal.add_done_callback(self._consume_terminal_result)
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return terminal.result()
            return True

        return self._request_direct_terminal_sync(
            trace_id,
            entry,
            context=context,
            description=description,
        )

    async def _request_terminal_async(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> bool:
        """Await one normal-span terminal lifecycle from any caller loop."""

        if self._runs_on_owner_loop(entry):
            finalizer = self._request_terminal(
                trace_id,
                entry,
                context=context,
                description=description,
            )
            if finalizer is None:
                return False
            await asyncio.shield(finalizer)
            return True

        terminal = self._submit_terminal_to_owner(
            trace_id,
            entry,
            context=context,
            description=description,
        )
        if terminal is not None:
            terminal.add_done_callback(self._consume_terminal_result)
            return await asyncio.shield(asyncio.wrap_future(terminal))

        return await self._request_direct_terminal_async(
            trace_id,
            entry,
            context=context,
            description=description,
        )

    def _submit_terminal_to_owner(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> ConcurrentFuture[bool] | None:
        """Ask the start-task loop to claim and await terminal cleanup."""

        owner_loop = entry.owner_loop
        if (
            owner_loop is None
            or owner_loop.is_closed()
            or not owner_loop.is_running()
        ):
            return None
        coroutine = self._complete_terminal_on_owner(
            trace_id,
            entry,
            context=context,
            description=description,
        )
        try:
            owner_context = entry.owner_context
            if owner_context is None:
                return asyncio.run_coroutine_threadsafe(coroutine, owner_loop)
            return owner_context.copy().run(
                asyncio.run_coroutine_threadsafe,
                coroutine,
                owner_loop,
            )
        except RuntimeError:
            coroutine.close()
            return None

    async def _complete_terminal_on_owner(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> bool:
        """Claim and await a finalizer after entering its owner event loop."""

        finalizer = self._request_terminal(
            trace_id,
            entry,
            context=context,
            description=description,
        )
        if finalizer is None:
            return False
        await asyncio.shield(finalizer)
        return True

    def _request_direct_terminal_sync(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> bool:
        """Finalize an already-started span after its original loop has stopped."""

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self._finalize_direct_entry(
                    trace_id,
                    entry,
                    context=context,
                    description=description,
                )
            )
        task = asyncio.create_task(
            self._finalize_direct_entry(
                trace_id,
                entry,
                context=context,
                description=description,
            ),
            name=f"opentelemetry-direct-terminal:{trace_id}",
        )
        task.add_done_callback(self._consume_terminal_result)
        return True

    async def _request_direct_terminal_async(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> bool:
        """Keep a direct fallback alive if the async caller is cancelled."""

        task = asyncio.create_task(
            self._finalize_direct_entry(
                trace_id,
                entry,
                context=context,
                description=description,
            ),
            name=f"opentelemetry-direct-terminal:{trace_id}",
        )
        task.add_done_callback(self._consume_terminal_result)
        return await asyncio.shield(task)

    async def _finalize_direct_entry(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> bool:
        """Use an available caller loop only after atomically reserving a span."""

        with self._lock:
            if (
                self._spans.get(trace_id) is not entry
                or entry.finalizer is not None
                or entry.direct_terminal
            ):
                return False
            handle = entry.handle
            if handle is None:
                self._spans.pop(trace_id, None)
                return False
            entry.direct_terminal = True
            if description is not None:
                entry.abort_description = description
            elif entry.abort_description is None and entry.terminal_context is None:
                entry.terminal_context = context
            description = entry.abort_description
            context = entry.terminal_context
        try:
            if description is not None:
                await handle.aabort(description)
            elif context is not None:
                await handle.afinish(context)
            else:
                await handle.aabort("telemetry span closed without terminal context")
        finally:
            with self._lock:
                if self._spans.get(trace_id) is entry:
                    self._spans.pop(trace_id, None)
        return True

    @staticmethod
    def _consume_terminal_result(future: asyncio.Future[Any] | ConcurrentFuture[Any]) -> None:
        """Observe deferred terminal errors so compatibility calls do not leak them."""

        try:
            future.result()
        except BaseException:
            pass

    @staticmethod
    def _runs_on_owner_loop(entry: _SpanEntry) -> bool:
        try:
            return asyncio.get_running_loop() is entry.owner_loop
        except RuntimeError:
            return False

    def _request_legacy_terminal_sync(
        self,
        trace_id: str,
        entry: _SpanEntry,
        *,
        context: ExecutionContext | None = None,
        description: str | None = None,
    ) -> bool:
        """Schedule legacy manager cleanup without exiting its ContextVar elsewhere."""

        if entry.start_task is not None and entry.start_task.done():
            with self._lock:
                if self._spans.get(trace_id) is entry:
                    self._spans.pop(trace_id, None)
            return True
        if not self._runs_on_owner_loop(entry):
            return False
        return self._request_terminal(
            trace_id,
            entry,
            context=context,
            description=description,
        ) is not None

    async def _finalize_entry(self, trace_id: str, entry: _SpanEntry) -> None:
        """End exactly one admitted span, including a late synchronous start."""

        try:
            handle = await self._await_handle(trace_id, entry)
            with self._lock:
                description = entry.abort_description
                context = entry.terminal_context
            if entry.legacy_terminal is not None:
                if not entry.legacy_terminal.done():
                    entry.legacy_terminal.set_result(None)
                assert entry.start_task is not None
                await asyncio.shield(entry.start_task)
            elif description is not None:
                await handle.aabort(description)
            elif context is not None:
                await handle.afinish(context)
        finally:
            with self._lock:
                if self._spans.get(trace_id) is entry:
                    self._spans.pop(trace_id, None)

    @property
    def active_span_count(self) -> int:
        with self._lock:
            return len(self._spans)

    @contextmanager
    def execution_scope(self, trace_id: str):
        """Make the runtime span current only while the governed tool executes."""

        with self._lock:
            entry = self._spans.get(trace_id)
            handle = None if entry is None else entry.handle
        if handle is None:
            with nullcontext():
                yield
            return
        try:
            from opentelemetry.trace import use_span
        except ImportError:
            with nullcontext():
                yield
            return
        with use_span(
            handle.span,
            end_on_exit=False,
            record_exception=False,
            set_status_on_exception=False,
        ):
            yield

    async def _start_span_async(
        self,
        context: ExecutionContext,
        entry: _SpanEntry,
    ) -> _SpanHandle:
        """Start ordinary tracer spans through the async-first extension boundary."""

        attributes = self._span_attributes(context)
        start_span = getattr(self._tracer, "start_span", None)
        if callable(start_span):
            kwargs: dict[str, Any] = {"attributes": attributes}
            if self._parent_context is not None:
                kwargs["context"] = self._parent_context
            callback = start_span
            if not entry.native_start:
                callback = self._observe_sync_start_result(start_span, entry)
            try:
                span = await invoke_extension(
                    callback,
                    f"tool.{context.tool_call.name}",
                    **kwargs,
                )
            except TypeError:
                if self._parent_context is None:
                    raise
                fallback_attributes = {
                    **attributes,
                    "arg.parent_context_dropped": True,
                }
                span = await invoke_extension(
                    callback,
                    f"tool.{context.tool_call.name}",
                    attributes=fallback_attributes,
                )
            return self._handle(span)
        # This legacy compatibility path has no detached span API. Its manager
        # owns a ContextVar token, so crossing worker threads would make a later
        # ``__exit__`` invalid. OpenTelemetry tracers expose ``start_span``.
        raise TypeError("tracer must provide start_span")

    async def _run_start_span_lifecycle(
        self,
        context: ExecutionContext,
        entry: _SpanEntry,
    ) -> _SpanHandle:
        """Keep a deliberately admitted start alive for its terminal cleanup."""

        with extension_lifecycle_scope():
            return await self._start_span_async(context, entry)

    def _observe_sync_start_result(
        self,
        callback: Any,
        entry: _SpanEntry,
    ) -> Any:
        """Record when a sync adapter hands control back as an awaitable."""

        def observed(*args: Any, **kwargs: Any) -> Any:
            value = callback(*args, **kwargs)
            if inspect.isawaitable(value):
                with self._lock:
                    entry.start_result_awaitable = True
                    cancel = entry.abort_description is not None
                    start_task = entry.start_task
                    owner_loop = entry.owner_loop
                if cancel and start_task is not None and owner_loop is not None:
                    owner_loop.call_soon_threadsafe(start_task.cancel)
            return value

        return observed

    def _span_attributes(self, context: ExecutionContext) -> dict[str, Any]:
        attributes = {
            "arg.trace_id": context.trace_id,
            "arg.span_id": context.span_id,
            "arg.parent_span_id": context.parent_span_id,
            "arg.request_id": context.request_id,
            "arg.tool.name": context.tool_call.name,
            "arg.risk.tier": context.risk_tier.name,
            "arg.action.digest": (
                context.bound_action.action_digest
                if context.bound_action is not None
                else None
            ),
            "arg.action.contract.id": (
                context.bound_action.contract.contract_id
                if context.bound_action is not None
                else None
            ),
            "arg.action.contract.version": (
                context.bound_action.contract.contract_version
                if context.bound_action is not None
                else None
            ),
        }
        return {key: value for key, value in attributes.items() if value is not None}

    def _start_current_span(
        self, context: ExecutionContext, attributes: dict[str, Any]
    ) -> _SpanHandle:
        manager = self._current_span_manager(context, attributes)
        return self._handle(manager.__enter__(), manager=manager)

    async def _run_current_span_manager(
        self, context: ExecutionContext, entry: _SpanEntry
    ) -> None:
        """Own a legacy ContextVar manager until its terminal lifecycle event."""

        handle: _SpanHandle | None = None
        try:
            manager = self._current_span_manager(context, self._span_attributes(context))
            handle = self._handle(manager.__enter__(), manager=manager)
            with self._lock:
                entry.handle = handle
            assert entry.ready is not None
            entry.ready.set_result(handle)
            assert entry.legacy_terminal is not None
            await asyncio.shield(entry.legacy_terminal)
            with self._lock:
                description = entry.abort_description
                terminal_context = entry.terminal_context
            if description is not None:
                handle.abort(description)
            elif terminal_context is not None:
                handle.finish(terminal_context)
            else:
                handle.abort("legacy telemetry span closed without terminal context")
        except BaseException as exc:
            if handle is None:
                if entry.ready is not None and not entry.ready.done():
                    entry.ready.set_exception(exc)
            elif not handle.ended:
                try:
                    handle.abort("legacy telemetry span owner stopped")
                except BaseException:
                    try:
                        handle._end()
                    except BaseException:
                        pass
            raise

    def _current_span_manager(
        self, context: ExecutionContext, attributes: dict[str, Any]
    ) -> Any:
        start_as_current = getattr(self._tracer, "start_as_current_span", None)
        if callable(start_as_current):
            kwargs: dict[str, Any] = {"attributes": attributes}
            if self._parent_context is not None:
                kwargs["context"] = self._parent_context
            return start_as_current(f"tool.{context.tool_call.name}", **kwargs)
        raise TypeError("tracer must provide start_span or start_as_current_span")

    def _handle(self, span: Span, *, manager: Any = None) -> _SpanHandle:
        return _SpanHandle(
            span=span,
            manager=manager,
            manager_owner_task=(asyncio.current_task() if manager is not None else None),
            status_cls=self._status_cls
            or _exposed_type(span, "Status", "status_cls"),
            status_code_cls=self._status_code_cls
            or _exposed_type(span, "StatusCode", "status_code_cls"),
        )


def _set_span_terminal_state(
    span: Span,
    context: ExecutionContext,
    *,
    status_cls: Any = None,
    status_code_cls: Any = None,
) -> None:
    if context.status is ExecutionStatus.SUCCEEDED:
        _set_status(
            span,
            "OK",
            "succeeded",
            status_cls=status_cls,
            status_code_cls=status_code_cls,
        )
        return
    if context.status in {
        ExecutionStatus.FAILED,
        ExecutionStatus.DENIED,
        ExecutionStatus.UNKNOWN,
    }:
        description = context.status.value
        if context.status in {ExecutionStatus.FAILED, ExecutionStatus.UNKNOWN}:
            _record_exception(
                span,
                RuntimeError(f"tool execution ended with status {description}"),
            )
        _set_status(
            span,
            "ERROR",
            description,
            status_cls=status_cls,
            status_code_cls=status_code_cls,
        )


async def _aset_span_terminal_state(
    span: Span,
    context: ExecutionContext,
    *,
    status_cls: Any = None,
    status_code_cls: Any = None,
) -> None:
    if context.status is ExecutionStatus.SUCCEEDED:
        await _aset_status(
            span,
            "OK",
            "succeeded",
            status_cls=status_cls,
            status_code_cls=status_code_cls,
        )
        return
    if context.status in {
        ExecutionStatus.FAILED,
        ExecutionStatus.DENIED,
        ExecutionStatus.UNKNOWN,
    }:
        description = context.status.value
        if context.status in {ExecutionStatus.FAILED, ExecutionStatus.UNKNOWN}:
            await _arecord_exception(
                span,
                RuntimeError(f"tool execution ended with status {description}"),
            )
        await _aset_status(
            span,
            "ERROR",
            description,
            status_cls=status_cls,
            status_code_cls=status_code_cls,
        )


def _set_status(
    span: Span,
    code_name: str,
    description: str,
    *,
    status_cls: Any = None,
    status_code_cls: Any = None,
) -> None:
    setter = getattr(span, "set_status", None)
    if not callable(setter):
        return
    status_cls = status_cls or _exposed_type(span, "Status", "status_cls")
    status_code_cls = status_code_cls or _exposed_type(
        span, "StatusCode", "status_code_cls"
    )
    if status_cls is None or status_code_cls is None:
        _warn_missing_status_types_once()
        return
    code = status_code_cls.OK if code_name == "OK" else status_code_cls.ERROR
    setter(
        status_cls(code)
        if code is status_code_cls.OK
        else status_cls(code, description=description)
    )


async def _aset_status(
    span: Span,
    code_name: str,
    description: str,
    *,
    status_cls: Any = None,
    status_code_cls: Any = None,
) -> None:
    setter = getattr(span, "set_status", None)
    if not callable(setter):
        return
    status_cls = status_cls or _exposed_type(span, "Status", "status_cls")
    status_code_cls = status_code_cls or _exposed_type(
        span, "StatusCode", "status_code_cls"
    )
    if status_cls is None or status_code_cls is None:
        _warn_missing_status_types_once()
        return
    code = status_code_cls.OK if code_name == "OK" else status_code_cls.ERROR
    status = (
        status_cls(code)
        if code is status_code_cls.OK
        else status_cls(code, description=description)
    )
    await invoke_extension(setter, status)


def _exposed_type(owner: Any, *names: str) -> Any:
    for candidate in (owner, type(owner)):
        for name in names:
            value = getattr(candidate, name, None)
            if value is not None:
                return value
    return None


def _warn_missing_status_types_once() -> None:
    global _STATUS_WARNING_EMITTED
    with _STATUS_WARNING_LOCK:
        if _STATUS_WARNING_EMITTED:
            return
        _STATUS_WARNING_EMITTED = True
    warnings.warn(
        "injected OpenTelemetry span exposes set_status but no compatible "
        "Status and StatusCode types; terminal status was not exported",
        RuntimeWarning,
        stacklevel=3,
    )


def _record_exception(span: Span, exc: BaseException) -> None:
    recorder = getattr(span, "record_exception", None)
    if callable(recorder):
        recorder(exc)


async def _arecord_exception(span: Span, exc: BaseException) -> None:
    recorder = getattr(span, "record_exception", None)
    if callable(recorder):
        await invoke_extension(recorder, exc)


def _set_span_attribute(span: Span, key: str, value: Any) -> None:
    if value is not None:
        span.set_attribute(key, value)


async def _aset_span_attribute(span: Span, key: str, value: Any) -> None:
    if value is not None:
        await invoke_extension(span.set_attribute, key, value)
