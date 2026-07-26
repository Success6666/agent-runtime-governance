from __future__ import annotations

import asyncio
import hashlib
import inspect
from concurrent.futures import Executor, ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from contextvars import copy_context
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from threading import Lock
from time import perf_counter
from typing import Any, Callable, Iterable, Mapping, ParamSpec, TypeVar

from ._context_boundaries import validate_middleware_transition
from ._metadata import metadata_text as _metadata_text
from .action_contracts import ActionContract
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
    ToolExecutionError,
)
from .hooks import CriticalHookError, HookCallback, HookPoint, HookRegistry
from .identity import IdentityProvider, VerifiedPrincipal
from .middleware.base import (
    ExecutionCall,
    ExecutionMiddleware,
    Middleware,
    MiddlewareKind,
)
from .pipeline import Pipeline
from .registry import (
    GovernedTool,
    IdempotencyClaim,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    IdempotencyOutcomeUnknownError,
    IdempotencyStore,
    InMemoryIdempotencyStore,
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


@dataclass(frozen=True, slots=True)
class RunResult:
    value: Any
    context: ExecutionContext


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
        identity_provider: IdentityProvider | None = None,
        require_verified_identity: bool = False,
        limits: RuntimeLimits | None = None,
        sync_executor: Executor | None = None,
        idempotency_executor: Executor | None = None,
    ) -> None:
        self.pipeline = pipeline if isinstance(pipeline, Pipeline) else Pipeline(pipeline)
        self.hooks = hooks or HookRegistry()
        self.registry = ToolRegistry()
        self.idempotency_store = idempotency_store or InMemoryIdempotencyStore()
        self.identity_provider = identity_provider
        self.require_verified_identity = require_verified_identity
        self.limits = limits or RuntimeLimits()
        self._bulkhead = RuntimeBulkhead(self.limits.max_in_flight)
        self._async_tool_bulkhead = RuntimeBulkhead(self.limits.max_in_flight)
        self._sync_bulkhead = RuntimeBulkhead(self.limits.max_in_flight)
        self._owns_sync_executor = sync_executor is None
        self._sync_executor = sync_executor or ThreadPoolExecutor(
            max_workers=self.limits.max_in_flight,
            thread_name_prefix="arg-tool",
        )
        self._owns_idempotency_executor = idempotency_executor is None
        self._idempotency_executor = idempotency_executor or ThreadPoolExecutor(
            max_workers=min(4, self.limits.max_in_flight),
            thread_name_prefix="arg-idempotency",
        )
        self._idempotency_bulkhead = RuntimeBulkhead(
            min(4, self.limits.max_in_flight)
        )
        self._idempotency_poison_lock = Lock()
        self._idempotency_poison: BaseException | None = None
        self._idempotency_draining = 0
        self._closed = False

    def close(self, *, wait: bool = True) -> None:
        """Stop accepting work and release the owned synchronous executor."""
        self._closed = True
        if self._owns_idempotency_executor:
            self._idempotency_executor.shutdown(wait=wait, cancel_futures=True)
        if self._owns_sync_executor:
            self._sync_executor.shutdown(wait=wait, cancel_futures=True)

    async def aclose(self) -> None:
        await asyncio.to_thread(self.close)

    @property
    def sync_executor(self) -> Executor:
        """Return the executor used for synchronous tool bodies."""

        return self._sync_executor

    @property
    def idempotency_executor(self) -> Executor:
        """Return the executor isolated for idempotency-store operations."""

        return self._idempotency_executor

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
            )
            self.registry.register(spec)
            return GovernedTool(self, spec)

        return decorator

    def invoke(self, name: str, *args: Any, **kwargs: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.ainvoke(name, *args, **kwargs))
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
        if self._closed:
            raise RuntimeError("runtime is closed")
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
            execution_args, execution_kwargs = materialize_call(
                spec.function, normalized_parameters
            )
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
            context = await self._handle_cancellation(
                context, started, uncertain=False
            )
            raise GovernanceCancelledError(context) from exc
        claim: IdempotencyClaim | None = None
        heartbeat_task: asyncio.Task[None] | None = None
        tool_returned = False
        execution_started = False
        try:
            if context.execution_mode is ExecutionMode.IDEMPOTENT and context.idempotency_key:
                fingerprint = self._fingerprint(spec.name, normalized_parameters)
                try:
                    claim = await self._acquire_idempotency(
                        self._idempotency_namespace(context),
                        context.idempotency_key,
                        fingerprint,
                        context.deadline,
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
                    value = await await_stage(
                        asyncio.shield(asyncio.wrap_future(claim.future)),
                        stage="idempotency wait",
                        timeout_seconds=timeout,
                        cancellation_grace_seconds=(
                            self.limits.cancellation_grace_seconds
                        ),
                    )
                    value = self._normalize_result(spec, value)
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
                context = await self._commit_approvals(context)
                context = self._enforce_required_approval(context)
                if context.denied:
                    denial = GovernanceDenied(context)
                    await self._finish_idempotency(claim, context, denial)
                    claim = None
                    context = await self._run_observers(context, post=True)
                    raise denial
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
                item
                for item in self.pipeline
                if item.kind is MiddlewareKind.EXECUTION
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
            value = self._normalize_result(spec, value)
            self._enforce_size_limit("result", value, spec.max_result_bytes)
            await self._stop_idempotency_heartbeat(
                heartbeat_task, raise_on_failure=True
            )
            heartbeat_task = None
            await self._finish_idempotency(claim, context, None, value)
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
            context = await self._settle_idempotency(claim, context, cause)
            context = await self._emit_hook(HookPoint.ON_ERROR, context, allow_critical=False)
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, cause) from cause
        except GovernanceDenied as exc:
            await self._stop_idempotency_heartbeat(
                heartbeat_task, raise_on_failure=False
            )
            context = await self._settle_idempotency(
                claim, exc.context, exc
            )
            claim = None
            context = await self._run_observers(context, post=True)
            raise GovernanceDenied(context) from exc
        except asyncio.CancelledError as exc:
            await asyncio.shield(
                self._stop_idempotency_heartbeat(
                    heartbeat_task, raise_on_failure=False
                )
            )
            context = await self._handle_cancellation(
                context,
                started,
                uncertain=execution_started,
                claim=claim,
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
            context = await self._settle_idempotency(claim, context, exc)
            context = await self._emit_hook(HookPoint.ON_ERROR, context, allow_critical=False)
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, exc) from exc

        metadata = {**context.metadata, "duration_ms": (perf_counter() - started) * 1000}
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
        """Evaluate governance without executing the tool."""
        spec = self.registry.get(name)
        context = await self._create_context(spec, args, kwargs, _governance)
        started = perf_counter()
        try:
            self._prepare_parameters(spec, args, kwargs, context.deadline)
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
            context = await self._handle_cancellation(
                context, started, uncertain=False
            )
            raise GovernanceCancelledError(context) from exc

    async def areplay(self, context: ExecutionContext) -> ExecutionContext:
        """Reapply deterministic middleware to a recorded request identity."""
        spec = self.registry.get(context.tool_call.name)
        clean = context.reset_for_replay(
            risk_tier=spec.risk,
            requires_approval=spec.requires_approval,
            execution_mode=spec.execution_mode,
        )
        self._prepare_parameters(
            spec,
            clean.tool_call.args,
            dict(clean.tool_call.kwargs),
            clean.deadline,
        )
        clean = self._enforce_idempotency_key(clean)
        if clean.denied:
            return clean
        replayed = await self._run_pre_pipeline(clean, replayable_only=True)
        return self._enforce_required_approval(replayed)

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
        identity_pending = self.identity_provider is not None or self.require_verified_identity
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
        return await await_stage(
            asyncio.to_thread(self.identity_provider.verify, claims),
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
        return await await_stage(
            call(context),
            stage="tool execution",
            timeout_seconds=timeout,
            cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
        )

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
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise StageTimeoutError(stage, 0.0)
        return min(configured, remaining)

    @classmethod
    def _enforce_size_limit(
        cls, label: str, value: Any, limit: int | None
    ) -> None:
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
        self._bounded_timeout(deadline, self.limits.middleware_timeout_seconds, "request")
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

    @classmethod
    def _fingerprint(cls, name: str, parameters: dict[str, Any]) -> str:
        payload = canonical_json_bytes(
            {"tool": name, "parameters": parameters}, label="idempotency fingerprint"
        )
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _idempotency_namespace(context: ExecutionContext) -> str:
        tenant = context.tenant or "global"
        return f"{tenant}:{context.tool_call.name}"

    @staticmethod
    def _normalize_result(spec: ToolSpec[Any, Any], value: Any) -> Any:
        if (
            spec.result_schema is not None
            or spec.max_result_bytes is not None
            or spec.execution_mode is ExecutionMode.IDEMPOTENT
        ):
            return validate_instance(value, spec.result_schema, label="result")
        return value

    async def _acquire_idempotency(
        self,
        namespace: str,
        key: str,
        fingerprint: str,
        deadline: datetime | None,
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
            future = self._idempotency_executor.submit(
                self.idempotency_store.acquire,
                namespace,
                key,
                fingerprint,
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
                self.idempotency_store.mark_unknown(
                    claim,
                    TimeoutError("request stopped waiting during acquisition"),
                )
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

    async def _finish_idempotency(
        self,
        claim: IdempotencyClaim | None,
        context: ExecutionContext,
        error: BaseException | None,
        value: Any = None,
    ) -> None:
        if claim is None:
            return
        if error is None:
            await self._run_critical_store_operation(
                self.idempotency_store.complete,
                claim,
                value,
                deadline=context.deadline,
                stage="idempotency complete",
            )
        elif context.status is ExecutionStatus.UNKNOWN:
            await self._run_critical_store_operation(
                self.idempotency_store.mark_unknown,
                claim,
                error,
                deadline=context.deadline,
                stage="idempotency mark unknown",
            )
        else:
            await self._run_critical_store_operation(
                self.idempotency_store.fail,
                claim,
                error,
                deadline=context.deadline,
                stage="idempotency fail",
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
    ) -> ExecutionContext:
        try:
            await self._finish_idempotency(claim, context, error, value)
        except Exception as settlement_error:
            changes: dict[str, Any] = {
                "error": (
                    f"{type(settlement_error).__name__}: idempotency ledger "
                    "could not record the final outcome"
                )
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
        for middleware in self.pipeline:
            if middleware.kind is MiddlewareKind.EXECUTION:
                continue
            if replayable_only and not middleware.metadata.replayable:
                continue
            if context.denied and middleware.kind is MiddlewareKind.GATING:
                continue
            try:
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=True
                )
                if context.denied and middleware.kind is MiddlewareKind.GATING:
                    continue
                timeout = self._bounded_timeout(
                    context.deadline,
                    (
                        self.limits.observer_timeout_seconds
                        if middleware.kind is MiddlewareKind.OBSERVING
                        else self.limits.middleware_timeout_seconds
                    ),
                    f"middleware:{middleware.name}",
                )
                candidate = await await_stage(
                    middleware.process(context),
                    stage=f"middleware:{middleware.name}",
                    timeout_seconds=timeout,
                    cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
                )
                context = validate_middleware_transition(
                    context, candidate, middleware.kind
                )
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=False
                )
            except Exception as exc:
                if middleware.kind is MiddlewareKind.OBSERVING:
                    if self._is_critical_observer(middleware, context):
                        decision = DecisionRecord(
                            DecisionOutcome.DENY,
                            f"critical observer {middleware.name!r} failed closed",
                            f"observer:{middleware.name}",
                        )
                        context = context.with_decision(decision).append_history(
                            HistoryEntry(middleware.name, "error", str(exc))
                        )
                        continue
                    context = context.append_history(
                        HistoryEntry(middleware.name, "error", f"observer ignored: {exc}")
                    )
                    continue
                decision = DecisionRecord(
                    DecisionOutcome.DENY,
                    f"gating middleware {middleware.name!r} failed closed",
                    "runtime",
                )
                context = context.with_decision(decision).append_history(
                    HistoryEntry(middleware.name, "error", str(exc))
                )
        if not context.denied:
            context = context.evolve(status=ExecutionStatus.ALLOWED)
        return context

    async def _commit_approvals(
        self, context: ExecutionContext
    ) -> ExecutionContext:
        for middleware in self.pipeline:
            commit = getattr(middleware, "commit_approval", None)
            if callable(commit):
                timeout = self._bounded_timeout(
                    context.deadline,
                    self.limits.middleware_timeout_seconds,
                    "approval commit",
                )
                context = await await_stage(
                    commit(context),
                    stage="approval commit",
                    timeout_seconds=timeout,
                    cancellation_grace_seconds=self.limits.cancellation_grace_seconds,
                )
                if context.denied:
                    break
        return context

    async def _release_approvals(
        self, context: ExecutionContext
    ) -> ExecutionContext:
        for middleware in self.pipeline:
            release = getattr(middleware, "release_approval", None)
            if callable(release):
                try:
                    timeout = self._bounded_timeout(
                        context.deadline,
                        self.limits.middleware_timeout_seconds,
                        "approval release",
                    )
                    context = await await_stage(
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
            or decision.policy_version != _metadata_text(
                context.metadata, "policy_version"
            )
            or decision.policy_digest != _metadata_text(
                context.metadata, "policy_digest"
            )
            or decision.subject != context.user
            or decision.tenant != context.tenant
            or decision.identity_issuer != expected_identity_issuer
        ):
            return False
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
                candidate = await await_stage(
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
    ) -> ExecutionContext:
        if not context.denied:
            context = context.evolve(
                status=(
                    ExecutionStatus.UNKNOWN
                    if uncertain
                    else ExecutionStatus.FAILED
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
            claim, context, asyncio.CancelledError()
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

    async def _abort_observers(
        self, context: ExecutionContext
    ) -> ExecutionContext:
        for middleware in self.pipeline:
            abort = getattr(middleware, "abort", None)
            if not callable(abort):
                continue
            try:
                result = abort(context.trace_id)
                if inspect.isawaitable(result):
                    await await_stage(
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
            return await await_stage(
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
        metadata = {**context.metadata, "duration_ms": (perf_counter() - started) * 1000}
        status = (
            ExecutionStatus.UNKNOWN
            if isinstance(
                exc,
                (TimeoutError, IdempotencyOutcomeUnknownError, IdempotencyInProgressError),
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
