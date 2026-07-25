from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Callable, Iterable, ParamSpec, TypeVar

from .context import (
    ExecutionContext,
    ExecutionStatus,
    HistoryEntry,
    RiskTier,
    ToolCall,
)
from .decisions import DecisionOutcome, DecisionRecord
from .errors import ExecutionControlError, GovernanceDenied, ToolExecutionError
from .hooks import CriticalHookError, HookCallback, HookPoint, HookRegistry
from .middleware.base import ExecutionCall, ExecutionMiddleware, Middleware, MiddlewareKind
from .pipeline import Pipeline
from .registry import GovernedTool, ToolRegistry, ToolSpec

P = ParamSpec("P")
R = TypeVar("R")


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
    metadata: dict[str, Any] | None = None


class Runtime:
    """Executes registered tools through a deterministic governance pipeline."""

    def __init__(
        self,
        pipeline: Pipeline | Iterable[Middleware] = (),
        *,
        hooks: HookRegistry | None = None,
    ) -> None:
        self.pipeline = pipeline if isinstance(pipeline, Pipeline) else Pipeline(pipeline)
        self.hooks = hooks or HookRegistry()
        self.registry = ToolRegistry()

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
    ) -> Callable[[Callable[P, R]], GovernedTool[P, R]]:
        def decorator(function: Callable[P, R]) -> GovernedTool[P, R]:
            spec = ToolSpec(
                name=name or function.__name__,
                function=function,
                risk=risk,
                requires_approval=requires_approval,
                description=description or (function.__doc__ or ""),
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
        spec = self.registry.get(name)
        options = _governance or InvocationOptions()
        context = ExecutionContext.create(
            ToolCall(name=name, args=args, kwargs=kwargs),
            input_text=options.input_text,
            user=options.user,
            tenant=options.tenant,
            permissions=options.permissions,
            task_id=options.task_id,
            conversation_id=options.conversation_id,
            risk_tier=spec.risk,
            requires_approval=spec.requires_approval,
            metadata=options.metadata,
        )
        context = await self._emit_hook(
            HookPoint.BEFORE_PIPELINE, context, allow_critical=True
        )
        context = await self._run_pre_pipeline(context)
        context = await self._emit_hook(
            HookPoint.AFTER_PIPELINE, context, allow_critical=True
        )
        if context.denied:
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
        if context.denied:
            context = await self._run_observers(context, post=True)
            raise GovernanceDenied(context)
        started = perf_counter()
        try:
            async def execute_tool(
                current: ExecutionContext,
            ) -> tuple[ExecutionContext, Any]:
                if inspect.iscoroutinefunction(spec.function):
                    value = await spec.function(*args, **kwargs)
                else:
                    value = await asyncio.to_thread(spec.function, *args, **kwargs)
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
                    return await current_middleware.execute(current, call_next)

                call = wrapped
            context, value = await call(context)
        except ExecutionControlError as exc:
            context = exc.context
            cause = exc.cause
            context = self._failed_context(context, cause, started)
            context = await self._emit_hook(HookPoint.ON_ERROR, context, allow_critical=False)
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, cause) from cause
        except Exception as exc:
            context = self._failed_context(context, exc, started)
            context = await self._emit_hook(HookPoint.ON_ERROR, context, allow_critical=False)
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, exc) from exc

        metadata = {**context.metadata, "duration_ms": (perf_counter() - started) * 1000}
        context = context.evolve(
            status=ExecutionStatus.SUCCEEDED,
            result=value,
            metadata=metadata,
        ).append_history(HistoryEntry("executor", "succeeded", "tool completed"))
        context = await self._emit_hook(
            HookPoint.AFTER_EXECUTE, context, allow_critical=False
        )
        context = await self._run_observers(context, post=True)
        return RunResult(value=value, context=context)

    async def _run_pre_pipeline(self, context: ExecutionContext) -> ExecutionContext:
        for middleware in self.pipeline:
            if middleware.kind is MiddlewareKind.EXECUTION:
                continue
            if context.denied and middleware.kind is MiddlewareKind.GATING:
                continue
            try:
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=True
                )
                if context.denied and middleware.kind is MiddlewareKind.GATING:
                    continue
                context = await middleware.process(context)
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=False
                )
            except Exception as exc:
                if middleware.kind is MiddlewareKind.OBSERVING:
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

    async def _run_observers(
        self, context: ExecutionContext, *, post: bool
    ) -> ExecutionContext:
        if not post:
            return context
        for middleware in self.pipeline:
            if middleware.kind is not MiddlewareKind.OBSERVING:
                continue
            try:
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=True
                )
                context = await middleware.process(context)
                context = await self._emit_middleware_hook(
                    middleware.name, context, before=False
                )
            except Exception as exc:
                context = context.append_history(
                    HistoryEntry(middleware.name, "error", f"observer ignored: {exc}")
                )
        return context

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
            return await self.hooks.emit(
                point, context, allow_critical=allow_critical
            )
        except CriticalHookError as exc:
            decision = DecisionRecord(
                DecisionOutcome.DENY, str(exc), f"hook:{point.value}"
            )
            return context.with_decision(decision).append_history(
                HistoryEntry(f"hook:{point.value}", "deny", str(exc))
            )

    @staticmethod
    def _failed_context(
        context: ExecutionContext, exc: Exception, started: float
    ) -> ExecutionContext:
        metadata = {**context.metadata, "duration_ms": (perf_counter() - started) * 1000}
        return context.evolve(
            status=ExecutionStatus.FAILED,
            error=f"{type(exc).__name__}: {exc}",
            metadata=metadata,
        ).append_history(HistoryEntry("executor", "failed", str(exc)))


Harness = Runtime
