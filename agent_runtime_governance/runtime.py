from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Any, Callable, ParamSpec, TypeVar

from .context import (
    ExecutionContext,
    ExecutionStatus,
    HistoryEntry,
    RiskTier,
    ToolCall,
)
from .decisions import DecisionOutcome, DecisionRecord
from .errors import GovernanceDenied, ToolExecutionError
from .middleware.base import Middleware, MiddlewareKind
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

    def __init__(self, pipeline: list[Middleware] | tuple[Middleware, ...] = ()) -> None:
        self.pipeline = tuple(pipeline)
        self.registry = ToolRegistry()

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
        context = await self._run_pre_pipeline(context)
        if context.denied:
            context = await self._run_observers(context, post=True)
            raise GovernanceDenied(context)

        context = context.evolve(
            status=ExecutionStatus.EXECUTING,
            decision=context.decision
            or DecisionRecord(DecisionOutcome.ALLOW, "pipeline allowed", "runtime"),
        )
        try:
            value = spec.function(*args, **kwargs)
            if inspect.isawaitable(value):
                value = await value
        except Exception as exc:
            context = context.evolve(
                status=ExecutionStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}",
            ).append_history(
                HistoryEntry("executor", "failed", str(exc))
            )
            context = await self._run_observers(context, post=True)
            raise ToolExecutionError(context, exc) from exc

        context = context.evolve(
            status=ExecutionStatus.SUCCEEDED,
            result=value,
        ).append_history(HistoryEntry("executor", "succeeded", "tool completed"))
        context = await self._run_observers(context, post=True)
        return RunResult(value=value, context=context)

    async def _run_pre_pipeline(self, context: ExecutionContext) -> ExecutionContext:
        for middleware in self.pipeline:
            if context.denied and middleware.kind is MiddlewareKind.GATING:
                continue
            try:
                context = await middleware.process(context)
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
                context = await middleware.process(context)
            except Exception as exc:
                context = context.append_history(
                    HistoryEntry(middleware.name, "error", f"observer ignored: {exc}")
                )
        return context


Harness = Runtime
