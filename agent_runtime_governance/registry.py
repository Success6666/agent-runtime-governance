from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Generic, ParamSpec, TypeVar

from .context import RiskTier
from .errors import RegistryError

if TYPE_CHECKING:
    from .runtime import Runtime

P = ParamSpec("P")
R = TypeVar("R")


@dataclass(frozen=True, slots=True)
class ToolSpec(Generic[P, R]):
    name: str
    function: Callable[P, R]
    risk: RiskTier
    requires_approval: bool
    description: str


class GovernedTool(Generic[P, R]):
    def __init__(self, runtime: "Runtime", spec: ToolSpec[P, R]) -> None:
        self.runtime = runtime
        self.spec = spec
        self.__name__ = spec.name
        self.__doc__ = spec.function.__doc__

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R:
        return self.runtime.invoke(self.spec.name, *args, **kwargs)

    async def ainvoke(self, *args: P.args, **kwargs: P.kwargs) -> R:
        return await self.runtime.ainvoke(self.spec.name, *args, **kwargs)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec[Any, Any]] = {}

    def register(self, spec: ToolSpec[Any, Any]) -> None:
        if spec.name in self._tools:
            raise RegistryError(f"tool {spec.name!r} is already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec[Any, Any]:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise RegistryError(f"unknown tool {name!r}") from exc

    def list(self) -> tuple[ToolSpec[Any, Any], ...]:
        return tuple(self._tools.values())

