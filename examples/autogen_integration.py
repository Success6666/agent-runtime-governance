"""Microsoft AutoGen FunctionTool backed by the governance runtime."""

from agent_runtime_governance import Runtime

try:
    from autogen_core.tools import FunctionTool
except ImportError as exc:  # pragma: no cover - optional example dependency
    raise SystemExit("Install with: pip install 'agent-runtime-governance[autogen]'") from exc


runtime = Runtime()


@runtime.tool()
def service_status(service: str) -> str:
    return f"{service}: healthy"


async def governed_service_status(service: str) -> str:
    return await service_status.ainvoke(service)


autogen_tool = FunctionTool(
    governed_service_status,
    description="Return service status through runtime governance.",
)
