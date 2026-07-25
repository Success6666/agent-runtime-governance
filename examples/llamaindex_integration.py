"""LlamaIndex FunctionTool backed by the governance runtime."""

from agent_runtime_governance import Runtime

try:
    from llama_index.core.tools import FunctionTool
except ImportError as exc:  # pragma: no cover - optional example dependency
    raise SystemExit(
        "Install with: pip install 'agent-runtime-governance[llamaindex]'"
    ) from exc


runtime = Runtime()


@runtime.tool()
def service_status(service: str) -> str:
    return f"{service}: healthy"


async def governed_service_status(service: str) -> str:
    """Return service status through runtime governance."""
    return await service_status.ainvoke(service)


llamaindex_tool = FunctionTool.from_defaults(
    async_fn=governed_service_status,
    name="governed_service_status",
    description="Return service status through runtime governance.",
)

