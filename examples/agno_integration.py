"""Agno function tool backed by the governance runtime."""

from agent_runtime_governance import Runtime

try:
    from agno.agent import Agent
except ImportError as exc:  # pragma: no cover - optional example dependency
    raise SystemExit("Install with: pip install 'agent-runtime-governance[agno]'") from exc


runtime = Runtime()


@runtime.tool()
def service_status(service: str) -> str:
    return f"{service}: healthy"


def governed_service_status(service: str) -> str:
    """Return service status through runtime governance."""
    return service_status(service)


agent = Agent(tools=[governed_service_status])

