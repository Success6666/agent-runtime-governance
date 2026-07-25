"""CrewAI custom tool backed by the governance runtime."""

from agent_runtime_governance import Runtime

try:
    from crewai import Agent
    from crewai.tools import tool
except ImportError as exc:  # pragma: no cover - optional example dependency
    raise SystemExit("Install with: pip install 'agent-runtime-governance[crewai]'") from exc


runtime = Runtime()


@runtime.tool()
def service_status(service: str) -> str:
    return f"{service}: healthy"


@tool("Governed Service Status")
async def crewai_service_status(service: str) -> str:
    """Return service status through runtime governance."""
    return await service_status.ainvoke(service)


agent = Agent(
    role="Operations Analyst",
    goal="Report service health through governed tools",
    backstory="An operations analyst with read-only service access.",
    tools=[crewai_service_status],
)

