"""Optional OpenAI Agents SDK adapter for a governed tool."""

from agent_runtime_governance import Runtime

try:
    from agents import Agent, Runner, function_tool
except ImportError as exc:  # pragma: no cover - optional example dependency
    raise SystemExit(
        "Install with: pip install 'agent-runtime-governance[openai-agents]'"
    ) from exc


runtime = Runtime()


@runtime.tool()
def lookup_status(service: str) -> str:
    return f"{service}: healthy"


@function_tool
async def governed_lookup_status(service: str) -> str:
    """Return service status through the governance runtime."""
    return await lookup_status.ainvoke(service)


agent = Agent(
    name="operations-assistant",
    instructions="Use the governed status tool when service state is requested.",
    tools=[governed_lookup_status],
)


if __name__ == "__main__":
    result = Runner.run_sync(agent, "Check the api service")
    print(result.final_output)
