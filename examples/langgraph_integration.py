"""Optional LangGraph adapter using the governed tool as a node function."""

from typing import TypedDict

from agent_runtime_governance import Runtime

try:
    from langgraph.graph import END, START, StateGraph
except ImportError as exc:  # pragma: no cover - optional example dependency
    raise SystemExit("Install with: pip install 'agent-runtime-governance[langgraph]'") from exc


class State(TypedDict):
    path: str
    content: str


runtime = Runtime()


@runtime.tool()
def read_file(path: str) -> str:
    with open(path, encoding="utf-8") as stream:
        return stream.read()


def governed_tool_node(state: State) -> State:
    return {**state, "content": read_file(state["path"])}


builder = StateGraph(State)
builder.add_node("governed_tool", governed_tool_node)
builder.add_edge(START, "governed_tool")
builder.add_edge("governed_tool", END)
graph = builder.compile()


if __name__ == "__main__":
    print(graph.invoke({"path": "README.md", "content": ""})["content"][:80])

