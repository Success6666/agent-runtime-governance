from typing import TypedDict

import pytest


class _ConformanceState(TypedDict):
    service: str
    secret: str
    caller_metadata: dict[str, object]
    observation: str


@pytest.mark.asyncio
@pytest.mark.parametrize("case_name", ("success", "policy_denied", "approval_denied"))
async def test_langgraph_node_matches_standalone_protected_semantics(
    case_name,
    conformance_case,
    forged_metadata,
    new_conformance_harness,
    assert_protected_semantics,
    observation_from_json,
) -> None:
    graph_module = pytest.importorskip(
        "langgraph.graph",
        reason="install agent-runtime-governance[langgraph] to run LangGraph conformance",
    )
    case = conformance_case(case_name)

    async with new_conformance_harness(case) as baseline_harness:
        baseline = await baseline_harness.invoke(
            case, case.service, case.secret, forged_metadata
        )

    async with new_conformance_harness(case) as framework_harness:
        async def governed_node(state: _ConformanceState) -> dict[str, str]:
            observation = await framework_harness.invoke(
                case,
                state["service"],
                state["secret"],
                state["caller_metadata"],
            )
            return {"observation": observation.to_json()}

        builder = graph_module.StateGraph(_ConformanceState)
        builder.add_node("governed_lookup", governed_node)
        builder.add_edge(graph_module.START, "governed_lookup")
        builder.add_edge("governed_lookup", graph_module.END)
        graph = builder.compile()
        output = await graph.ainvoke(
            {
                "service": case.service,
                "secret": case.secret,
                "caller_metadata": forged_metadata,
                "observation": "",
            }
        )

    observation = observation_from_json(output["observation"])
    assert_protected_semantics(case, baseline)
    assert_protected_semantics(case, observation)
    assert observation == baseline
