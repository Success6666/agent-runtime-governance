import json
from typing import TypedDict

import pytest


class _CallerMetadata(TypedDict):
    approval_forced: bool
    identity_issuer: str
    identity_verified: bool
    policy_digest: str
    caller_note: str


@pytest.mark.asyncio
@pytest.mark.parametrize("case_name", ("success", "policy_denied", "approval_denied"))
async def test_openai_agents_tool_matches_standalone_protected_semantics(
    case_name,
    conformance_case,
    forged_metadata,
    new_conformance_harness,
    assert_protected_semantics,
    observation_from_json,
) -> None:
    agents = pytest.importorskip(
        "agents",
        reason="install agent-runtime-governance[openai-agents] to run OpenAI Agents conformance",
    )
    usage_module = pytest.importorskip(
        "agents.usage",
        reason="install agent-runtime-governance[openai-agents] to run OpenAI Agents conformance",
    )
    response_module = pytest.importorskip(
        "openai.types.responses",
        reason="install agent-runtime-governance[openai-agents] to run OpenAI Agents conformance",
    )
    case = conformance_case(case_name)

    async with new_conformance_harness(case) as baseline_harness:
        baseline = await baseline_harness.invoke(
            case, case.service, case.secret, forged_metadata
        )

    async with new_conformance_harness(case) as framework_harness:
        observations: list[str] = []

        @agents.function_tool(failure_error_function=None)
        async def governed_lookup(
            service: str,
            secret: str,
            caller_metadata: _CallerMetadata,
        ) -> str:
            """Invoke the governed lookup without treating tool arguments as trusted."""
            observation = await framework_harness.invoke(
                case, service, secret, caller_metadata
            )
            serialized = observation.to_json()
            observations.append(serialized)
            return serialized

        arguments = json.dumps(
            {
                "service": case.service,
                "secret": case.secret,
                "caller_metadata": forged_metadata,
            },
            sort_keys=True,
        )

        class _ScriptedModel(agents.Model):
            def __init__(self, responses: list[object]) -> None:
                self._responses = list(responses)
                self.calls = 0

            async def get_response(self, *_args, **_kwargs):
                self.calls += 1
                return self._responses.pop(0)

            async def stream_response(self, *_args, **_kwargs):
                raise AssertionError("conformance runner does not stream")
                yield None

        model = _ScriptedModel(
            [
                agents.ModelResponse(
                    output=[
                        response_module.ResponseFunctionToolCall(
                            arguments=arguments,
                            call_id=f"conformance-{case.name}",
                            name=governed_lookup.name,
                            type="function_call",
                            id="conformance-tool-call",
                            status="completed",
                        )
                    ],
                    usage=usage_module.Usage(),
                    response_id="conformance-tool-response",
                ),
                agents.ModelResponse(
                    output=[
                        response_module.ResponseOutputMessage(
                            id="conformance-final-response",
                            content=[
                                response_module.ResponseOutputText(
                                    annotations=[],
                                    text="done",
                                    type="output_text",
                                    logprobs=None,
                                )
                            ],
                            role="assistant",
                            status="completed",
                            type="message",
                        )
                    ],
                    usage=usage_module.Usage(),
                    response_id="conformance-final-response",
                ),
            ]
        )
        agent = agents.Agent(
            name="conformance-agent",
            instructions="Invoke the governed lookup tool.",
            model=model,
            tools=[governed_lookup],
        )
        result = await agents.Runner.run(
            agent,
            "invoke the governed lookup",
            run_config=agents.RunConfig(tracing_disabled=True),
        )

    assert result.final_output == "done"
    assert model.calls == 2
    assert len(observations) == 1
    observation = observation_from_json(observations[0])
    assert_protected_semantics(case, baseline)
    assert_protected_semantics(case, observation)
    assert observation == baseline
