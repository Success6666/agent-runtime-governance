from agent_runtime_governance import (
    ApprovalMiddleware,
    HumanDecisionProvider,
    RiskTier,
    Runtime,
)


def ask_user(context, request) -> bool:
    answer = input(f"Allow {request.tool_name} on trace {request.trace_id}? [y/N] ")
    return answer.strip().lower() == "y"


runtime = Runtime([ApprovalMiddleware(HumanDecisionProvider(ask_user))])


@runtime.tool(risk=RiskTier.HIGH, requires_approval=True)
def restart_service(name: str) -> str:
    return f"restarted {name}"


if __name__ == "__main__":
    print(restart_service("demo"))

