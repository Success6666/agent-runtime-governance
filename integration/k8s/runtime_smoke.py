"""Small package-level runtime check executed by the hardened Kind Job."""

from agent_runtime_governance import (
    ExecutionMode,
    GovernanceDenied,
    InvocationOptions,
    Rule,
    RuleMiddleware,
    Runtime,
)


def main() -> None:
    runtime = Runtime(
        [
            RuleMiddleware(
                [Rule("block-erase", r"\berase\s+all\b", "bulk erase denied")]
            )
        ]
    )
    tool_called = False

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def health() -> str:
        return "ready"

    @runtime.tool()
    def protected() -> None:
        nonlocal tool_called
        tool_called = True

    try:
        if runtime.invoke("health") != "ready":
            raise RuntimeError("runtime health tool returned an unexpected value")
        try:
            runtime.invoke(
                "protected",
                _governance=InvocationOptions(input_text="erase all records"),
            )
        except GovernanceDenied:
            pass
        else:
            raise RuntimeError("rule middleware did not deny the protected tool")
        if tool_called:
            raise RuntimeError("denied Kubernetes runtime tool was executed")
    finally:
        runtime.close()
    print("kubernetes runtime smoke passed")


if __name__ == "__main__":
    main()
