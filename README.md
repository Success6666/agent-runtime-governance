# Agent Runtime Governance

A lightweight, framework-agnostic runtime governance framework for AI agents.
It governs an immutable `ExecutionContext` through a deterministic middleware
pipeline, then produces an explicit decision, an auditable execution, and a
replayable trace.

## 30-second start

```bash
pip install agent-runtime-governance
```

```python
from agent_runtime_governance import Runtime

runtime = Runtime()

@runtime.tool()
def read_file(path: str) -> str:
    return open(path, encoding="utf-8").read()

print(read_file("README.md"))
```

Add deterministic rules, semantic review, human decisions, and signed audit:

```python
from agent_runtime_governance import (
    ApprovalMiddleware, AuditMiddleware, HumanDecisionProvider,
    InvocationOptions, JSONLAuditSink, LLMMiddleware, RiskTier,
    Rule, RuleMiddleware, Runtime,
)

runtime = Runtime([
    RuleMiddleware([Rule("explicit-wipe", r"\bwipe\s+all\b", "bulk wipe is forbidden")]),
    LLMMiddleware(lambda ctx: True),
    ApprovalMiddleware(HumanDecisionProvider(lambda ctx, request: True)),
    AuditMiddleware(JSONLAuditSink("audit.log", sign_key="replace-me")),
])

@runtime.tool(risk=RiskTier.HIGH, requires_approval=True)
def delete_file(path: str) -> bool:
    return True

delete_file(
    "old.log",
    _governance=InvocationOptions(input_text="remove the old application log"),
)
```

## Why it exists

| Approach | Deterministic boundary | Human decision | Audit and replay |
| --- | --- | --- | --- |
| Prompt-only guardrails | No | Ad hoc | No |
| Hand-written permission checks | Partial | Application-specific | Ad hoc |
| Agent Runtime Governance | Yes | Provider interface | Built in |

Prompt instructions are useful guidance, but they are not an authorization
boundary. This project places deterministic policy, explicit decisions, and
audit outside the model while remaining independent from agent planning and
model providers.

## Architecture

```text
Tool Registry
     |
     v
Immutable ExecutionContext
     |
     v
Runtime Pipeline
  Rule -> LLM -> Human Decision -> Audit
     |
     v
Explicit Decision -> Tool Executor -> Final Audit Snapshot
```

Gating middleware may stop execution and fails closed. Observing middleware
cannot grant permission and its failure does not interrupt an allowed tool.
Earlier denials cannot be overridden by later middleware.

## Design principles

1. **Deterministic first** - code and policy establish the execution boundary.
2. **Policy over prompt** - prompts guide behavior; policies authorize actions.
3. **Defense in depth** - independent controls can only tighten a decision.
4. **Framework agnostic** - the runtime does not own planning or model calls.
5. **Human in the loop** - applications supply the decision channel.
6. **Observability by default** - each transition produces traceable state.
7. **Immutable context** - middleware returns a new context instead of mutating
   shared state.

## Examples

- `examples/standalone_demo.py`: framework-free pipeline
- `examples/cli_approval_demo.py`: interactive human decision provider
- `examples/langgraph_integration.py`: LangGraph tool-node integration
- `examples/openai_agents_integration.py`: OpenAI Agents SDK tool integration
- `scripts/replay.py`: print the snapshots for a trace from JSONL audit data

## Engineering controls

v0.2 adds immutable pipeline composition, lifecycle hooks, Python-native policy,
metrics, retries, timeouts, and optional OpenTelemetry export:

```python
from agent_runtime_governance import (
    MetricsMiddleware, Pipeline, PolicyMiddleware, RetryMiddleware,
    SimplePolicy, TimeoutMiddleware,
)

pipeline = Pipeline([
    PolicyMiddleware(SimplePolicy(admin_only={"restart_service"})),
    RetryMiddleware(max_attempts=2),
    TimeoutMiddleware(5.0),
    MetricsMiddleware(),
])
runtime = Runtime(pipeline)

@runtime.before_tool
def attach_region(ctx):
    return ctx.evolve(metadata={**ctx.metadata, "region": "cn-beijing"})
```

Pipeline edits return a new `Pipeline`; a live runtime is never mutated behind
concurrent calls. Hooks may enrich context but cannot change status or decisions.

## Non-goals

- Agent planning, prompting, model routing, or memory
- Multi-agent communication or distributed execution
- Approval UI or a hosted control plane
- A general policy language, plugin marketplace, or mutable live pipeline
- Production-grade time-travel debugging

See [ARCHITECTURE.md](ARCHITECTURE.md) for invariants and
[ROADMAP.md](ROADMAP.md) for the deliberately staged scope.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
python -m build
```

Python 3.10+ is supported. The core package has no runtime dependencies.

## License

MIT
