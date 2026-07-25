# Agent Runtime Governance

[![CI](https://github.com/Success6666/agent-runtime-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/Success6666/agent-runtime-governance/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)
[![Release: v0.4.0](https://img.shields.io/badge/release-v0.4.0-6f42c1.svg)](https://github.com/Success6666/agent-runtime-governance/releases/tag/v0.4.0)

A lightweight, framework-agnostic runtime governance framework for AI agents.
It governs an immutable `ExecutionContext` through a deterministic middleware
pipeline, then produces an explicit decision, an auditable execution, and a
replayable trace.

## Quick start

```bash
pip install "agent-runtime-governance @ git+https://github.com/Success6666/agent-runtime-governance.git@v0.4.0"
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
- `examples/crewai_integration.py`: CrewAI decorated tool
- `examples/agno_integration.py`: Agno function tool
- `examples/llamaindex_integration.py`: LlamaIndex `FunctionTool`
- `examples/autogen_integration.py`: Microsoft AutoGen `FunctionTool`
- `scripts/replay.py`: print the snapshots for a trace from JSONL audit data

Each framework adapter is intentionally an example rather than a runtime
dependency. The governed function remains ordinary Python and can be wrapped by
the framework's native tool interface.

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

## Policies, snapshots, and regression

Load a strict versioned policy with a deterministic digest:

```python
from agent_runtime_governance import Runtime, YAMLPolicyLoader

document = YAMLPolicyLoader.load("examples/policy.yaml")
runtime = Runtime([document.middleware()])
print(document.version, document.digest)
```

Duplicate tool entries, unknown fields, invalid risks, and unsafe YAML tags are
rejected. YAML remains a configuration format over the deliberately small
`SimplePolicy` model; it is not a general policy language.

`SnapshotMiddleware` records immutable lifecycle snapshots. `ReplayDebugger`
prints timelines and field-level diffs, while `EvaluationSuite` runs governance
without executing tools. `PolicyDriftDetector` reapplies deterministic policy to
the same recorded request identity and reports decision or risk changes.

```bash
python scripts/trace_debug.py snapshots.jsonl TRACE_ID
python scripts/trace_debug.py snapshots.jsonl TRACE_ID --diff 0 1
python scripts/trace_debug.py snapshots.jsonl TRACE_ID --mermaid
```

## Plugins and integrations

Plugins register components during construction; the built runtime remains
immutable:

```python
from agent_runtime_governance import OPAClient, OPAPlugin, PluginManager

manager = PluginManager()
manager.load(OPAPlugin(OPAClient("http://localhost:8181", "agents/tools/allow")))
runtime = manager.build()
```

Third-party plugins can publish the Python entry-point group
`agent_runtime_governance.plugins`. Entry points execute Python code and must be
treated as trusted dependencies. The project does not download plugins or
provide a marketplace.

| Integration | Extra | Behavior |
| --- | --- | --- |
| Prometheus | `prometheus` | Terminal status and duration; no trace/user labels |
| Slack | none | Denial/failure notifications; official HTTPS webhooks only |
| OPA | none | Minimal decision input; fail closed by default |
| LangGraph | `langgraph` | Governed function in a graph node |
| OpenAI Agents SDK | `openai-agents` | Governed async function tool |
| CrewAI | `crewai` | Decorated governed async tool |
| Agno | `agno` | Typed governed Python function |
| LlamaIndex | `llamaindex` | Governed `FunctionTool` async function |
| Microsoft AutoGen | `autogen` | Governed `FunctionTool` async function |

Install only the integrations an application uses:

```bash
pip install "agent-runtime-governance[yaml,prometheus,crewai]"
```

## Releases

| Version | Scope |
| --- | --- |
| v0.1.0 | Immutable context, registry, rule/LLM/approval/audit middleware, basic replay |
| v0.2.0 | Hooks, Python policy, metrics, retry, timeout, and OpenTelemetry bridge |
| v0.3.0 | Strict YAML policy, snapshots, replay diff, evaluation, and policy drift |
| v0.4.0 | Trusted plugins, Prometheus, Slack, OPA, and six framework integrations |

All four versions are preserved as immutable Git tags. See
[CHANGELOG.md](CHANGELOG.md) for the detailed compatibility and security notes.

## Non-goals

- Agent planning, prompting, model routing, or memory
- Multi-agent communication or distributed execution
- Approval UI or a hosted control plane
- A general policy language, plugin marketplace, or mutable live pipeline
- Production-grade time-travel debugging
- Arbitrary condition evaluation, policy inheritance, or conflict resolution

See [ARCHITECTURE.md](ARCHITECTURE.md) for invariants and
[ROADMAP.md](ROADMAP.md) for the deliberately staged scope. Security reports and
integration boundaries are documented in [SECURITY.md](SECURITY.md).

## Development

```bash
python -m pip install -e ".[dev]"
pytest
python -m build
```

Python 3.10+ is supported. The core package has no runtime dependencies.

Pull requests to `main` must pass every CI job, resolve CodeRabbit blocking
reviews, and receive one approval from the code owner. Repository administrators
retain direct-push access for controlled maintenance and release operations.

## License

MIT
