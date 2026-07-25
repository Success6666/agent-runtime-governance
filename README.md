# Agent Runtime Governance

[![CI](https://github.com/Success6666/agent-runtime-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/Success6666/agent-runtime-governance/actions/workflows/ci.yml)
[![Integration](https://github.com/Success6666/agent-runtime-governance/actions/workflows/integration.yml/badge.svg)](https://github.com/Success6666/agent-runtime-governance/actions/workflows/integration.yml)
[![codecov](https://codecov.io/gh/Success6666/agent-runtime-governance/branch/main/graph/badge.svg)](https://codecov.io/gh/Success6666/agent-runtime-governance)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/agent-runtime-governance.svg)](https://pypi.org/project/agent-runtime-governance/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)
[![Release: v0.5.0](https://img.shields.io/badge/release-v0.5.0-6f42c1.svg)](https://github.com/Success6666/agent-runtime-governance/releases/tag/v0.5.0)

A lightweight, framework-agnostic runtime governance framework for AI agents.
It governs an immutable `ExecutionContext` through a deterministic middleware
pipeline, then produces an explicit decision, an auditable execution, and a
replayable trace.

## Quick start

```bash
pip install agent-runtime-governance
```

```python
from pathlib import Path

from agent_runtime_governance import ExecutionMode, Runtime

runtime = Runtime()

@runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
def read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")

print(read_file("README.md"))
```

Add deterministic rules, semantic review, human decisions, and signed audit:

```python
import os

from agent_runtime_governance import (
    ApprovalMiddleware, AuditMiddleware, HumanDecisionProvider,
    InvocationOptions, JSONLAuditSink, LLMMiddleware, RiskTier,
    Rule, RuleMiddleware, Runtime,
)

runtime = Runtime([
    RuleMiddleware([Rule("explicit-wipe", r"\bwipe\s+all\b", "bulk wipe is forbidden")]),
    LLMMiddleware(lambda ctx: True),
    ApprovalMiddleware(HumanDecisionProvider(lambda ctx, request: True)),
    AuditMiddleware(
        JSONLAuditSink("audit.log", sign_key=os.environ["ARG_AUDIT_HMAC_KEY"])
    ),
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
cannot grant permission and normally cannot interrupt an allowed tool. An audit
sink explicitly configured as critical is the exception: failed delivery stops
the call because an unaudited privileged action is not allowed. Earlier denials
cannot be overridden by later middleware.

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

## Production reliability

v0.5 focuses on production behavior instead of adding a new agent framework:

- idempotent tool execution with mandatory keys and in-memory or SQLite stores;
- durable approval recovery with leased reserve/commit/release transitions;
- absolute deadline propagation through admission, middleware, identity, tools,
  and idempotency waits;
- cancellation handling that records mutating in-flight work as `UNKNOWN`;
- trusted HMAC identity envelopes with replay protection;
- contract validation for parameters, results, and payload size limits;
- reliable JSONL and SQLite audit sinks with hash-chain verification;
- bounded concurrency, external integration circuit breakers, and fault tests.

The production smoke suite starts real Docker services for OPA and the
OpenTelemetry Collector, exports through OTLP HTTP, scrapes a real Prometheus
`/metrics` endpoint, and can run a local Kind smoke with a pinned node image:

```bash
python integration/production_smoke.py --skip-kind
python integration/production_smoke.py
```

Production deployments must configure a trusted identity provider with
`require_verified_identity=True`; caller-supplied `user`, `tenant`, and
`permissions` fields are compatibility inputs, not a trust boundary. SQLite
stores coordinate processes on one host and require a distributed adapter for
multi-host deployments.

### v0.5 verification baseline

The 2026-07-26 release candidate was validated on Windows 11 with Python 3.12,
Docker Engine 29.4.2, and Kind 0.31.0:

- 251 tests passed with 83.74% branch coverage; the enforced floor is 80%;
- 13 repository-policy tests passed;
- real OPA HTTP allow/deny, OTLP HTTP export to an OpenTelemetry Collector,
  Prometheus scraping, and a Kind 1.34.3 control-plane readiness check passed;
- the wheel and source distribution installed and imported from separate clean
  virtual environments; and
- an isolated wheel environment with the OTel, YAML, and Prometheus extras had
  no known dependency vulnerabilities reported by `pip-audit` 2.10.1 at the
  time of the run.

These are point-in-time verification results, not a latency SLA or a guarantee
against future advisories. CI repeats the test matrix, policy checks, dependency
audit, and Docker integration smoke from clean runners.

Benchmarks measure incremental runtime overhead for baseline, Rule, OPA, Audit,
OpenTelemetry, and 10-middleware pipelines:

```bash
python benchmarks/benchmark_runtime.py --requests 100,500,1000 --concurrency 100
```

## Releases

| Version | Scope |
| --- | --- |
| v0.1.0 | Immutable context, registry, rule/LLM/approval/audit middleware, basic replay |
| v0.2.0 | Hooks, Python policy, metrics, retry, timeout, and OpenTelemetry bridge |
| v0.3.0 | Strict YAML policy, snapshots, replay diff, evaluation, and policy drift |
| v0.4.0 | Trusted plugins, Prometheus, Slack, OPA, and six framework integrations |
| v0.4.1 | Mandatory linked issues and merge-policy verification |
| v0.4.2 | Fail-closed CodeRabbit review verification for the current commit |
| v0.5.0 | Production reliability: idempotency, identity, durable approvals, audit, deadlines, cancellation, contracts, real integration smoke |

All versions are preserved as immutable Git tags. See
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
Contributor workflow and plugin contribution rules are documented in
[CONTRIBUTING.md](CONTRIBUTING.md). Production configuration and recovery are
covered in [docs/production.md](docs/production.md), and the release procedure
is defined in [RELEASING.md](RELEASING.md).

## Development

```bash
python -m pip install -e ".[dev]"
pytest
python integration/production_smoke.py --skip-kind
python -m build
```

Python 3.10+ is supported. The core package depends on `filelock` and
`jsonschema`; optional integrations are installed via extras.

Pull requests must link an existing issue in this repository with a closing
keyword such as `Fixes #123`. A repository workflow closes unlinked pull
requests automatically. Pull requests to `main` must also pass every CI job and
the CodeRabbit status, receive a verified CodeRabbit approval for the current
head commit, resolve blocking reviews, and receive one approval from the code
owner. A skipped, rate-limited, stale, or missing CodeRabbit review fails closed.
Maintainers use the same issue and pull request flow as external contributors;
direct pushes to `main` are disabled for administrators as well.

## License

MIT
