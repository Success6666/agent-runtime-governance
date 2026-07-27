# Agent Runtime Governance

[![CI](https://github.com/Success6666/agent-runtime-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/Success6666/agent-runtime-governance/actions/workflows/ci.yml)
[![Integration](https://github.com/Success6666/agent-runtime-governance/actions/workflows/integration.yml/badge.svg)](https://github.com/Success6666/agent-runtime-governance/actions/workflows/integration.yml)
[![codecov](https://codecov.io/gh/Success6666/agent-runtime-governance/branch/main/graph/badge.svg)](https://codecov.io/gh/Success6666/agent-runtime-governance)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/agent-runtime-governance.svg)](https://pypi.org/project/agent-runtime-governance/)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)

**The action a reviewer approved is the action that executes. A side effect
with an uncertain outcome is recorded as `UNKNOWN`, and automatic reuse stays
blocked while that idempotency record is retained.**

Two failures motivate this project. An agent retries a payment call after a
network timeout and charges a customer twice. A reviewer approves one tool
call, and something different executes because arguments or governance state
changed between approval and execution. Agent Runtime Governance is an
embeddable, framework-agnostic Python runtime that closes both gaps at the
final execution boundary - the moment a proposed tool call is about to touch the real
world within the configured storage guarantees. It runs inside the agent stack
you already use rather than replacing it. The default in-memory idempotency
store has bounded TTL/LRU retention and does not survive restarts; longer-lived
protection requires a durable store. The current v0.7 implementation adds
durable, deterministic reconciliation for `UNKNOWN` outcomes; it remains under
release verification until the required CI, integration, release-artifact, and
publication evidence is recorded.

Every shipped guarantee links to its regression test:

| Shipped in v0.5.1 | Evidence |
| --- | --- |
| Approval is bound to request ID, tool name, argument digest, risk tier, policy version/digest, subject, tenant, identity issuer, and request expiry. A mismatch or expired request/decision is rejected before the tool body runs | [`test_decision_binding_rejects_wrong_request_or_arguments`](tests/test_approval_identity_hardening.py) |
| Caller-supplied metadata cannot forge approval, policy, or identity state | [`test_caller_metadata_cannot_forge_required_approval`](tests/test_approval_identity_hardening.py) |
| A mutating call with an uncertain outcome is recorded as `UNKNOWN` instead of being retried | [`test_cancellation_propagates_and_marks_context_unknown`](tests/test_production_reliability.py) |
| Idempotency keys are mandatory for idempotent mutating tools and bound to the parameter fingerprint | [`test_idempotency_key_is_bound_to_parameter_fingerprint`](tests/test_execution_hardening.py) |
| JSONL audit is hash-chained and signable; deletion and tampering are detected | [`test_jsonl_audit_hash_chain_detects_deletion_and_tamper`](tests/test_audit_otel_hardening.py) |

v0.6 binds one immutable action across the final execution boundary. Every
claim below is covered by a regression test or recorded benchmark:

| Shipped in v0.6.0 | Evidence |
| --- | --- |
| The exact frozen parameter snapshot covered by `action_digest` reaches the tool body and cannot be replaced by middleware or hooks | [`test_exact_bound_snapshot_reaches_tool_and_audit`](tests/test_bound_action_runtime.py), [`test_middleware_cannot_replace_or_mutate_bound_action`](tests/test_bound_action_runtime.py) |
| Key, policy, and external-precondition drift fail before tool entry | [`test_key_rotation_fails_before_tool_entry`](tests/test_bound_action_runtime.py), [`test_policy_identity_mismatch_fails_closed`](tests/test_bound_action_runtime.py), [`test_precondition_change_fails_before_tool_entry`](tests/test_bound_action_runtime.py) |
| Approval and idempotency consume `action_digest`; v0.5 records remain readable but cannot authorize or satisfy a contracted v0.6 action | [`test_approval_is_bound_to_action_digest`](tests/test_bound_action_runtime.py), [`test_v05_approval_fails_closed_for_contracted_tool`](tests/test_bound_action_runtime.py), [`test_v05_compatibility.py`](tests/test_v05_compatibility.py) |
| Success and terminal exception/timeout/cancellation paths retain the same action identity | [`test_exact_bound_snapshot_reaches_tool_and_audit`](tests/test_bound_action_runtime.py), [`test_exception_and_timeout_keep_bound_action_in_audit`](tests/test_bound_action_runtime.py), [`test_cancellation_keeps_bound_action_in_audit`](tests/test_bound_action_runtime.py) |
| Audit evidence carries the action identity without duplicating raw parameters, and OpenTelemetry exports the same contract/action attributes | [`test_audit_bound_action_never_duplicates_raw_parameters`](tests/test_bound_action_runtime.py), [`test_opentelemetry_exports_bound_action_identity`](tests/test_audit_otel_hardening.py) |
| At 1,000 requests and concurrency 100 on the recorded Windows/Python 3.12 host, the median of three alternating paired runs measured action bind plus verification at 1.553x mean, 1.720x p95, 1.850x p99, and 1.040x peak traced memory versus its strict baseline | [`v0.6.0-windows-python312.json`](benchmarks/results/v0.6.0-windows-python312.json), [`v0.6.0 budget`](benchmarks/budgets/v0.6.0.json) |

The current v0.7 implementation keeps `UNKNOWN` recovery on a durable,
compare-and-set ledger. The following behaviors are implemented and covered by
regression tests; they are not a claim that an external side effect is
exactly-once unless the downstream system independently supports that property.

| Implemented for v0.7 release verification | Evidence |
| --- | --- |
| Before an idempotent side effect can be dispatched, the SQLite claim and bounded recovery descriptor (excluding raw caller key and tool parameters) are created in one transaction; an expired prepared lease materializes an `UNKNOWN` head instead of becoming retryable | [`test_runtime_atomically_prepares_recovery_descriptor_before_dispatch`](tests/test_runtime_reconciliation.py), [`test_expired_atomically_prepared_lease_materializes_reconciliation_head`](tests/test_reconciliation.py) |
| Reconciliation records are append-only and revision-checked. The provider identity, protocol version, and supported evidence kinds persisted with the action must still match after restart | [`test_reconciliation_rejects_provider_drift_after_restart`](tests/test_runtime_reconciliation.py) |
| Reconciliation head/event lineage intent is committed to a SQLite outbox with the matching mutation. Delivery is ordered per execution, retryable, and deduplicated by a stable source event ID at `SQLiteAuditSink` | [`test_reconciliation_audit_outbox_is_ordered_and_redacted`](tests/test_reconciliation.py), [`test_sqlite_audit_source_id_prevents_duplicate_after_ack_failure`](tests/test_runtime_reconciliation.py) |
| Strict control-plane operations require separate probe, manual-resolution, and audit-drain permissions, plus tenant binding for per-action access | [`test_strict_reconciliation_denies_cross_tenant_probe_without_attempt`](tests/test_runtime_reconciliation.py), [`test_strict_global_audit_recovery_requires_its_own_permission`](tests/test_runtime_reconciliation.py) |
| A durable started probe is finalized under an independent budget. An expired unclosed probe is closed with `recovery_required` and moved to `MANUAL_REVIEW`; a second provider probe is not started | [`test_cancellation_during_finish_keeps_finalization_running`](tests/test_runtime_reconciliation.py), [`test_restart_quarantines_an_expired_unfinished_provider_attempt`](tests/test_runtime_reconciliation.py) |
| Control-plane caller deadlines bound audit recovery and delivery; a stalled sink leaves the durable envelope pending rather than corrupting the ledger or holding the process open after shutdown | [`test_global_audit_recovery_honors_its_caller_deadline`](tests/test_runtime_reconciliation.py), [`test_blocked_reconciliation_audit_sink_cannot_hold_python_process_open`](tests/test_runtime_reconciliation.py) |

The staged v0.8-v1.0 direction and its exit criteria are in
[`ROADMAP.md`](ROADMAP.md) and [`docs/production-roadmap.md`](docs/production-roadmap.md).
Planned capabilities are never presented as shipped.

## Quick start

```bash
pip install agent-runtime-governance
```

```python
from pathlib import Path

from agent_runtime_governance import ExecutionMode, Runtime

runtime = Runtime()
WORKSPACE_ROOT = Path.cwd().resolve()

@runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
def read_file(path: str) -> str:
    candidate = (WORKSPACE_ROOT / path).resolve()
    try:
        candidate.relative_to(WORKSPACE_ROOT)
    except ValueError as exc:
        raise ValueError("path must remain inside the workspace") from exc
    return candidate.read_text(encoding="utf-8")

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

## How it compares

Human approval, policy interception, audit, retries, and telemetry are
industry baseline; this project does not claim to have invented them. The
narrow claim is the governed execution boundary. Rows cite each project's own public
documentation and describe scope, not quality.

| Alternative | What it provides | Where this project is narrower and deeper |
| --- | --- | --- |
| Framework-native approvals: [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/guides/human-in-the-loop/), [LangGraph](https://docs.langchain.com/oss/python/langchain/human-in-the-loop), [pydantic-ai deferred tools](https://ai.pydantic.dev/deferred-tools/) | Pause-and-approve flows inside one framework | One framework-neutral runtime where approval is revalidated against the normalized call immediately before execution, combined with idempotent commit and `UNKNOWN` semantics |
| [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | Broad policy, identity, sandboxing, and SRE toolkit | Its [versioned limitations document](https://github.com/microsoft/agent-governance-toolkit/blob/2962693358c26201f2bbc13a54b5966af933accf/docs/LIMITATIONS.md) records that audit captures attempts and allow/deny results, with outcome attestation planned; this project's entire scope is that commit-and-outcome boundary |
| Durable execution engines: [Temporal](https://github.com/temporalio/temporal), [Restate](https://github.com/restatedev/restate), [DBOS](https://github.com/dbos-inc/dbos-transact-py) | Durable workflow state with automatic retries | The governance-layer default is different: an uncertain side effect is recorded as `UNKNOWN` and is not automatically retried while unresolved. v0.7 adds a receipt/probe reconciliation ledger and explicit manual-review path; human approval remains bound to the action identity |
| Content guardrails: [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails), [Guardrails AI](https://github.com/guardrails-ai/guardrails) | Input, output, and dialog rails | A different layer that composes with this one; this project governs the side-effect boundary, not prompts or content |

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
  Prepare -> Bind Action -> Policy -> Human Decision
     |
     v
Action Digest -> Idempotency -> Executor Revalidation -> Tool
     |
     v
Terminal Context -> Evidence-safe Audit Snapshot
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
- `examples/strict_action_contract.py`: sealed contracted side-effecting runtime
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

Load a versioned policy with separate semantic and exact-artifact digests:

```python
from agent_runtime_governance import Runtime, YAMLPolicyLoader

document = YAMLPolicyLoader.load("examples/policy.yaml")
runtime = Runtime([document.artifact_middleware()])
print(document.version, document.digest, document.artifact_digest)
```

Duplicate tool entries, unknown fields, invalid risks, and unsafe YAML tags are
rejected. YAML remains a configuration format over the deliberately small
`SimplePolicy` model; it is not a general policy language. `digest` identifies
normalized policy semantics for compatibility and drift comparison;
`artifact_digest` identifies the exact loaded bytes and is the value strict
production profiles must bind.

`SnapshotMiddleware` records immutable lifecycle snapshots. `ReplayDebugger`
prints timelines and field-level diffs, while `EvaluationSuite` runs governance
without executing tools. `PolicyDriftDetector` reapplies deterministic policy to
the same recorded request identity and reports decision or risk changes.
`Runtime.areplay()` is deliberately non-authoritative: historical identity
fields are analysis inputs, verification metadata is stripped, no tool runs,
and no `BoundAction` is created. Use `apreview()` with current trusted identity
claims when a fresh bound action preview is required.

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

v0.5 establishes the production reliability baseline:

- idempotent tool execution with mandatory keys and in-memory or SQLite stores;
- durable approval recovery with leased reserve/commit/release transitions;
- absolute deadline propagation through admission, middleware, identity, tools,
  and idempotency waits;
- cancellation handling that records mutating in-flight work as `UNKNOWN`;
- trusted HMAC identity envelopes with replay protection;
- contract validation for parameters, results, and payload size limits;
- reliable JSONL and SQLite audit sinks with hash-chain verification;
- bounded concurrency, external integration circuit breakers, and fault tests.

v0.6 adds strict startup inventory and sealing, one
`BoundAction.action_digest` across approval/idempotency/execution/audit,
executor-boundary revalidation, policy and precondition identity checks, and
versioned v0.5 migration readers. See
[`docs/migration-v0.6.md`](docs/migration-v0.6.md) and the runnable
[`strict_action_contract.py`](examples/strict_action_contract.py) example.

The current v0.7 implementation adds an explicit recovery protocol for
idempotent actions whose external outcome is uncertain. Strict deployments
co-locate `SQLiteIdempotencyStore` and `SQLiteReconciliationLedger` in the
same SQLite database so a claim and its recovery descriptor are created before
dispatch. Reconciliation head/event lineage mutations and their audit envelopes
commit together; `SQLiteAuditSink` deduplicates retried envelope delivery with the
outbox source ID. The application must supply a read-only receipt/probe provider;
the runtime binds its identifier, protocol version, and evidence kinds to the
persisted action but cannot prove that third-party provider code has no side
effects.
See [`docs/production.md`](docs/production.md) and
[`docs/migration-v0.7.md`](docs/migration-v0.7.md) before enabling it for
production traffic.

The example hashes the exact policy artifact in `examples/policies/`, passes
that identity through
`PolicyMiddleware` and `ProductionProfile`, seals the runtime, and persists
signed audit plus idempotency state:

```powershell
python -m pip install -e .
$env:ARG_IDENTITY_DIGEST_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:ARG_AUDIT_HMAC_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:ARG_STATE_DIR = ".arg-state-example"
python examples/strict_action_contract.py
Remove-Item -Recurse -Force $env:ARG_STATE_DIR
```

```bash
python -m pip install -e .
export ARG_IDENTITY_DIGEST_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ARG_AUDIT_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ARG_STATE_DIR=.arg-state-example
python examples/strict_action_contract.py
rm -rf -- "$ARG_STATE_DIR"
```

`StaticIdentityProvider` in this example represents one identity already
authenticated by a trusted single-service host boundary. It must not be used
to authenticate arbitrary multi-user requests; use a validating identity
provider at that boundary in production.

The production smoke suite starts real Docker services for OPA and the
OpenTelemetry Collector, exports through OTLP HTTP, scrapes a real HTTP
`/metrics` exposition endpoint, and can run a local Kind smoke with a pinned
node image:

```bash
python integration/production_smoke.py --skip-kind
python integration/production_smoke.py
```

Production deployments must configure a trusted identity provider with
`require_verified_identity=True`; caller-supplied `user`, `tenant`, and
`permissions` fields are compatibility inputs, not a trust boundary. SQLite
stores coordinate processes on one host and require a distributed adapter for
multi-host deployments. For strict v0.7 reconciliation, configure a signed,
durable, source-idempotent audit sink behind a fail-closed `AuditMiddleware`.
`SQLiteAuditSink` is the built-in tested implementation; JSONL audit cannot
deduplicate a replayed outbox envelope. A recovery worker invokes
`Runtime.adrain_reconciliation_audit_outbox()` with a separately authorized
trusted identity, while `Runtime.areconcile()` and
`Runtime.aresolve_reconciliation()` use their own control-plane permissions.

### Release verification

Before a GitHub release is published, maintainers review the required protected
CI matrix (Python 3.10-3.13) and Docker-backed integration smoke. The
post-publication release workflow then repeats the full suite on Python 3.13,
runs dependency audit and package installation checks, and attaches the SPDX
SBOM, SHA256 checksums, and GitHub provenance. PyPI Trusted Publishing is a
separate workflow that consumes those verified release artifacts. Migration
restore drills and public-index installation checks are recorded release
evidence, not inferred from a successful build. Complete point-in-time records
for published releases are in [`docs/release-verification.md`](docs/release-verification.md).

Benchmarks measure incremental runtime overhead for baseline, Rule, OPA, Audit,
OpenTelemetry, 10-middleware pipelines, and paired strict runtimes with and
without action binding:

```bash
python benchmarks/benchmark_runtime.py --requests 100,500,1000 --concurrency 100
```

The committed Windows/Python 3.12 measurement is available in
[`benchmarks/results/v0.5.0-windows-python312.json`](benchmarks/results/v0.5.0-windows-python312.json).
Its 100-waiter, zero-hold FIFO admission test measured 2.93 ms p99 wait time.
This point-in-time result is regression evidence for that machine, not a
cross-platform latency SLA.

The v0.6 final measurement, earlier pre-release measurement, and enforced
paired budget are in
[`benchmarks/results/v0.6.0-windows-python312.json`](benchmarks/results/v0.6.0-windows-python312.json),
[`benchmarks/results/v0.6.0-rc-windows-python312.json`](benchmarks/results/v0.6.0-rc-windows-python312.json),
and [`benchmarks/budgets/v0.6.0.json`](benchmarks/budgets/v0.6.0.json).

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
| v0.5.1 | Security hardening: caller metadata isolation and exact approval binding |
| v0.6.0 | Immutable action contracts from admission through approval, idempotency, executor revalidation, telemetry, and audit |

Released versions are preserved as immutable Git tags. See
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
is defined in [RELEASING.md](RELEASING.md). The evidence-backed v0.6-v1.0
strategy is specified in
[`docs/production-roadmap.md`](docs/production-roadmap.md).

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
head commit, and resolve blocking reviews. A skipped, rate-limited, stale, or
missing CodeRabbit review fails closed. GitHub does not allow a pull request
author to approve their own change, so the single-maintainer phase has no human
approval count; one code-owner approval and last-push approval become mandatory
when a second maintainer is added. Maintainers still use the same issue and pull
request flow as external contributors, and administrators cannot push directly
to `main` or bypass protection.

## License

MIT
