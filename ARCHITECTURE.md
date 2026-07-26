# Architecture

## Runtime model

Agent Runtime Governance is defined as:

```text
Runtime = immutable ExecutionContext + ordered Pipeline + explicit Decision
```

The runtime owns governance around tool execution. It does not own agent
planning, model selection, prompts, or framework state.

## Invariants

1. Identity and trace fields cannot be rewritten by middleware.
2. Middleware returns a new context; it does not mutate shared context state.
3. A denial is terminal. Later middleware cannot turn it into an allow.
4. Gating failures fail closed.
5. Observing failures are recorded and fail open unless the observer is an
   explicitly configured critical audit sink. Critical audit delivery fails
   closed because an unaudited privileged action is not an allowed outcome.
6. Tool execution happens only after all gating middleware allows it.
7. Every terminal path can emit a structured audit snapshot.
8. Rules inspect the application-supplied user input, not generated internal
   messages or audit records.
9. A contracted invocation has one `BoundAction`; approval, idempotency,
   execution, telemetry, and audit use its `action_digest`.
10. Executor-boundary mismatch denies before tool entry and is never reported
    as an uncertain side effect.

## Context boundaries

Immutable identity fields include trace IDs, principal, permissions, original
user input, the requested tool call, and the optional `BoundAction`. Runtime
code binds the action once after parameter isolation. Governance fields such as
risk score, decision, status, history, result, and metadata evolve by
replacement.

Nested mappings and sequences, including execution result snapshots, are frozen
on context construction. Serialization produces a detached JSON-compatible
representation for audit and replay. The caller-facing tool return remains the
application value and is not replaced by the context snapshot.

For contracted tools, the frozen parameter values stored by `BoundAction` are
also used to materialize the Python call. Immediately before tool entry, the
runtime rebuilds the identity from the actual execution objects and current
trusted key, policy, and precondition inputs. The action digest must match.

## Middleware boundaries

`GatingMiddleware` may tighten risk and approval requirements or deny execution.
It cannot lower existing risk or approval requirements. `ObservingMiddleware`
may append history and add ordinary metadata, but it cannot change request,
governance, execution, or existing metadata state. These boundaries are checked
by the runtime for every returned context, including contexts reconstructed
without `ExecutionContext.evolve()`.

v0.2 represents that list as an immutable `Pipeline`. Composition operations
return a new pipeline, preserving deterministic order and avoiding concurrent
runtime mutation. `ExecutionMiddleware` wraps only the tool executor, enabling
retry and timeout without giving those controls policy authority. Its input and
output are checked again at the innermost tool boundary before the tool body is
called.

Hooks are lightweight observation/enrichment points. They cannot change status
or decisions. A critical pre-execution hook failure is converted into an
explicit denial; post-execution hook failures are recorded without rewriting the
completed outcome.

## Decisions

Human approval is modeled as a `DecisionProvider`, allowing CLI, chat, or HTTP
applications to supply an asynchronous callback. The framework provides the
protocol and suspension point, not a user interface.

Contracted approval requests and decisions carry `action_digest`. A v0.5
approval without that identity is readable but cannot authorize a contracted
v0.6 tool. Contracted idempotency uses a separate `action/v1` namespace and the
same digest as its fingerprint; non-contracted tools retain the v0.5 path.

## Audit and replay

Audit events contain the context snapshot before execution and after completion.
Schema version 3 adds the contract ID, contract version, and action digest. The
nested audit action uses the evidence-safe form without raw parameters, while
controlled snapshot persistence retains the complete isolated snapshot. The
JSONL sink can redact known secret keys and HMAC-sign each record. v0.1
replay intentionally only loads and prints these snapshots; it does not execute
tools again.

v0.3 adds a separate snapshot store for debugger and regression workflows.
Replay preserves historical request fields only as non-authoritative policy
test inputs and runs middleware whose metadata declares it replayable. It strips
identity-verification metadata and never creates an executor-authoritative
`BoundAction`. External model review, human interaction, metrics, retries,
audit, and telemetry are never invoked by deterministic replay. A fresh bound
preview uses `apreview()` and the current trusted identity provider.

Policy documents expose a formatting-independent semantic digest and an exact
artifact-byte digest. Strict production identity uses the artifact digest;
drift analysis may use semantic identity. Duplicate tool rules are rejected
instead of introducing an implicit conflict-resolution language. Drift
detection compares outcomes and risk tiers after applying two deterministic
pipelines to the same historical request input.

## Plugin boundary

Plugins modify a `RuntimeBuilder`, not a running `Runtime`. Registration is
validated transactionally and rolled back if a plugin introduces an invalid
pipeline. Named services, audit sinks, and decision providers are exposed as
read-only mappings after registration.

Python entry points are a trusted-code mechanism. Discovery never installs or
downloads packages. Applications must pin, review, and verify every plugin
distribution before loading it.

Network integrations send the minimum required data. OPA excludes tool
arguments and defaults to denial on transport or schema errors. Slack excludes
arguments, restricts endpoints to official HTTPS webhook hosts, and cannot
interrupt execution because it is observing middleware. Prometheus labels are
limited to registered tool name, status, and risk tier.
