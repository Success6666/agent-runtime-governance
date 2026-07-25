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

## Context boundaries

Immutable identity fields include trace IDs, principal, permissions, original
user input, and the requested tool call. Governance fields such as risk score,
decision, status, history, result, and metadata evolve by replacement.

Nested mappings and sequences are frozen on context construction. Serialization
produces a detached JSON-compatible representation for audit and replay.

## Middleware boundaries

`GatingMiddleware` may deny execution. `ObservingMiddleware` records state but
does not gain authority to allow or deny. v0.1 accepts a fixed Python list so
execution order is explicit at construction time.

v0.2 represents that list as an immutable `Pipeline`. Composition operations
return a new pipeline, preserving deterministic order and avoiding concurrent
runtime mutation. `ExecutionMiddleware` wraps only the tool executor, enabling
retry and timeout without giving those controls policy authority.

Hooks are lightweight observation/enrichment points. They cannot change status
or decisions. A critical pre-execution hook failure is converted into an
explicit denial; post-execution hook failures are recorded without rewriting the
completed outcome.

## Decisions

Human approval is modeled as a `DecisionProvider`, allowing CLI, chat, or HTTP
applications to supply an asynchronous callback. The framework provides the
protocol and suspension point, not a user interface.

## Audit and replay

Audit events contain the context snapshot before execution and after completion.
The JSONL sink can redact known secret keys and HMAC-sign each record. v0.1
replay intentionally only loads and prints these snapshots; it does not execute
tools again.

v0.3 adds a separate snapshot store for debugger and regression workflows.
Replay rebuilds the original request identity and runs only middleware whose
metadata declares it replayable. External model review, human interaction,
metrics, retries, audit, and telemetry are never invoked by deterministic
replay.

Policy documents have an explicit version and a digest derived from canonical
validated content. Duplicate tool rules are rejected instead of introducing an
implicit conflict-resolution language. Drift detection compares outcomes and
risk tiers after applying two deterministic pipelines to the same request.

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
