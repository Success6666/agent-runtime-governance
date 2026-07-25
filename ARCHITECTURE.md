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
5. Observing failures are recorded and fail open.
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

## Decisions

Human approval is modeled as a `DecisionProvider`, allowing CLI, chat, or HTTP
applications to supply an asynchronous callback. The framework provides the
protocol and suspension point, not a user interface.

## Audit and replay

Audit events contain the context snapshot before execution and after completion.
The JSONL sink can redact known secret keys and HMAC-sign each record. v0.1
replay intentionally only loads and prints these snapshots; it does not execute
tools again.

