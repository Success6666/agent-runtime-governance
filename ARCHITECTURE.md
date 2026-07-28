# Architecture

## Runtime model

Agent Runtime Governance is defined as:

```text
Runtime = immutable ExecutionContext + ordered Pipeline + explicit Decision
```

The runtime owns governance around tool execution. It does not own agent
planning, model selection, prompts, or framework state.

## v0.8 service boundaries

`Runtime` is the stable public lifecycle facade. It owns sealing, public
methods, deadlines, cancellation, and admission of potentially blocking work.
Its internal services have one dependency direction:

```text
Runtime facade -> pipeline/lifecycle/durable services -> protocol-facing adapters
```

`Pipeline` remains an immutable public value whose explicit registration order
is preserved. The internal `MiddlewareRegistry` validates middleware metadata
and offers a deterministic priority view without silently reordering an
existing Pipeline; `PipelineRunner` composes selected middleware through
Runtime-owned callbacks. Extension dispatch is likewise internal and
async-first. Concrete SQLite adapters are construction-boundary dependencies,
not dependencies of reusable runtime services.

Stable modules and public imports remain compatible through v0.8. Internal
modules are prefixed with `_`; consumers must not depend on them. Any later
audit, codec, protocol, or event extraction preserves its current public import
paths and serialized compatibility contract. See [ADR 0006](docs/adr/0006-v08-runtime-service-boundaries.md).

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
11. For strict idempotent SQLite deployments, the idempotency owner and the
    immutable recovery descriptor are committed before the tool body can be
    dispatched.
12. `UNKNOWN` actions are never silently made retryable. Reconciliation is an
    append-only, expected-revision protocol; unresolved and manual-review
    dispositions continue to block the original key.
13. A persisted reconciliation provider identity, protocol version, and
    supported evidence kinds must match the registered provider before a new
    receipt/probe call can start.
14. A reconciliation head/event lineage mutation and its fixed-allowlist
    audit-outbox envelope commit together. Retried delivery is ordered per
    execution and must use a source-idempotent sink in strict production.
15. A started reconciliation probe has a terminal-record obligation. If its
    deadline expires without one, recovery records `recovery_required` and
    moves the action to `MANUAL_REVIEW`, rather than invoking another provider.

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

## UNKNOWN reconciliation

An idempotent action with an uncertain external outcome receives an
`UnknownAction` descriptor. It contains the action and contract identities,
a hashed tenant partition, bounded receipt/probe schemas, and the
reconciliation provider binding (identifier, protocol version, and evidence
kinds); it does not persist a raw caller idempotency key or provider callable.
In the strict SQLite path, `SQLiteIdempotencyStore` writes that descriptor
atomically with the initial ownership claim. A lease that expires before
dispatch can therefore materialize the same durable `UNKNOWN` head instead of
reopening the action for execution.

`Runtime.areconcile()` is a control-plane workflow: the application must make
its provider invocation read-only receipt/probe work, while the runtime durably appends
`ATTEMPT_STARTED`, `ATTEMPT_FINISHED`, and `STATE_TRANSITION` records. Each is
guarded by the head revision. A provider cannot be substituted after a restart:
its identifier, protocol version, and supported evidence kinds must equal the
persisted binding. In a strict production profile, probe access, manual
resolution, and global audit recovery have separate permissions; a per-action
operation also requires the caller tenant to match the persisted tenant
partition.

Once an attempt start has committed, completion is finalized under an
independent bounded deadline even when the request is cancelled. A finalization
overrun or storage failure disables further reconciliation rather than treating
an incomplete ledger as authoritative. An unclosed attempt remains exclusive
until its deadline; after expiry, recovery appends a
`RECOVERY_REQUIRED` terminal attempt and a `RECOVERY -> MANUAL_REVIEW`
transition. A trusted operator can then resolve only that review state with an
expected revision, reason, evidence, and a keyed operator-identity digest.

The protocol distinguishes a confirmed success from a confirmed-not-applied
result. A retryable disposition requires an explicit retry-safe assertion on a
validated provider finding or manual resolution for `CONFIRMED_NOT_APPLIED`; it
does not infer external non-application from a timeout or missing record.
Receipt/probe evidence can support a particular downstream system's guarantee,
but the runtime does not claim general external exactly-once execution.

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

SQLite reconciliation uses a transactional outbox for its own lineage events.
The envelope payload is constructed from a fixed allowlist: raw provider
evidence, raw tenant identities, and idempotency keys are excluded. Its
identity and payload are immutable while delivery attempts, acknowledgement,
and last-error state remain mutable. It is enqueued with the matching head/event
lineage mutation and delivered in revision order for each execution.
`SQLiteAuditSink.write_idempotent(source_event_id, event)` makes a replay after
an acknowledgement failure safe only when the event payload is identical. A
sink timeout or process shutdown leaves the envelope pending for
`Runtime.adrain_reconciliation_audit_outbox()`; it does not rewrite the
reconciliation history. Audit delivery has an isolated bounded executor so a
blocked third-party sink cannot indefinitely delay runtime shutdown. The
runtime-owned delivery executor uses daemon workers only for this
source-idempotent, outbox-backed side work; reconciliation ledger and
finalization work remain authoritative, non-abandonable operations.

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
