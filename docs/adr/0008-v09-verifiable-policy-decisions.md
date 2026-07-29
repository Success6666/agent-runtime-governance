# ADR 0008: v0.9 verifiable policy-decision attachments

## Status

Accepted for the v0.9 planning boundary.

## Context

v0.6 binds policy, approval, idempotency, execution, and audit to one immutable
action. v0.7 contains uncertain side effects through `UNKNOWN` reconciliation,
and v0.8 supplies a closed, portable Evidence Bundle v1 with detached signing,
anchor, and receipt-verification inputs.

Those releases can answer whether a recorded action and selected outcome are
well formed and correctly bound. They do not provide a stable, privacy-safe
answer to which deterministic policy controls produced the allow, deny, or
approval requirement. Existing history and `DecisionRecord.reason` may contain
free text and are not an evidence contract.

Adding arbitrary policy source data, prompts, model data, reasoning traces, or
raw inputs would turn evidence into a log and break the v1 privacy and
compatibility boundary. Changing Evidence Bundle v1 would also change its
canonical bytes and detached-signature contract.

## Decision

v0.9 adds a detached, versioned decision-explanation attachment rather than a
new policy language or an Evidence Bundle v1 field.

The attachment is an immutable canonical commitment. It binds:

- the action digest and, when present, the evidence-bundle digest;
- policy version and policy digest;
- final decision, risk tier, and approval requirement; and
- an ordered sequence of deterministic control results.

A control result contains only a stable control ID, control version, effect,
result, and machine-readable reason code. It excludes raw parameters, prompts,
model output, chain-of-thought, secrets, identity values, raw receipts, and
free-text remote-policy output. The control sequence has deterministic ordering
and rejects duplicate identities.

Built-in Python/YAML policy and rule middleware project this attachment from
their known deterministic semantics. External policy integrations may emit an
explanation only through an explicit structured contract. A plain text reason,
including an OPA response reason, is not a verified control result.

The existing offline verifier validates the attachment's schema, canonical
digest, binding, order, uniqueness, and consistency with the referenced policy
outcome. Verification is observational: an attachment can neither authorize a
runtime action nor change an immutable bundle, receipt outcome, or
reconciliation state. A human-readable inspect command may only render the
same verifier report; it must not implement another verifier or contact a
network service.

Comparison is equally observational. It accepts two verified attachments for
the same action identity and reports decision, policy, risk, approval, and
control drift. It never replays a tool, calls an LLM or human provider, or
creates a new external effect.

## Consequences

- Evidence Bundle v1, its historical fixtures, and detached-signature/receipt
  contracts remain byte-compatible.
- A policy explanation becomes portable only when it meets the new attachment
  contract; runtime history remains diagnostic data rather than evidence.
- Explanation collection adds a measured cost and needs property, mutation,
  privacy, side-effect-safety, compatibility, and cross-framework conformance
  coverage.
- PostgreSQL, Redis, leases, migrations, and multi-instance fault injection
  are retained for the deferred v0.10 proposal, not introduced incidentally.

## Non-goals

This decision does not add a general policy DSL, policy editor, hosted control
plane, dashboard, additional framework adapters, prompt/model provenance,
chain-of-thought collection, result logging, generic tool simulation, or a new
receipt-verification protocol.
