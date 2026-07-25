# ADR 0001: Production reliability boundaries

## Status

Accepted for v0.5.0.

## Context

The runtime governs tool execution in host applications. In production, failures
must be explicit: retries must not duplicate mutating work, deadlines must flow
through middleware and tools, cancellation must leave a recoverable terminal
state, and audit must not disappear for critical operations.

## Decision

- Idempotent tools require an explicit idempotency key and use a durable ledger
  when cross-process recovery is needed.
- Expired pending leases are marked `unknown` instead of automatically
  re-executed.
- Deadlines are absolute, timezone-aware values carried in `InvocationOptions`.
- Mutating work that times out, is cancelled after execution starts, or loses an
  idempotency lease is reported as `UNKNOWN`.
- Critical audit sinks fail closed; non-critical observing failures are recorded
  without granting permission.
- Verified identity is accepted only from a trusted provider boundary, never
  from model text.
- Durable approvals are leased during governance and consumed only after every
  gate, critical pre-execution hook, and idempotency admission check succeeds.
  Pre-execution denial releases the lease; crash recovery relies on lease
  expiry.
- Timed-out asynchronous tools retain an execution-capacity lease until their
  actual task terminates, even if they suppress cancellation.

## Consequences

- Operators must reconcile `UNKNOWN` idempotency records before reusing the key.
- Applications that need durable recovery should use SQLite stores or provide a
  store with equivalent atomicity.
- The SDK stays a library runtime and does not provide a hosted control plane.
