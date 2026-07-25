# Production Operations

This guide covers the operational contract for v0.5. Applications remain
responsible for tool-specific authorization, business rollback, and data
retention requirements.

## Required configuration

- Classify every tool as `READ_ONLY`, `IDEMPOTENT`, or `MUTATING`. The default
  is conservative `MUTATING`; do not loosen it without proving retry safety.
- Use `SQLiteIdempotencyStore`, `SQLiteApprovalStore`, and
  `SQLiteIdentityReplayStore` when state must survive process restarts. Store
  each database on a local durable filesystem with restrictive permissions.
- Construct the runtime with a trusted `identity_provider` and
  `require_verified_identity=True`. Compatibility identity fields supplied by
  the caller are not a production trust boundary.
- Configure absolute request deadlines and bounded concurrency. Capacity must
  be derived from downstream limits, not only CPU count.
- Use a signed JSONL or SQLite audit sink. Mark audit delivery critical for
  actions that must never execute without a durable record.
- Keep identity and audit HMAC keys in a secret manager. Rotate identity keys by
  adding a new `kid`, switching issuers, waiting for the maximum envelope
  lifetime, and only then removing the old key.

SQLite stores coordinate multiple processes on one host. They are not a
distributed database. Deployments spanning hosts must provide store adapters
with equivalent atomic claim, lease, compare-and-set, and durability semantics.

## Deadlines and cancellation

The request deadline is absolute and propagates through governance,
idempotency waits, identity checks, middleware, and tool execution. A timeout or
cancellation cannot stop arbitrary synchronous Python or an already dispatched
external side effect. When a mutating operation may have started, the terminal
state is `UNKNOWN`.

Call `get_cancellation_context(error)` in a `CancelledError` handler to recover
the finalized governance state on every supported Python version. Python 3.10
re-materializes task cancellation exceptions and therefore cannot guarantee
that custom attributes remain directly attached to the caught exception.

Never automatically retry `UNKNOWN`. Reconcile the external system using the
trace ID, request ID, tool name, and idempotency key. After confirming the
outcome, close the operational incident or write a new compensating action with
a new idempotency key.

## Approval recovery

Approval requests bind the trace, tool call digest, identity, expiry, and
decision. On restart, reload pending requests from the durable store and reject
expired, tampered, already-consumed, or mismatched decisions. Approval channels
must authenticate the reviewer independently of user-supplied context.

The runtime reserves an approved decision during governance and commits it at
the execution boundary. Later gate or hook denial releases the reservation;
process failure is recovered by lease expiry. Approval consumption and an
arbitrary external tool side effect cannot share a transaction, so operators
must correlate approval, audit, and idempotency records for crash recovery.

## Audit and backup

Audit and snapshot records form hash chains and may also carry HMAC signatures.
Verification proves tampering or truncation only when the chain anchor and key
are protected separately. Back up databases, chain state, and keys according to
the same recovery point objective. Test restore and `verify()` before every
release that changes persistence code.

Redaction is enabled by default for request text, tool arguments, results,
errors, decision reasons, and known secret keys. Add domain-specific sensitive
keys and patterns before production traffic. Disabling redaction is appropriate
only for isolated test data.

## External services

- OPA is fail closed and validates response shape and size. Use TLS and a
  circuit breaker; alert on transport, schema, and latency failures.
- OpenTelemetry export is observing and should not carry raw arguments or
  identity claims. v0.5 verifies in-process async/thread context propagation and
  OTLP export. `ExecutionContext.trace_id` and `span_id` are governance IDs, not
  a W3C carrier; the host application remains responsible for extracting and
  injecting distributed trace headers.
- Prometheus labels are limited to registered tool, status, and risk tier. Do
  not add user, tenant, request, trace, path, or arbitrary error labels.
- Slack notifications contain generic classifications and are not an audit
  system or approval authority.

## Readiness and recovery checks

Before rollout:

```bash
ruff check .
pytest --cov=agent_runtime_governance --cov-report=term-missing
python -m venv /tmp/arg-dependency-audit
/tmp/arg-dependency-audit/bin/python -m pip install --upgrade "pip>=26.1.2"
/tmp/arg-dependency-audit/bin/python -m pip install ".[otel,yaml,prometheus]" "pip-audit==2.10.1"
/tmp/arg-dependency-audit/bin/python -m pip_audit
python integration/production_smoke.py --skip-kind
python integration/production_smoke.py
python -m build
```

Run the audit in a clean environment. Auditing a shared developer interpreter
mixes unrelated project dependencies into the result and cannot establish the
SDK dependency closure.

Verify a restart with pending approval and idempotency records, a forced OPA
failure, a critical audit failure, cancellation of an in-flight mutating tool,
and concurrent requests sharing an idempotency key. Alert on denied, failed, and
`UNKNOWN` terminal outcomes separately.
