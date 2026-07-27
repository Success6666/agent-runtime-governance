# Production Operations

This guide covers the operational contract through the v0.7 implementation.
Applications remain responsible for tool-specific authorization, business
rollback, downstream idempotency, and data-retention requirements.

The v0.6 strict profile adds an explicit registration and sealing lifecycle;
v0.7 adds deterministic reconciliation requirements for idempotent tools.
Configure `ProductionProfile`, register every tool, call
`seal_production()`, and expose readiness or accept traffic only after the
returned report has `ready=True`. Compatibility runtimes can call
`production_readiness(profile)` to generate a migration inventory without
changing v0.5 execution behavior. See
[`ADR 0004`](adr/0004-strict-production-sealing.md) for the exact trust and
capability boundary and [`ADR 0005`](adr/0005-single-bound-action.md) for the
runtime identity decision.

## Required configuration

- Classify every tool as `READ_ONLY`, `IDEMPOTENT`, or `MUTATING`. The default
  is conservative `MUTATING`; do not loosen it without proving retry safety.
- Use `SQLiteIdempotencyStore`, `SQLiteApprovalStore`, and
  `SQLiteIdentityReplayStore` when state must survive process restarts. Store
  each database on a local durable filesystem with restrictive permissions.
- For strict `IDEMPOTENT` tools, use a `SQLiteIdempotencyStore` and a
  `SQLiteReconciliationLedger` configured with the **same SQLite database
  path**. Register a tool-specific `ReconciliationProvider` with a stable
  provider ID, protocol version, and bounded evidence kinds. The application
  must ensure the provider is read-only: the runtime validates its binding and
  returned evidence, not the absence of provider side effects. The strict
  profile rejects a missing, non-durable, non-atomic, non-colocated, or
  provider-less configuration.
- Construct the runtime with a trusted `identity_provider` and
  `require_verified_identity=True`. Compatibility identity fields supplied by
  the caller are not a production trust boundary.
- Configure absolute request deadlines and bounded concurrency. Capacity must
  be derived from downstream limits, not only CPU count.
- Use a signed JSONL or SQLite audit sink for ordinary audit. Mark audit
  delivery critical for actions that must never execute without a durable
  record. Strict reconciliation requires a signed, durable, integrity-protected
  audit sink behind a fail-closed `AuditMiddleware`; it must advertise the
  reconciliation-delivery capability and implement
  `write_idempotent(source_event_id, event)` so a durable outbox envelope can
  be retried without appending a second audit record. `SQLiteAuditSink` is the
  built-in tested implementation. JSONL audit is not a replacement for that
  source-idempotent delivery boundary.
- Keep identity and audit HMAC keys in a secret manager. Rotate identity keys by
  adding a new `kid`, switching issuers, waiting for the maximum envelope
  lifetime, and only then removing the old key.
- Configure a public identity-digest key version plus an explicit policy
  version and SHA-256 digest of the exact immutable policy artifact. Do not
  hash a human label. Policy-bearing middleware must advertise the same
  identity. Contracts with external preconditions require a bounded provider
  that returns the current digest.
- For `YAMLPolicyLoader`, use `PolicyDocument.artifact_digest` and
  `artifact_middleware()` in the strict profile. `PolicyDocument.digest` is a
  formatting-independent semantic digest retained for compatibility and policy
  drift comparison; it is not deployment-artifact identity.

SQLite stores coordinate multiple processes on one host. They are not a
distributed database. Deployments spanning hosts must provide store adapters
with equivalent atomic claim, lease, compare-and-set, and durability semantics.

## Deadlines and cancellation

The request deadline is absolute and propagates through governance,
idempotency waits, identity checks, middleware, and tool execution. A timeout or
cancellation cannot stop arbitrary synchronous Python or an already dispatched
external side effect. When a mutating operation may have started, the terminal
state is `UNKNOWN`.

Custom idempotency stores must bound every lock, network, and database wait so
each method returns within `RuntimeLimits.idempotency_operation_timeout_seconds`.
The runtime also applies that boundary and permanently fails closed for new
idempotent work after an overrun, because Python cannot safely terminate a
blocked worker thread. Restart only after diagnosing or replacing the adapter.

Call `get_cancellation_context(error)` in a `CancelledError` handler to recover
the finalized governance state on every supported Python version. Python 3.10
re-materializes task cancellation exceptions and therefore cannot guarantee
that custom attributes remain directly attached to the caught exception.

Never automatically retry an unresolved `UNKNOWN`. The original key remains
blocked while its reconciliation disposition is `BLOCKED_UNKNOWN` or
`BLOCKED_MANUAL_REVIEW`. Use the deterministic reconciliation protocol below;
do not delete a durable record to force a retry.

## Deterministic UNKNOWN reconciliation

For the strict SQLite path, an idempotency owner and a bounded
`UnknownAction` recovery descriptor commit in the same transaction before a
side-effecting tool body is dispatched. The descriptor binds the action digest,
contract identity, tenant partition digest, receipt/probe schemas, and
reconciliation provider binding (identifier, protocol version, and evidence
kinds). It deliberately excludes the raw caller idempotency key and provider
callable. If the process fails before a terminal result is known, the same key
is not re-opened for execution; lease recovery can materialize an explicit
`UNKNOWN` reconciliation head from the descriptor.

`Runtime.areconcile(execution_record_id, ...)` starts a tracked control-plane
workflow. The application must ensure its provider call is a read-only
receipt/probe attempt; the runtime persists the attempt and transition protocol
records. A provider must return supported, bounded evidence and may only be
used when its registered ID, protocol version, and evidence kinds match the
descriptor stored with the unresolved action. A restart with a different
provider does not authorize a substitute probe. In a strict profile, the caller must have
`reconciliation:probe` (or the configured replacement) and its verified tenant
must match the persisted tenant partition.

After `ATTEMPT_STARTED` is durable, its terminal record is finalized under
`RuntimeLimits.reconciliation_finalization_timeout_seconds`, independently of
the caller cancellation budget. If that finalization cannot make durable
progress, the reconciliation channel fails closed for new work. If an attempt
is still unclosed before its own deadline, another worker cannot start a second
probe. After the deadline expires, recovery records a
`recovery_required` outcome and moves the action to `MANUAL_REVIEW`; it does
not invoke another provider.

`Runtime.aresolve_reconciliation(...)` is an optimistic, manual control-plane
operation. It requires the configured `reconciliation:resolve` permission,
verified tenant access, the expected review state and revision, a reason, and
bounded evidence. The runtime records a keyed operator-identity digest rather
than a raw principal. A transition to `CONFIRMED_NOT_APPLIED` additionally
requires an explicit `retry_safe=True` assertion; timeouts and absent receipts
never imply that a write was not applied.

Every reconciliation head/event lineage mutation enqueues a fixed-allowlist
audit envelope in the same SQLite transaction. It excludes raw provider
evidence, raw tenant identities, and idempotency keys. The worker path
`Runtime.adrain_reconciliation_audit_outbox(...)` performs no provider call;
it delivers pending envelopes in revision order for each execution, requires
the separately configured `reconciliation:audit:drain` permission in a strict
profile, and uses the outbox ID as the audit sink source identity. Sink failure
or timeout leaves the envelope pending for a later authorized worker. It does
not rewrite reconciliation history or make the original idempotency key
reusable. Audit delivery uses its own bounded timeout and bulkhead; runtime
shutdown does not wait indefinitely for a synchronous sink thread that has
already exceeded that delivery budget. The runtime-owned delivery executor uses
daemon workers only because this is an outbox-backed, source-idempotent retry
path. If an application injects its own audit-delivery executor, that executor
must provide equivalent bounded shutdown behavior. The reconciliation ledger
and finalization paths intentionally remain authoritative and cannot be made
daemon work without weakening their durability contract.

The protocol establishes durable local recovery state. It does **not** make an
arbitrary downstream side effect exactly-once. Confirm an external success or
non-application only when the target system's stable idempotency key, receipt,
or probe semantics support that conclusion; otherwise retain `UNKNOWN` or
`MANUAL_REVIEW` and follow the application's incident process.

## Approval recovery

Contracted approval requests bind `action_digest`, identity, policy, risk, and
expiry. On restart, reload pending requests from the durable store and reject
expired, tampered, already-consumed, or mismatched decisions. Approval channels
must authenticate the reviewer independently of user-supplied context.

Approvals written by v0.5 do not contain `action_digest`. They remain readable
but fail closed for contracted tools and must be reissued. Follow
[`migration-v0.6.md`](migration-v0.6.md); do not copy a legacy allow decision
into a v0.6 request.

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

For v0.7, the reconciliation SQLite database contains a per-execution ordered
audit outbox in addition to the reconciliation heads and append-only events.
The envelope payload and identity are immutable; delivery attempt count,
acknowledgement time, and last error are intentionally mutable operational
state. Back up and restore it as part of the same recovery unit as the
colocated idempotency database. A restored database can have pending audit
envelopes; drain those through the authorized recovery worker rather than
editing payloads or marking them delivered by hand. `SQLiteAuditSink`
independently checks its hash chain and source-event payload identity, so back
up its database and signing key with the same care. The outbox is delivery
intent, not a second authoritative copy of the external side effect.

Configure `sign_key` for snapshot stores when tamper evidence is required. In
unsigned mode the snapshot sequence state uses only a recomputable
`state_hash`; anyone able to rewrite the state file can forge it, so unsigned
state must not be treated as tamper-proof.

Redaction is enabled by default for request text, tool arguments, results,
errors, decision reasons, and known secret keys. Add domain-specific sensitive
keys and patterns before production traffic. Disabling redaction is appropriate
only for isolated test data.

Full context/replay snapshots retain normalized tool parameters and therefore
have a higher confidentiality classification than parameter-free audit
evidence. Hash chains and HMAC signatures do not encrypt them. Production
snapshot stores and backups require encryption at rest and in transit,
least-privilege ACLs, independent encryption/HMAC keys, bounded retention, and
verified deletion from replicas. Treat `from_dict()` as parsing only.
`Runtime.areplay()` is non-authoritative policy analysis and deliberately does
not create `BoundAction`. For a current bound preview, verify the snapshot chain
externally and call `Runtime.apreview()` with freshly verified identity claims;
do not promote replay output into authorization evidence. Replay preserves
non-governance correlation metadata, removes identity/approval/policy metadata,
and returns `replay.parameter_validation_failed` when recorded parameters no
longer satisfy the current tool contract.

Precondition providers receive the contract, exact normalized parameters,
verified principal, and tenant. They must return a lowercase SHA-256 digest,
finish within the middleware/deadline budget, and fail closed on stale,
missing, or ambiguous state. Final executor-boundary revalidation narrows
TOCTOU exposure
but cannot make an external write atomic. Strongly consistent side effects must
send an ETag, version, CAS predicate, or transaction condition to the target
system and have that system reject a changed state.

## External services

- OPA is fail closed and validates response shape and size. Use TLS and enable
  circuit breaking explicitly by passing a positive `failure_threshold` to
  `OPAClient`; the default value `0` leaves circuit breaking disabled. Alert on
  transport, schema, and latency failures.
  For contracted strict runtimes, configure `policy_version` and
  `policy_digest` on `OPAMiddleware` and use the same values in
  `ProductionProfile`; an absent or mismatched identity blocks sealing. Tie the
  values to the exact signed OPA bundle bytes or admitted OCI manifest digest,
  never a revision label. Deployment admission must verify the artifact and
  loaded OPA revision. The runtime checks configuration equality but cannot
  independently attest remote policy bytes.
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
/tmp/arg-dependency-audit/bin/python -m pip install ".[otel,yaml,prometheus]"
python -m venv /tmp/arg-pip-audit-tool
/tmp/arg-pip-audit-tool/bin/python -m pip install "pip-audit==2.10.1"
AUDIT_SITE_PACKAGES=$(
  /tmp/arg-dependency-audit/bin/python -c \
    'import sysconfig; print(sysconfig.get_paths()["purelib"])'
)
/tmp/arg-pip-audit-tool/bin/pip-audit --path "$AUDIT_SITE_PACKAGES"
python integration/production_smoke.py --skip-kind
python integration/production_smoke.py
python benchmarks/benchmark_runtime.py --requests 1000 --concurrency 100 \
  --output benchmarks/results/release-candidate.json
python scripts/check_benchmark_budget.py \
  benchmarks/results/release-candidate.json
python -m build
```

Run the audit in a clean environment. Auditing a shared developer interpreter
mixes unrelated project dependencies into the result and cannot establish the
SDK dependency closure.

Verify a restart with pending approval and idempotency records, a forced OPA
failure, a critical audit failure, cancellation of an in-flight mutating tool,
and concurrent requests sharing an idempotency key. For v0.7, also verify an
expired unclosed reconciliation attempt, a provider identity mismatch after
restart, an audit acknowledgement failure followed by idempotent redelivery,
and recovery-worker authorization. Alert on denied, failed, `UNKNOWN`, and
`MANUAL_REVIEW` outcomes separately; alert separately on pending outbox age,
delivery failures, and reconciliation-channel fail-closed state.
