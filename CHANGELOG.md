# Changelog

All notable changes are documented here.

## [Unreleased]

### Added

- Internal middleware registration and pipeline-composition seams. Public
  `Pipeline` remains immutable and explicitly ordered; the v0.8 internal
  registry validates metadata and exposes deterministic priority views without
  changing public ordering semantics.
- A Runtime-owned async-first extension dispatcher. Native async hooks, LLM
  reviewers, human-decision callbacks, audit/snapshot adapters,
  identity/precondition providers, and OPA/Slack adapters execute on the
  caller event loop; synchronous adapters retain a managed worker fallback.
- Read-only extension-dispatch capacity snapshots and optional low-cardinality
  Prometheus metrics for queue wait, execution duration, saturation, detached
  work, worker capacity/activity, and queue depth.
- Cancellation-safe OpenTelemetry span admission and terminal cleanup. A span
  started by a timed-out observer remains Runtime-owned until it is ended.
- `Runtime.invoke()` now uses a Runtime-owned event loop while the Runtime is
  open, so terminal cleanup admitted by a synchronous call survives after the
  tool result returns and is coordinated by `aclose()`.

### Changed

- `RuntimeLimits.max_blocking_extension_workers` (default `4`) now controls
  extension worker count independently from
  `max_blocking_extension_in_flight` (default `16`), which bounds admitted
  synchronous running and queued work. Timed-out synchronous work still holds
  its permit until it exits, and `aclose()` still waits for it.
- Audit, snapshot, identity, precondition, OPA, and Slack extension protocols
  now accept awaitable adapter results without changing the synchronous durable
  approval, idempotency, or reconciliation storage contracts.
- Runtime shutdown now drains admitted extension terminal-cleanup tasks before
  releasing extension workers; that narrow cleanup path cannot admit new work.
- Synchronous `close()` now rejects both running and detached extension work;
  `aclose()` remains the graceful path that waits for it.

## [0.7.0] - 2026-07-27

### Added

- A deterministic, append-only reconciliation protocol for idempotent actions
  whose external outcome is `UNKNOWN`, with revision-checked heads, durable
  attempt events, provider descriptors, manual resolution, and explicit
  `MANUAL_REVIEW` containment.
- Atomic SQLite prepared-action persistence: the idempotency owner and its
  minimal `UnknownAction` recovery descriptor commit before a side-effecting
  body can be dispatched. The descriptor excludes raw idempotency keys and
  parameters.
- A schema-v5 transactional reconciliation-audit outbox. SQLite mutations and
  fixed-allowlist delivery envelopes commit together; `SQLiteAuditSink` supports
  stable source-event-id de-duplication for safe acknowledgement retries.
- Recovery for expired unfinished provider attempts. Recovery records a
  terminal `recovery_required` event and moves the action to `MANUAL_REVIEW`
  instead of issuing another provider probe.
- Separate strict-production permissions for reconciliation probing, manual
  resolution, and global reconciliation-audit recovery, with tenant binding
  for per-action control-plane operations.
- A dedicated daemon delivery executor for abandonable reconciliation-audit
  attempts. The durable outbox remains pending until acknowledgement, so a
  blocked third-party sink cannot prevent process termination or lose the
  redelivery obligation.

### Changed

- Strict idempotent SQLite deployments now require a colocated
  `SQLiteIdempotencyStore` and `SQLiteReconciliationLedger`, a persisted
  reconciliation provider for every idempotent tool, and a signed,
  source-idempotent audit sink behind fail-closed audit middleware. The
  built-in `SQLiteAuditSink` is one verified implementation.
- Reconciliation provider identity, protocol version, and supported evidence
  kinds are bound into the persisted recovery descriptor and fail closed on
  drift after restart.
- Reconciliation audit delivery has its own deadline, bulkhead, and durable
  recovery-worker entry point; a sink delivery timeout leaves the envelope
  pending rather than poisoning the reconciliation ledger.
- Normal ledger startup refuses pre-outbox reconciliation schema versions.
  A verified v1-v3 database must be upgraded through the explicit,
  offline `SQLiteReconciliationLedger.migrate_legacy(...)` operation instead
  of allowing a long-lived runtime to recreate an outbox.

### Fixed

- JSON-safe context and audit serialization now normalizes `NaN` and infinities
  to deterministic markers before hash-backed audit or snapshot persistence, so
  non-critical observers cannot silently drop evidence for those values.
- Caller deadlines now bound outbox reads, audit delivery, acknowledgement, and
  failure recording consistently. Naive public reconciliation deadlines are
  rejected with a stable validation error.
- A configured audit-delivery timeout now returns a recoverable error carrying
  the execution and outbox identities while the caller deadline remains valid;
  only an exhausted caller deadline is surfaced as a stage timeout.
- Runtime close no longer waits on a blocked reconciliation-audit delivery
  thread. In-flight delivery remains unacknowledged and is safely retried by a
  later worker using the source event ID.
- Standalone `SQLiteIdempotencyStore` failure cleanup no longer assumes a
  colocated reconciliation schema, preserving the original tool failure and
  releasing the claim when reconciliation is not configured.
- Reconciliation schema validation now compares the released DDL without
  folding SQL string-literal case, rejects forged v1-v3 downgrade paths,
  validates the complete legacy authority set during controlled migration,
  and detects orphaned foreign-key records before startup.
- SQLite idempotency initialization now validates its complete authority
  contract (table DDL, current version row, canonical indexes, and persistent
  trigger inventory) before accepting durable execution state. Pre-versioned
  stores require the explicit offline `SQLiteIdempotencyStore.migrate_legacy(...)`
  path instead of automatic service-startup migration.
- Reconciliation construction now validates a colocated idempotency authority
  before creating or migrating reconciliation tables, so a rejected legacy
  store cannot leave a partial reconciliation schema behind.
- Controlled shared SQLite migration now validates both authority inventories
  and upgrades them in one `BEGIN IMMEDIATE` transaction, rolling back the
  reconciliation authority when the idempotency upgrade cannot complete.
- Idempotency startup and controlled migration now reject an orphaned
  `idempotency_records_v07` staging object before creating any new authority;
  standalone idempotency migration also refuses a database that contains any
  reconciliation authority object.
- Runtime shutdown now tracks every public asynchronous operation, keeps the
  close transition exclusive until owned executors are released, waits for
  admitted normal work, cancellation-ignoring tool coroutines, and detached
  reconciliation providers during `aclose()`, and rejects self- or
  cross-event-loop shutdown that would otherwise deadlock or leave executors
  live.
- Synchronous hooks, middleware callbacks, identity/precondition providers,
  approval stores, audit and snapshot sinks, and built-in OPA/Slack adapters
  now use a bounded Runtime-owned executor. Timed-out thread-backed work holds
  capacity until it actually exits, and graceful shutdown waits for it instead
  of reporting a false clean stop; nested blocking submission fails closed.
- Synchronous tools submitted through an application-provided executor remain
  tracked after their asyncio wrapper times out, so `aclose()` cannot return
  while that tool body is still running.
- The reconciliation audit daemon executor now fails queued deliveries and
  rejects new submission after a queue-read failure rather than leaving a
  `Future` pending indefinitely, and preserves caller cancellation in its
  post-dequeue failure path; the durable outbox remains available for a fresh
  runtime to retry the source-idempotent delivery.
- The optional Kind smoke now builds and executes the local SDK in a hardened
  Kubernetes Job instead of only applying and reading a ConfigMap; Docker OPA,
  OTLP, and Prometheus smoke checks likewise require runtime-produced evidence.
- A transient Docker build failure retries a cache-busting Docker build; a
  failed build is never treated as a successful integration check. Artifact
  hash pinning is not claimed without a hash-locked dependency input.
- Reconciliation operation and audit-delivery timeouts now register exactly one
  deferred cleanup path, preventing duplicate capacity release or an incorrect
  drain-state decrement after a non-cooperative operation completes.
- Best-effort reconciliation-audit stall marking can no longer make pending
  outbox reads fail during a competing SQLite write. Idempotency startup checks
  now validate only the idempotency authority's foreign keys, leaving the
  reconciliation ledger responsible for its own integrity boundary.
- Docker build contexts now exclude SQLite database files, sidecars, and
  `.env`-style environment files; hardened smoke coverage includes exhausted
  and timed-out image-build retries.

## [0.6.0] - 2026-07-27

### Added

- Immutable `ActionContract` and `BoundAction` primitives with versioned RFC
  8785 canonical envelopes, domain-separated SHA-256 digests, and keyed
  HMAC-SHA-256 identity digests with explicit rotation versions.
- Strict action-value validation for unsupported types, non-finite numbers,
  negative zero, unsafe integers, invalid Unicode, cycles, duplicate mapping
  keys, nesting limits, node budgets, and canonical payload limits.
- Versioned serialization that recomputes every digest on restore, plus a
  parameter-free evidence representation and cross-process golden fixtures.
- Principal and tenant digests that require deployment- or tenant-scoped secret
  material while keeping the key and raw identity values out of serialized
  actions, evidence, and representations. Parameter contract errors omit
  rejected values to avoid secret disclosure.
- A versioned strict-production profile with deterministic registry inventory,
  fail-closed runtime sealing, explicit adapter capability declarations, and
  stable redacted readiness reason codes.
- One immutable `BoundAction` carried through context, approval, versioned
  idempotency, executor-boundary revalidation, OpenTelemetry, and schema-v3
  audit evidence.
- Strict policy-identity and external-precondition readiness checks, contract
  receipt validation, v0.5 context/approval/idempotency compatibility fixtures,
  and a documented migration and rollback procedure.
- A paired strict-runtime benchmark, committed pre-release and final release
  measurements, and a CI-enforced latency and memory regression budget.

### Changed

- Added the dependency-free `rfc8785` encoder for the new action-contract
  domain. Existing v0.5 identity, approval, and idempotency encodings remain
  unchanged until the versioned runtime migration phase.
- Side-effecting tool registrations can carry an `ActionContract`; strict
  runtimes reject traffic until the complete registry and required durable,
  trusted, integrity-protected components pass startup validation. Non-strict
  construction remains compatible and can emit the same migration inventory.
- Sealed production runtimes now reject reassignment of `pipeline`, `hooks`,
  `registry`, `idempotency_store`, `identity_provider`,
  `require_verified_identity`, and `production_profile`, so post-seal mutation
  can no longer swap in an unvalidated registry, drop critical hooks, or
  otherwise invalidate the sealed guarantees. Assigning a production profile to
  an existing runtime re-arms the fail-closed admission gate.
- `Runtime.apreview` and `Runtime.areplay` enforce the same fail-closed
  sealing gate as `Runtime.arun`, so governance previews and replays cannot
  run middleware before a strict runtime is sealed.
- Policy middleware identities are validated at construction, and strict
  production sealing rejects policy middleware configured to fail open.
- Non-authoritative replay preserves caller correlation metadata, removes
  governance metadata, and returns a stable denial for invalid recorded
  parameters instead of leaking parser or contract exceptions.
- Identity replay-store durability validation now applies to any identity
  provider exposing a `replay_store`, not just the built-in HMAC provider.
- Contracted approvals now bind `action_digest`; v0.5 approvals remain readable
  but require re-approval. Contracted idempotency uses the isolated
  `action/v1` namespace and cannot reuse a v0.5 result.
- The exact frozen parameter snapshot covered by `action_digest` now
  materializes the tool call. Key, policy, precondition, contract, or parameter
  drift denies before tool entry.

### Fixed

- The production smoke test's pinned image pulls now treat a hung
  `docker pull` (`subprocess.TimeoutExpired`) as a retryable failure instead
  of aborting before the retry/backoff logic engages.
- Contracted idempotency partitions are stable across identity-key and contract
  version rotation, and fixed-length contract partitions accept every valid
  `contract_id` supported by `ActionContract` and SQLite stores.
- Deterministic replay is explicitly non-authoritative and no longer mints a
  `BoundAction` from persisted identity fields; current binding requires the
  trusted identity path through `apreview()`.
- Contract binding providers are queried at admission and once at the final
  executor boundary; the redundant intermediate revalidation call was removed
  without weakening the final TOCTOU check.
- Benchmark collection and release-budget evaluation reject invalid repetition
  counts, missing pairs, non-finite values, negative values, and invalid limits.

## [0.5.1] - 2026-07-26

### Security

- Invocation metadata can no longer supply reserved `approval_`, `identity_`,
  or `policy_` governance state. Reserved prefixes are filtered
  case-insensitively at the runtime trust boundary.
- Required approvals now execute only when a first-class grant is bound to the
  current request, allow decision, tool, arguments, risk tier, policy version
  and digest, subject, tenant, identity issuer, and unexpired decision. The
  binding is revalidated after pre-execution hooks, after approval commit, and
  inside the execution middleware chain immediately before the tool body.
- Runtime-owned duration metadata is isolated from caller metadata so metrics
  cannot be polluted by forged execution timing values.
- Middleware context transitions are enforced at runtime boundaries so
  observers and execution wrappers cannot rewrite identity, tool arguments,
  risk, approval, decisions, or terminal outcomes through reconstructed
  contexts.
- Context result snapshots now freeze nested mappings and sequences before
  post-execution observers run, preventing in-place audit-state mutation.

### Changed

- Serialized execution contexts now include validated approval request and
  decision identifiers. Contexts created by earlier releases remain readable
  and restore as unapproved unless they contain the new bound state.
- A later deny decision clears any previously granted approval state.
- Durable approvals issued by `0.5.0` do not contain the new risk and policy
  digest bindings. They fail closed after upgrade and must be reissued.

## [0.5.0] - 2026-07-26

### Added

- Idempotent execution modes with in-memory and SQLite ledgers, lease renewal,
  result reuse, conflict detection, and explicit `UNKNOWN` recovery state.
- Persistent approval stores, trusted HMAC identity providers, and replay
  protection for short-lived identity envelopes.
- Absolute deadline propagation, runtime bulkheads, cancellation handling,
  synchronous tool context propagation, and contract validation for parameters,
  results, and payload size limits.
- Reliable JSONL and SQLite audit/snapshot stores with hash-chain verification,
  redaction, and critical fail-closed delivery.
- Docker-backed production smoke tests for real OPA HTTP decisions, real OTLP
  HTTP export to an OpenTelemetry Collector, Prometheus `/metrics` scraping,
  and optional Kind example deployment.
- Fault, property, concurrency, benchmark, security, release, dependency-review,
  CodeQL, PyPI publish, and provenance verification assets.

### Fixed

- OpenTelemetry spans now propagate correctly into synchronous tool threads
  without leaking cross-task context managers.
- Slack notifications no longer forward raw policy or user-supplied denial
  reasons.
- Prometheus records `unknown` terminal outcomes so uncertain mutating writes
  are visible in metrics.
- Idempotency acquisition cancellation no longer waits on slow storage I/O and
  orphaned owner claims are settled as `UNKNOWN`.
- Idempotent tools without a key are now denied before execution, and absolute
  deadlines bound slow ledger acquisition.
- Tool execution now consumes the same isolated parameter snapshot used by
  contract validation, approval binding, and idempotency fingerprints.
- Durable approvals use leased reservation and commit transitions so later
  gates or critical pre-execution hooks cannot consume an unused approval.
- Uncooperative asynchronous tools retain execution capacity until the real
  task exits, preventing cancellation from bypassing the runtime bulkhead.
- OPA smoke policy fixtures use Rego v1 syntax and service readiness tolerates
  transient connection resets without hiding terminal failures.
- SQLite-backed stores serialize one-time WAL initialization across processes,
  avoiding startup lock races while retaining normal concurrent access.
- Cancellation context recovery now works across Python 3.10-3.13 without
  relying on version-specific `CancelledError` attribute preservation.
- Approval reservations that expire locally now deny at the execution boundary
  instead of allowing a request without an authoritative store commit.
- Idempotency ledger operations now have a dedicated timeout and capacity
  boundary; overrunning adapters fail closed without unbounded executor queues.
- Failures while settling an already-denied idempotent request preserve the
  monotonic denial instead of raising a context mutation error.
- Context serialization rejects non-string mapping keys and deterministically
  handles heterogeneous sets without silently changing approval payloads.
- Injected OpenTelemetry tracers can expose compatible status types directly;
  otherwise a one-time warning makes terminal-status degradation visible.
- CodeRabbit thread acknowledgements no longer overwrite the latest decisive
  approval or change-request verdict for the same pull-request head.

### Changed

- Raised the `filelock` runtime floor to 3.20.3 so supported installations do
  not retain releases affected by known security advisories.
- Raised the isolated build backend floor to `setuptools` 83.0.0 and upgraded
  CI/release installers to `pip` 26.1.2 or newer.
- Maintainers must use issue-linked pull requests; administrator direct pushes
  to `main` are no longer part of the project workflow.
- Release verification now checks both wheel and sdist distributions and
  verifies GitHub artifact attestations against the expected release workflow
  and tag ref before PyPI publishing.
- Release artifacts are built only when the tag commit belongs to protected
  `main`, after tests, dependency audit, and Docker integration smoke rerun.

## [0.4.2] - 2026-07-25

### Added

- A fail-closed status gate that verifies a CodeRabbit approval exists for the
  current pull request head commit.
- Repository-policy tests for approval, requested changes, stale reviews,
  missing reviews, and CodeRabbit rate limits.

### Fixed

- CodeRabbit's completion status can no longer satisfy merge protection when a
  review was skipped because of a service-side review limit.

## [0.4.1] - 2026-07-25

### Added

- GitHub-native linked-issue enforcement for every pull request.
- Pull request template with an explicit closing-keyword issue field.
- Repository-policy tests in CI and CodeRabbit as a required status context.

## [0.4.0] - 2026-07-25

### Added

- Build-time plugin registration and trusted Python entry-point discovery.
- Prometheus terminal metrics with bounded, non-identity labels.
- Slack denial/failure notifications with strict webhook validation.
- OPA policy decisions with minimal payloads and fail-closed defaults.
- CrewAI, Agno, LlamaIndex, and Microsoft AutoGen integration examples.

### Changed

- Synchronous LLM reviewers, human decision callbacks, hooks, audit sinks,
  snapshot stores, and network integrations run outside the event-loop thread.

## [0.3.0] - 2026-07-25

### Added

- Strict, versioned YAML policy documents with stable SHA-256 digests.
- Context snapshot stores, structured replay diffs, and a text debugger.
- Regression evaluation and policy drift detection over recorded requests.
- Mermaid trace rendering for lightweight visualization.

### Fixed

- Tool calls that require approval now fail closed when no explicit human
  decision was granted.
- Deterministic replay skips LLM, human decision, audit, metrics, and other
  non-replayable middleware.

## [0.2.0] - 2026-07-25

### Added

- Immutable pipeline composition and middleware metadata.
- Runtime hooks around pipeline, semantic review, decisions, tools, and audit.
- Python-native policies for permissions, approval, denial, and risk overrides.
- In-memory metrics plus retry and timeout execution middleware.
- Optional OpenTelemetry lifecycle export and OpenAI Agents SDK example.

## [0.1.0] - 2026-07-25

### Added

- Immutable execution context with OpenTelemetry-style trace identifiers.
- Deterministic gating and observing middleware contracts.
- Rule, semantic review, human decision, and audit middleware.
- Governed tool registry with synchronous and asynchronous execution.
- Redacted JSONL audit records with optional HMAC verification.
- Basic trace replay, LangGraph integration example, tests, and CI.
