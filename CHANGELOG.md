# Changelog

All notable changes are documented here.

## [0.5.1] - 2026-07-26

### Security

- Invocation metadata can no longer supply reserved `approval_`, `identity_`,
  or `policy_` governance state. Reserved prefixes are filtered
  case-insensitively at the runtime trust boundary.
- Required approvals now execute only when a first-class grant is bound to the
  current request, allow decision, tool, arguments, subject, tenant, identity
  issuer, and unexpired decision.

### Changed

- Serialized execution contexts now include validated approval request and
  decision identifiers. Contexts created by earlier releases remain readable
  and restore as unapproved unless they contain the new bound state.
- A later deny decision clears any previously granted approval state.

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
