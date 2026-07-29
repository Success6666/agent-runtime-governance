# Roadmap

The architecture is frozen per release. New ideas enter this file before code.
The detailed production plan is in
[`docs/production-roadmap.md`](docs/production-roadmap.md).

## Released baseline

- [x] v0.1: immutable context, fixed pipeline, rule/LLM/decision/audit, replay
- [x] v0.2: hooks, Python policy, metrics, retry, timeout, OpenTelemetry
- [x] v0.3: versioned YAML policy, snapshots, replay diff, regression, drift
- [x] v0.4: plugin boundary, Prometheus, Slack, OPA, framework examples
- [x] v0.5.0: idempotency, durable approval, trusted identity, deadlines,
  cancellation, contracts, reliable stores, real integration smoke
- [x] v0.5.1: caller-metadata isolation, exact approval binding, and enforced
  middleware context authority
- [x] v0.6.0: immutable action contracts across policy, approval, idempotency,
  execution, telemetry, and audit

## Released v0.7

- [x] v0.7: deterministic `UNKNOWN` reconciliation on an append-only,
  revision-checked ledger; atomic SQLite claim/descriptor preparation;
  persisted provider binding; and a durable, ordered reconciliation-audit
  outbox with source-idempotent SQLite delivery
- [x] v0.7: strict probe, manual-resolution, and audit-drain authorization;
  tenant isolation; bounded provider/finalization/audit-delivery paths; and
  recovery of expired unfinished probes into `MANUAL_REVIEW`

v0.7.0 was released on 2026-07-27 from protected `main`. Its immutable CI,
integration, package, provenance, and PyPI publication evidence is recorded in
[`docs/release-verification.md`](docs/release-verification.md).

## Product direction

The next releases focus on **Action Commit Safety for AI Agents**:

> The approved action is the executed action; uncertain side effects are
> recorded as `UNKNOWN` and automatic reuse is blocked while the idempotency
> record is retained; and recovery produces verifiable evidence.

Lightweight deployment, framework independence, approval, audit, idempotency,
and telemetry remain required foundations. They are not treated as unique
differentiators.

The runtime is embedded inside existing agent frameworks as a governance
layer. It complements framework-native approval flows instead of replacing
the host framework.

Adjacent governance toolkits are also advancing outcome-attestation work, so
signed evidence alone is not a durable differentiator. This SDK remains focused
on the narrow, tested combination of immutable action binding, intent-bound
approval, explicit `UNKNOWN` containment, and offline verification at the
commit boundary.

## v0.6 - Action Contracts

- [x] One immutable bound action for policy, approval, idempotency, execution, and
  audit
- [x] Versioned canonical digests and strict production startup validation
- [x] Migration path for v0.5 registrations
- [x] Property, boundary, compatibility, and performance-regression tests

The release path requires CI checks enforced by branch protection, CodeRabbit
review, Docker smoke, package verification, artifact provenance, and PyPI
Trusted Publishing.

No reconciliation engine, distributed store, or new framework adapter enters
this release.

## v0.7 - Reconciliation and recovery

- [x] Explicit `UNKNOWN` state machine with append-only, revision-checked
  transitions to `CONFIRMED_SUCCEEDED`, `CONFIRMED_NOT_APPLIED`, or
  `MANUAL_REVIEW`
- [x] Tool-specific `ReconciliationProvider` bindings persisted with the action
  and rejected on provider identity drift after restart; applications must keep
  provider implementations read-only
- [x] No automatic key reuse while the reconciliation disposition is
  `BLOCKED_UNKNOWN` or `BLOCKED_MANUAL_REVIEW`
- [x] Atomic prepared-action recovery, cancellation/finalization, timeout,
  audit-delivery, crash/restart, and competing-worker regression coverage on
  local durable SQLite storage

The protected workflow and publication record for v0.7.0 are documented in
[`docs/release-verification.md`](docs/release-verification.md). The release
does not claim external exactly-once behavior without a downstream idempotency
or receipt/probe guarantee.

## Released v0.8

- [x] Versioned, privacy-aware Governance Evidence Bundle with detached signing,
  anchor, and receipt-verification boundaries
- [x] Offline verification, schema compatibility tests, and release-manifest
  provenance
- [x] Cross-framework conformance for standalone, LangGraph, and OpenAI Agents
  SDK
- [x] Async-first extension dispatch with a controlled synchronous fallback,
  event-loop-isolation tests, native async external-adapter compatibility, and
  bounded worker/queue observability ([#43](https://github.com/Success6666/agent-runtime-governance/issues/43))

v0.8.0 was withdrawn before distribution after its release verification failed.
v0.8.1 was released on 2026-07-29 with the same implementation scope and a
corrected release-audit path. Its immutable evidence is recorded in
[`docs/release-verification.md`](docs/release-verification.md).

## v0.9 - Verifiable policy decisions

- A detached, privacy-safe decision-explanation attachment bound to the action
  and policy identity, with stable control IDs, machine-readable results, and
  no raw inputs or free-text remote policy output ([#91](https://github.com/Success6666/agent-runtime-governance/issues/91))
- Offline verification and read-only comparison of decision, policy, risk,
  approval, and ordered-control drift; no new authorizer or tool replay
- A thin human-readable projection of the existing verifier report, not a
  dashboard, hosted service, policy DSL, or second verification engine

## v0.10 - Deferred multi-instance adapters

- PostgreSQL authoritative state adapters, leases, migrations, failover, and
  database fault tests remain retained in [#31](https://github.com/Success6666/agent-runtime-governance/issues/31)
- This work starts only when a real multi-host adopter requires it; Redis is
  never the irreversible-action fact source

## v1.0 - Stable Action Commit Safety

- Frozen public APIs, state transitions, evidence schemas, and adapter protocols
- Release-candidate recovery drills in two independent host applications
- Compatibility, security, performance, operations, and release evidence only;
  no platform expansion

## Out of scope

General policy language, plugin marketplace, dashboard, scheduler, cluster
controller, hosted control plane, model routing, agent planning, automatic
compensation, prompt/model provenance collection, and chain-of-thought storage.
