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

## Implementation under release verification

- [x] v0.7: deterministic `UNKNOWN` reconciliation on an append-only,
  revision-checked ledger; atomic SQLite claim/descriptor preparation;
  persisted provider binding; and a durable, ordered reconciliation-audit
  outbox with source-idempotent SQLite delivery
- [x] v0.7: strict probe, manual-resolution, and audit-drain authorization;
  tenant isolation; bounded provider/finalization/audit-delivery paths; and
  recovery of expired unfinished probes into `MANUAL_REVIEW`

The v0.7 implementation is not listed as released until its protected CI,
Docker integration, migration, package, and publication evidence is recorded.

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

The [Microsoft Agent Governance Toolkit's versioned limitations](https://github.com/microsoft/agent-governance-toolkit/blob/2962693358c26201f2bbc13a54b5966af933accf/docs/LIMITATIONS.md)
explicitly distinguish attempted actions and allow/deny audit from verified
real-world outcomes and list outcome attestation as planned. That adjacent gap
is expected to narrow. Delivery speed for v0.6 and v0.7 is part of the strategy,
not an implementation detail.

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

Release evidence still requires the protected workflow and documented
publication record. The implementation does not claim external exactly-once
behavior without a downstream idempotency or receipt/probe guarantee.

## v0.8 - Evidence and conformance

- Versioned, privacy-aware Governance Evidence Bundle
- Offline verification and schema compatibility tests
- Cross-framework conformance for standalone, LangGraph, and OpenAI Agents SDK

## v0.9 - Distributed production adapters

- PostgreSQL authoritative state adapters
- Multi-instance leases, migrations, failover, and real database fault tests
- Optional Redis coordination that is never the irreversible-action fact source

## v1.0 - Stable Action Commit Safety

- Frozen public APIs, state transitions, evidence schemas, and adapter protocols
- Release-candidate recovery drills in two independent host applications
- Compatibility, security, performance, operations, and release evidence only;
  no platform expansion

## Out of scope

General policy language, plugin marketplace, dashboard, scheduler, cluster
controller, hosted control plane, model routing, agent planning, and automatic
compensation.
