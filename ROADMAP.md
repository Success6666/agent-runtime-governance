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

The release path requires protected CI, CodeRabbit review, Docker smoke,
package verification, artifact provenance, and PyPI Trusted Publishing.

No reconciliation engine, distributed store, or new framework adapter enters
this release.

## v0.7 - Reconciliation and recovery

- Explicit `UNKNOWN` resolution state machine
- Tool-specific receipts and `ReconciliationProvider`
- No automatic key reuse before resolution
- Crash, timeout, cancellation, lease-loss, and competing-worker fault matrix

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
