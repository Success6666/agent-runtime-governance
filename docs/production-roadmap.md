# Production Roadmap: Action Commit Safety

## Status

- Direction approved after the v0.5.1 production reliability release.
- Last reviewed: 2026-07-29.
- This document defines future work and retains the v0.7 release and v0.8
  implementation exit criteria as historical evidence. Shipped behavior is
  documented in the release notes and production guide.
- A production claim is published only when it points to a repeatable test,
  benchmark, integration run, or release artifact.

## Executive decision

Agent Runtime Governance will not compete by accumulating more middleware,
framework examples, or policy syntax. Human approval, policy interception,
audit, replay, idempotency, and telemetry are necessary production foundations,
but they are no longer distinctive on their own.

The product direction is **Action Commit Safety for AI Agents**:

> Enforce that the action approved is the action executed; never blindly retry
> an uncertain side effect; and provide a deterministic reconciliation protocol
> with an auditable path from intent to supported evidence about the outcome.

The runtime remains an embeddable Python library. It does not become an agent
planner, workflow engine, hosted control plane, or Kubernetes operator. It is
positioned as a complement embedded inside host agent frameworks, not as a
replacement for them: framework-native approval flows remain useful, and this
runtime binds their decisions to the committed action.

## Verified baseline

The roadmap starts from the released v0.8.1 baseline, not from planned
features. The v0.5.1 evidence below remains a historical release record.

| Evidence | Verified result |
| --- | --- |
| Release source | [`v0.5.1`](https://github.com/Success6666/agent-runtime-governance/releases/tag/v0.5.1) was built from protected `main` |
| Release tests and coverage | The point-in-time [release workflow run](https://github.com/Success6666/agent-runtime-governance/actions/runs/30189974541/job/89761387069) reports 396 tests passed with 88.89% branch coverage |
| Supported Python CI | The [pull-request matrix](https://github.com/Success6666/agent-runtime-governance/actions/runs/30189730392) passed on Python 3.10, 3.11, 3.12, and 3.13 |
| Real integrations | The [release job](https://github.com/Success6666/agent-runtime-governance/actions/runs/30189974541/job/89761387069) passed Docker-backed OPA HTTP decisions, OTLP HTTP export, and Prometheus scraping |
| Supply chain | The release contains the [SPDX SBOM](https://github.com/Success6666/agent-runtime-governance/releases/download/v0.5.1/sbom.spdx.json), [SHA256 checksums](https://github.com/Success6666/agent-runtime-governance/releases/download/v0.5.1/SHA256SUMS), and [GitHub provenance](https://github.com/Success6666/agent-runtime-governance/attestations/37136035) |
| Dependency audit | The isolated production dependency audit passed in the [release job](https://github.com/Success6666/agent-runtime-governance/actions/runs/30189974541/job/89761387069) |
| Distribution | [`agent-runtime-governance==0.5.1`](https://pypi.org/project/agent-runtime-governance/0.5.1/) was published with PyPI Trusted Publishing and installed from the public index in a clean environment |
| Current release record | [`v0.8.1`](https://github.com/Success6666/agent-runtime-governance/releases/tag/v0.8.1) released after its protected artifact and PyPI workflows; the point-in-time evidence is recorded in [`release-verification.md`](release-verification.md) |

The evidence is point-in-time. It is not an uptime, latency, security, or future
dependency guarantee.

## Market boundary

The following overlap is treated as industry baseline rather than a unique
product claim. The final column is this project's narrower proof target, not a
claim that another project cannot implement it.

| Capability | Existing public overlap | This project's narrower proof target |
| --- | --- | --- |
| Multi-stage guardrails | OpenAI Agents SDK and NVIDIA NeMo describe input, output, retrieval, dialog, and execution guardrails | Govern the external side-effect commit boundary rather than expand prompt or content rails |
| Human approval and policy | OpenAI Agents SDK, LangChain, pydantic-ai deferred tools, and Agent Policy describe persistent HITL and deterministic policy decisions | Bind one canonical `BoundAction` to policy, approval, idempotency, execution, and audit |
| Chokepoint, idempotency, and leases | Lynx and OnceOnly describe action chokepoints, persistent execution, leases, and duplicate suppression | Combine intent-bound approval with explicit `UNKNOWN` and a reconciliation protocol |
| Cryptographic evidence | Stipul describes pre-execution policy and cryptographic proof | Separate evidence integrity, signer authenticity, and verified external outcome, then test the complete chain across frameworks |
| Broad governance runtime | Microsoft Agent Governance Toolkit spans policy, runtime, observability, and other packages | Keep a narrow embeddable library and publish conformance evidence for the action-commit path |

These references establish public feature overlap, not independent validation
of another project's production quality:

- [OpenAI Agents SDK guardrails](https://openai.github.io/openai-agents-js/guides/guardrails/)
- [OpenAI Agents SDK human in the loop](https://openai.github.io/openai-agents-js/guides/human-in-the-loop/)
- [LangChain human in the loop](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)
- [pydantic-ai deferred tools](https://ai.pydantic.dev/deferred-tools/)
- [NVIDIA NeMo Guardrails rail types](https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/rail-types)
- [Agent Policy](https://agent-policy.github.io/guard/)
- [Lynx](https://lynxharness.com/)
- [OnceOnly](https://www.onceonly.tech/)
- [Stipul](https://stipul.dev/)
- [Microsoft Agent Governance Toolkit packages](https://microsoft.github.io/agent-governance-toolkit/packages/)

The defensible opening is the commit boundary between an approved action and an
external side effect. Adjacent projects, including Microsoft Agent Governance
Toolkit, are actively expanding receipt and outcome-attestation work. That
overlap is a market signal, not proof that this project or no other project
solves the entire problem. The intended differentiation is the tested
combination of a unified bound action, intent-bound approval, explicit
`UNKNOWN` reconciliation, cross-framework evidence consistency, and a narrow
in-process deployment model:
[Microsoft known limitations at commit `2962693`](https://github.com/microsoft/agent-governance-toolkit/blob/2962693358c26201f2bbc13a54b5966af933accf/docs/LIMITATIONS.md).

Two boundary observations recorded on 2026-07-26 qualify that opening:

- The Microsoft toolkit repository already contains in-progress receipt and
  attestation schemas alongside the planned-outcome-attestation statement, so
  the overlap window should be treated as narrowing rather than static.
  Delivery speed for v0.6 and v0.7 is therefore strategic, not incidental.
- [HumanLayer's versioned SDK notice](https://github.com/humanlayer/humanlayer/blob/bdea199c/humanlayer.md)
  states that its SDK documentation is being superseded by CodeLayer and that
  the SDKs were removed. This documents a product-positioning pivot; it does
  not prove that approval is an invalid category. It does suggest that approval
  alone may be a less durable differentiator, supporting this project's narrower
  emphasis on the commit boundary.

## Target users

Primary users are teams that embed agent tool calls into systems where a
duplicate, substituted, or unverified action has material consequences:

- infrastructure and operations automation;
- data administration and migration tools;
- financial or quota-bearing API actions;
- internal enterprise workflows with human authorization;
- agent platforms that need a framework-neutral execution boundary.

The framework is not optimized for read-only chat, prompt filtering alone, or
teams seeking a hosted dashboard without owning their execution code.

## Target developer contract

The roadmap targets six v1.0 invariants. They are not all current v0.5.1
capabilities:

1. **Intent binding** - policy, approval, idempotency, execution, and audit use
   one canonical bound action.
2. **No blind retry** - a side effect with uncertain outcome remains `UNKNOWN`
   until deterministic or human reconciliation supplies evidence.
3. **Fail-closed authority** - missing identity, policy, approval, contract, or
   critical evidence cannot silently become permission.
4. **Explicit effects** - mutating tools declare their execution and receipt
   semantics before production startup.
5. **Portable evidence** - a verifier can validate evidence without trusting its
   storage or transport. Authenticity still depends on configured trust roots,
   and an external outcome is verified only by a supported receipt verifier.
6. **Framework consistency** - the same bound action receives the same
   governance result regardless of the supported host framework.
7. **Decision provenance** - a verifier can inspect the deterministic controls
   behind a recorded policy result without receiving policy inputs, prompts, or
   free-text remote output.

## Reference flow

```text
User intent + trusted principal + tool request
                     |
                     v
           Normalize tool parameters
                     |
                     v
        Bind immutable Action Contract
                     |
                     v
    Policy + approval + idempotency admission
                     |
                     v
              Commit boundary
                     |
          +----------+----------+
          |          |          |
          v          v          v
     SUCCEEDED     FAILED     UNKNOWN
                                  |
                                  v
                   Reconciliation protocol
                                  |
               +------------------+------------------+
               |                  |                  |
               v                  v                  v
     CONFIRMED_SUCCEEDED  CONFIRMED_NOT_APPLIED  MANUAL_REVIEW/UNKNOWN
               |                  |                  |
               +------------------+------------------+
                                  |
                                  v
                       Verifiable evidence bundle
```

## Delivery sequence

| Release | Product proof | Explicit exclusion |
| --- | --- | --- |
| v0.6 | One immutable action is shared by contract, policy, approval, idempotency, execution, and audit | No reconciliation engine or distributed transaction |
| v0.7 | Every uncertain side effect enters a deterministic reconciliation protocol that may still require manual review | No automatic compensation or hosted operator UI |
| v0.8 | Governance evidence is portable, privacy-aware, and independently verifiable | No compliance certification claims |
| v0.9 | A recorded policy result has a detached, privacy-safe, offline-verifiable explanation | No policy DSL, dashboard, or tool replay |
| v0.10 | Multi-instance state adapters preserve single-active-commit-owner semantics under failure | Redis is not an authoritative fact store |
| v1.0 | Public APIs, state transitions, schemas, and compatibility policy are stable | No platform expansion during stabilization |

## v0.6 - Action Contracts and strict production profile

### Objective

Eliminate representation drift between what policy evaluated, what a human
approved, what idempotency identified, what the tool received, and what audit
recorded.

### Planned model

- `ActionContract` declares a stable contract identifier and version, execution
  mode, parameter contract, effect class, precondition requirements, and result
  receipt schema.
- `BoundAction` is created only after the runtime prepares and isolates tool
  parameters. It carries canonical contract, parameter, policy, principal,
  tenant, and optional precondition digests.
- `action_digest` is the single immutable identifier consumed by policy,
  approval, idempotency, the executor boundary, and audit.
- The strict production profile rejects mutating tools without a valid contract
  during runtime construction, before traffic is accepted.
- Existing non-strict construction remains available for migration and clearly
  reports which tools are not production-ready.

The exact public API is frozen only after an ADR and executable contract tests.
Canonicalization must reject ambiguous values instead of silently coercing
them, including non-finite numbers, unsupported objects, duplicate semantic
representations, and oversized payloads.

### Work packages

1. Record the action-contract state model, trust boundary, canonical encoding,
   and compatibility rules in an ADR.
2. Add immutable `ActionContract` and `BoundAction` value objects with versioned
   canonical serialization and SHA-256 digests.
3. Bind the action after `_prepare_parameters` and before policy or approval.
4. Replace separate approval and idempotency fingerprints with the bound action
   digest while retaining versioned migration readers.
5. Add a strict production profile with startup validation and an inventory
   report for incomplete tool registrations.
6. Carry contract identifiers and digests into audit records without exposing
   raw sensitive parameters.
7. Publish a migration guide and one real mutating-tool integration example.

### Verification matrix

- Unit and property tests cover mapping order, nested values, Unicode,
  unsupported types, non-finite numbers, payload limits, and deterministic
  serialization across fresh processes.
- Approval becomes invalid after any tool, parameter, contract, policy,
  principal, tenant, issuer, expiry, or precondition change.
- Middleware and hooks cannot substitute a new bound action after approval.
- The exact isolated parameter snapshot hashed by `BoundAction` reaches the
  tool body.
- Audit, denial, timeout, cancellation, and exception paths record the same
  action identifier.
- Python 3.10-3.13, Windows, Linux, Docker integration, dependency audit, and
  release-package verification remain green.
- A benchmark baseline and regression budget are committed before optimization;
  implementation and budget relaxation cannot occur in the same pull request.

### Exit criteria

- The strict builder enumerates the complete registry and fails construction
  when any `MUTATING` tool lacks a valid action contract.
- The internal executor accepts the current `BoundAction`, and a digest mismatch
  fails before entry into the tool body.
- Registry traversal, state-machine model, mutation, and real-call tests enforce
  the strict-builder and executor invariants.
- Canonicalization has deterministic cross-process fixtures and property tests.
- Existing v0.5 applications have a documented migration path and non-strict
  compatibility tests.
- Every README production claim added for v0.6 links to its test, benchmark, or
  release evidence.

### Not in v0.6

- resolving `UNKNOWN` outcomes;
- compensation, saga orchestration, or distributed transactions;
- PostgreSQL or Redis state stores;
- evidence-bundle signing or an offline verifier;
- new agent framework examples.

## v0.7 - Reconciliation and recovery

### Objective

Turn `UNKNOWN` from an operator warning into an explicit recovery protocol
without ever treating uncertainty as permission to repeat a side effect.

### Implementation status

The core protocol shipped as v0.7.0 on 2026-07-27 from protected `main` after
the recorded CI, Docker integration, package, provenance, and PyPI publication
checks. See [`release-verification.md`](release-verification.md) for immutable
workflow and release links. The released model is:

- A versioned `ReconciliationProvider` protocol whose stable identifier,
  protocol version, and supported evidence kinds are persisted with the
  unresolved action; the callable itself is not persisted. The application is
  responsible for making the provider read-only.
- Legal, append-only, expected-revision transitions from `UNKNOWN` to
  `CONFIRMED_SUCCEEDED`, `CONFIRMED_NOT_APPLIED`, or `MANUAL_REVIEW`.
- Tool-specific receipts and external state probes as bounded evidence.
- No automatic reuse of an idempotency key while its reconciliation disposition
  remains blocked.
- A SQLite recovery descriptor prepared atomically with the idempotency owner,
  a transactional fixed-allowlist audit outbox, and expired-unclosed-attempt
  recovery into `MANUAL_REVIEW` without a second provider invocation.

### Exit criteria

- The failure matrix covers crash before dispatch, crash after external commit
  but before local record, timeout, cancellation, lease loss, audit failure,
  duplicate workers, and unavailable reconciliation providers.
- The runtime does not automatically redispatch the same unresolved
  `action_digest`.
- Manual resolution records operator identity, reason, prior state, new state,
  timestamp, and supplied evidence.
- Restart and competing-worker tests allow at most one active commit owner per
  action key on all supported local durable stores.
- External exactly-once behavior is claimed only when the downstream system
  supports a stable idempotency key or a receipt/probe can verify the result;
  otherwise the action remains `UNKNOWN` or enters manual review.
- Windows, Linux, and Docker recovery tests use real persistence rather than
  mocked repositories.

## Released v0.8 - Evidence and conformance

### Objective

Make the integrity and configured signer authenticity of action-governance
evidence independently verifiable, verify supported external receipts, and prove
that supported framework adapters preserve identical governance semantics.

### Shipped model

- A versioned Governance Evidence Bundle contains normalized action, identity,
  policy, approval, execution, reconciliation, audit-anchor, and redaction
  commitments without raw parameters, prompts, or identity values.
- The offline verifier validates strict JSON/schema input, canonical digest
  commitments, requested tenant/policy/contract bindings, reconciliation
  sequence and legal transitions, plus detached Ed25519 signatures against
  explicit trust roots.
- Its machine-readable report keeps bundle `integrity`, signer `authenticity`,
  and `outcome_verified` separate. Integrity alone never asserts an external
  real-world result; an unsigned bundle without an expected digest is reported
  as unanchored.
- A deployment can explicitly select one detached external anchor provider or
  tool-specific receipt verifier. The verifier has no generic network client;
  without a protected anchor, continuity remains unsupported, and a valid
  receipt establishes only the outcome claim that its verifier supports.
- Bundle v1 remains closed and canonical. Its historical vector is packaged in
  wheel and sdist artifacts; unknown versions, fields, and non-null in-bundle
  receipt/signature semantics are rejected rather than interpreted as v1.
- The optional `evidence` extra supplies the default Ed25519 signer and verifier
  with key identifiers, trust roots, rotation, and revocation. It remains out
  of the core installation.

### Implemented release boundaries

- The release workflow is configured to publish a machine-readable Release
  Verification Manifest containing test and coverage summaries, integration
  results, dependency-audit status, and pinned external-service image digests.
  It is included in release checksums and provenance so evidence remains
  available after Actions log retention expires.
- Evidence Bundle v1 projects a closed allowlist that excludes raw prompts,
  secrets, sensitive parameters, and raw identity values.
- The conformance suite covers the
  standalone runtime, LangGraph, and OpenAI Agents SDK paths.

### Exit criteria

- The verifier detects mutation, reordering, cross-tenant substitution, stale
  policy, stale contract, and broken reconciliation links. Deletion detection
  requires a protected external anchor and reports unsupported when absent.
- Signature tests cover trusted, unknown, rotated, revoked, and expired keys.
- Receipt tests prove that a valid bundle without a supported receipt verifier
  can be authentic while `outcome_verified` remains false.
- Evidence contains no raw secret fixture in privacy tests and uses a closed
  allowlist projection.
- At least three real framework entry paths produce the same decision, action
  digest, execution status, and evidence semantics for shared fixtures.
- Schema evolution and migration fixtures run in CI.
- Release CI verifies the Release Verification Manifest schema, checksums, and
  provenance before publication.
- Documentation makes no certification or legal-compliance claim without an
  external assessment.

## v0.9 - Verifiable policy decisions

### Objective

Make the deterministic policy result for an already-bound action independently
inspectable without turning the SDK into a policy platform or duplicating the
v0.8 receipt-verification path.

### Planned model

- Define a versioned immutable decision-explanation attachment bound to the
  action digest, policy version/digest, final decision, risk, approval
  requirement, and an ordered sequence of stable control results.
- Limit each control result to a stable control ID/version, effect, result, and
  machine-readable reason code. Raw parameters, prompts, model output,
  chain-of-thought, secrets, identity values, and free-text remote policy
  output are excluded.
- Keep Evidence Bundle v1 closed. The attachment binds to its action and bundle
  identity without changing v1 bytes, schemas, signatures, or receipt sidecars.
- Extend the existing offline verifier and provide a thin human-readable
  renderer of its report. Neither component becomes an authorizer, dashboard,
  network client, or second verification engine.
- Add a read-only comparison of two attachments for the same action identity.
  It reports decision, policy, risk, approval, and control drift without
  invoking a tool, LLM, human decision provider, or external receipt provider.
- Project deterministic explanations from built-in Python/YAML policies and
  rule middleware. An external policy can participate only through a declared
  structured explanation contract; a free-text reason is not verified evidence.

### Exit criteria

- An attachment proves its final decision, ordered controls, risk, approval
  requirement, action identity, and policy identity without exposing sensitive
  inputs.
- The verifier rejects reordering, duplicate controls, mutation, action/policy
  substitution, and final-decision inconsistency.
- Missing or invalid explanation evidence can never authorize an action or
  rewrite an evidence bundle, receipt outcome, or reconciliation state.
- The comparison path remains side-effect free and detects policy/control/risk/
  approval drift.
- Standalone, LangGraph, and OpenAI Agents SDK paths produce identical decision
  explanation semantics for shared fixtures.
- A measured performance budget and the existing compatibility, security, and
  release gates remain green.

## v0.10 - Deferred multi-instance adapters

The retained [multi-instance PostgreSQL proposal](https://github.com/Success6666/agent-runtime-governance/issues/31)
starts only after a real adopter needs it. It will then cover authoritative
PostgreSQL state, bounded Redis coordination, leases, migrations, failover,
fault injection, and a separate performance record.

## v1.0 - Stable Action Commit Safety

### Objective

Stabilize the public contract. v1.0 is a compatibility and credibility release,
not another feature expansion.

### Exit criteria

- Public Python APIs, action states, evidence schemas, adapter protocols, and
  semantic-versioning policy are documented and frozen for the v1 line.
- At least one release candidate runs reproducible end-to-end recovery drills
  in two independent host codebases or separately maintained integration paths,
  with evidence records for each failure scenario.
- Two consecutive release candidates introduce no undocumented breaking API or
  schema change.
- Every supported Python, database, and framework version has a real CI path.
- No unresolved high-severity security advisory, duplicate-side-effect defect,
  or blocked data migration remains.
- PyPI, GitHub Release, SBOM, provenance, checksums, and clean installation are
  produced by the protected release process.
- Every production capability in README points to current verification evidence.

## Continuous production program

The following work is required in every release rather than deferred to one
milestone:

- threat-model and ADR updates for new trust boundaries;
- failure-injection tests for every new persistent transition;
- compatibility fixtures for old serialized state;
- dependency review, CodeQL, isolated `pip-audit`, SBOM, and provenance;
- bounded concurrency and context-isolation tests;
- point-in-time benchmarks with machine and interpreter metadata;
- migration, backup, restore, and rollback instructions whenever a release
  changes persistent formats, schemas, or storage adapters;
- issue-linked pull requests, protected main, required CI, CodeRabbit approval,
  and resolved review threads;
- a public release record before a feature is described as shipped.

## Explicitly rejected expansion

The roadmap does not include a general policy language, plugin marketplace,
dashboard, scheduler, cluster controller, agent planner, model router, hosted
approval service, or automatic compensation engine. Such work requires separate
user evidence and a new architectural decision; it cannot enter a milestone as
incidental scope.

## Definition of done

A milestone is complete only when all of the following are true:

1. The implementation follows an accepted issue and ADR where required.
2. Unit, property, concurrency, fault, integration, and migration tests match
   the changed failure surface.
3. Required checks and CodeRabbit approve the current commit.
4. The change merges through protected `main` without an administrator bypass.
5. Release artifacts, dependency audit, SBOM, checksums, and provenance pass.
6. The PyPI package installs and imports in a clean environment.
7. Documentation separates measured facts, current limitations, and future work.
8. A roadmap or milestone-planning pull request does not authorize
   implementation. After that plan merges, the next milestone starts from a
   separate implementation issue that fixes its scope, failure model, and
   required evidence before any implementation pull request opens.
