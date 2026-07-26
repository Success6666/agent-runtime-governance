# ADR 0004: Strict production sealing

## Status

Accepted for v0.6 strict-production profile.

## Context

v0.5 permits tools to be registered after a `Runtime` is constructed. That is
useful for decorators and plugins, but a constructor cannot validate the final
registry. Treating construction alone as readiness would allow traffic before
all side-effecting tools, durable stores, trusted identity, and critical audit
delivery have been checked.

Production readiness also cannot be inferred safely from protocol conformance.
An in-memory object can implement the same methods as a durable adapter, and an
unsigned audit sink can implement the same write interface as a signed sink.
Startup diagnostics must be deterministic and must not expose tool arguments,
identity values, or secret material.

## Decision

### Registration and sealing lifecycle

A runtime configured with `ProductionProfile` starts unsealed. Tool registration
remains available so decorators, direct `ToolSpec` registration, and plugins can
finish composition. Every invocation fails before context construction while
the runtime is unsealed.

`Runtime.seal_production()` traverses the complete registry, evaluates the
versioned profile, and either raises `ProductionReadinessError` with a structured
report or atomically seals the registry. A sealed registry rejects every later
registration. Failed validation does not seal the registry or accept traffic.

Compatibility runtimes without a profile retain v0.5 behavior. They can call
`production_readiness(profile)` to obtain the same migration inventory without
changing execution behavior.

### Contract policy

Every `MUTATING` or `IDEMPOTENT` tool requires an `ActionContract`. `READ_ONLY`
tools have an explicit contract exception because they do not commit an external
side effect; they may still opt into a contract. A supplied contract must match
the registered tool name, execution mode, parameter schema, and parameter byte
limit. Contracted tools also require a tenant-scoped identity-digest key
provider, public key version, and explicit policy version and digest. Contracts
declaring external preconditions require a precondition digest provider. A tool
result schema must agree with a declared contract receipt schema.

The runtime binds the contract after parameter preparation and carries one
immutable action identity through policy, approval, idempotency, executor
revalidation, telemetry, and audit. The detailed decision is ADR 0005.

### Runtime capabilities

Every non-empty strict runtime requires trusted identity, durable identity
replay for the built-in HMAC provider, and durable integrity-protected
fail-closed audit. Side-effecting tools additionally require durable
idempotency. Tools requesting approval additionally require durable,
integrity-protected approval state. Concretely, sealing checks:

- a trusted identity provider with `require_verified_identity=True`;
- durable identity replay protection for the built-in HMAC provider;
- a durable idempotency store for side-effecting tools;
- a durable, integrity-protected, fail-closed audit middleware;
- when approval is required, a decision middleware with a durable and
  integrity-protected approval store.

Built-in adapters declare `production_durable`, `production_trusted`, and
`production_integrity_protected` capabilities. In-memory adapters declare these
capabilities as false. Third-party adapters are rejected unless they explicitly
declare the required capabilities; such a declaration is an operator-reviewed
adapter contract, not independent proof of durability.

Integrity protection requires at least 32 bytes of configured HMAC key material.
Keys and key providers are never serialized into readiness reports.

### Report boundary

The report contains only the profile version, readiness state, stable reason
codes, tool identifiers, execution modes, and public action-contract identifiers,
versions, and digests. Registry order is normalized by tool name. Parameters,
principals, tenants, signing keys, and identity-digest keys are excluded.

## Consequences

- Strict runtimes cannot accidentally serve traffic before registration and
  startup validation are complete.
- A deployment must call `seal_production()` explicitly after all tools are
  registered and before exposing readiness or network traffic.
- New built-in production adapters must declare and test their capabilities.
- Third-party capability declarations must be verified by deployment-specific
  durability, concurrency, restart, and integrity tests.
- v0.5 applications remain executable while receiving a deterministic migration
  inventory.

## Rejected alternatives

- Validating only in `Runtime.__init__` was rejected because the registry is not
  complete at that point.
- Automatically sealing on the first invocation was rejected because startup
  failures would occur after traffic was accepted and race with registration.
- Inferring durability from method names or structural protocols was rejected
  because process-local and durable implementations share the same interface.
- Serializing configuration for diagnostics was rejected because it could expose
  secret providers or key material.
