# ADR 0005: One bound action from admission to audit

## Status

Accepted for v0.6.

## Context

v0.5 normalizes a tool call once but derives separate approval and idempotency
digests. Policy metadata, trusted identity, contract version, and external
preconditions do not share one executor-bound identity. Independent
representations can drift between review and side effect even when every
individual component is correct.

## Decision

After parameter preparation and verified-identity construction, a contracted
runtime creates one immutable `BoundAction`. It binds the contract and exact
parameter snapshot to keyed principal and tenant digests, identity key version,
policy version and digest, and any declared precondition digest.

`ExecutionContext.bound_action` is an identity-class field. Runtime code may set
it once; middleware and hooks cannot replace it. Approval records carry its
`action_digest`. Contracted idempotency uses the digest as its fingerprint under
the versioned `action/v1` namespace. Its fixed-length tenant and contract
partitions are domain-separated SHA-256 digests of the verified tenant ID and
stable contract ID. They are independent of the rotatable identity-digest key
and contract version; either change updates the fingerprint in the same
partition and therefore conflicts instead of bypassing the prior record. The
executor reconstructs the action from the exact objects about to enter the
tool, current key material, policy identity, and current precondition before
tool entry. A mismatch is a denial, not `UNKNOWN`, because no side effect has
started.

The precondition provider receives the contract, normalized parameters,
verified principal, and tenant and returns a lowercase SHA-256 digest under the
request deadline. This is an admission check, not a distributed transaction.
Tools requiring strong external consistency must also submit an ETag, version,
CAS predicate, or transactional condition with the write itself.

Audit schema version 3 exposes the contract identifier, contract version, and
action digest. Its nested action is the parameter-free evidence form. Controlled
context and snapshot persistence retains the full isolated parameters for
replay and migration.

The strict profile is the policy-identity source of truth. Policy-bearing
middleware must advertise the same version and SHA-256 digest. Missing or
mismatched identities fail readiness before traffic.

The digest is SHA-256 over the exact immutable policy artifact admitted for
the deployment, not a descriptive label. Local loaders and OPA deployments
must derive middleware identity from the same artifact bytes or admitted OCI
manifest digest and verify artifact provenance outside the runtime.

## Compatibility

Non-contracted tools retain the v0.5 approval and idempotency paths. v0.5
contexts and approval documents remain readable when `bound_action` and
`action_digest` are absent. A contracted request cannot consume a legacy
approval; it requires re-approval. The new idempotency namespace prevents a
legacy record from being mistaken for a v0.6 action claim.

## Consequences

- Policy, approval, idempotency, execution, telemetry, and audit can correlate
  one action without raw identity or duplicate raw parameters.
- Key, policy, precondition, contract, or parameter drift fails before tool
  entry.
- Binding and executor revalidation add measurable overhead. The paired strict
  benchmark and CI budget make that cost visible.
- Rolling back side-effecting traffic to v0.5 requires reconciliation because
  v0.5 does not consult the `action/v1` idempotency namespace.

## Rejected alternatives

- Keeping independent component digests was rejected because equality between
  representations would remain an application convention.
- Storing raw principal and tenant values was rejected because correlation does
  not justify widening identity exposure.
- Reusing the v0.5 idempotency namespace was rejected because two identity
  schemes under one key space could return an invalid cached result.
- Treating executor mismatch as `UNKNOWN` was rejected because the tool has not
  started and the correct state is a deterministic denial.
