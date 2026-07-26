# ADR 0003: Action contract canonicalization

## Status

Accepted for v0.6 phase 1.

## Context

v0.5 computes separate JSON digests for approval and idempotency. Those formats
are already persisted and signed, so replacing their encoder in place would
silently invalidate existing records. v0.6 needs one cross-process action
identity that can later be shared by policy, approval, idempotency, execution,
and audit without changing the v0.5 formats during the migration.

The encoding is a security boundary. It must not coerce unsupported Python
objects, accept multiple semantic representations for the same action, invoke
untrusted representation hooks, or depend on mapping insertion order.

## Decision

### Canonical encoding

New action-contract values use the JSON Canonicalization Scheme from RFC 8785
through the public `rfc8785.dumps` API. The dependency is constrained to the
reviewed 0.1 release series. It is a dependency-free, Apache-2.0 implementation
that emits UTF-8 bytes and rejects non-string object keys and unsupported
values.

Inputs are normalized and validated before canonicalization:

- only JSON null, booleans, strings, arrays, objects with string keys, and
  finite numbers are accepted;
- integers must be within the RFC 8785 implementation's interoperable IEEE-754
  safe integer range;
- negative zero is rejected in accordance with verified RFC 8785 erratum 7920,
  rather than being normalized to positive zero;
- cyclic structures, nesting deeper than 100 levels, lone Unicode surrogates,
  and unsupported Python values are rejected explicitly;
- parameter bytes are checked against the contract's declared upper bound
  after canonicalization.

Deterministically encoded CBOR from RFC 8949 was considered. It is smaller, but
would add a second public representation while the project and its existing
integrations are JSON based. It is not part of v0.6.

### Domain and version separation

Contract, parameter, and action digests are SHA-256 over complete canonical JSON
envelopes. Principal and tenant digests use HMAC-SHA-256 over complete canonical
JSON envelopes with deployment- or tenant-scoped secret material. Raw strings
or partially concatenated values are never hashed.

- `arg.action-contract` version 1 binds the public contract fields.
- `arg.action-parameters` version 1 binds the normalized parameter snapshot.
- `arg.bound-action` version 1 binds the contract and parameter digests to the
  verified principal, tenant, identity-digest key version, policy, and optional
  precondition.
- `arg.principal.hmac-sha256.<key-version>` and
  `arg.tenant.hmac-sha256.<key-version>` bind identity values without exposing a
  dictionary-attackable unkeyed digest. The caller must provide at least 32
  bytes of secret material and an explicit rotation version for every bind.

The envelope carries both `domain` and `version`. Digest values are exposed as
lowercase hexadecimal SHA-256 strings. Any future encoding or field-semantics
change requires a new envelope version or domain; it cannot reinterpret an
existing digest.

### Immutable values

`ActionContract` and `BoundAction` are frozen value objects. Their nested JSON
members are detached from caller-owned inputs and recursively frozen. Public
serialization is an explicitly versioned envelope; deserialization recomputes
and verifies every non-secret-derived digest. Representations omit raw principal
and tenant values and retain only keyed, domain-separated HMAC digests. The
principal digest jointly binds the trusted identity issuer and opaque subject,
preventing equal subject values from different identity providers from sharing
an action identity. The HMAC key is an ephemeral binding input: it is never
retained by `BoundAction`, emitted by `repr`, serialized, or written to evidence.
Only the non-secret key version is retained and bound into the action digest so
operators can trace rotations. Cross-process identity is deterministic only
when both processes possess the same scoped key and key version; rotating either
intentionally changes the principal, tenant, and action digests. If the scoped
key is compromised, the digests must be treated as correlation identifiers
rather than identity confidentiality guarantees.

Identity values are valid Unicode strings so OIDC subjects, email-style
identifiers, and URI forms are not constrained by tool-name syntax. `repr` also
excludes raw parameters, and a separate evidence representation excludes
parameters entirely. The full `to_dict()` form includes the isolated parameters
only for controlled persistence, migration, and replay readers; audit logs and
external evidence must use the parameter-free evidence representation.
Parameter schema failures report only the failed path and constraint; they
never include the rejected instance value.

An `ActionContract` includes its stable identifier and version, tool name,
execution mode, parameter schema, effect class, precondition requirements,
optional receipt schema, and maximum parameter bytes. Binding validated
parameters produces a `BoundAction` with contract, parameter, and action
digests.

### Compatibility boundary

This phase does not change `canonical_json_bytes`, approval argument digests,
identity signatures, idempotency fingerprints, or existing stored records.
Runtime integration is a later v0.6 phase with versioned migration readers and
compatibility tests. Applications can therefore adopt the new public values
without silently changing v0.5 execution identity.

## Consequences

- Contract and parameter identities are deterministic across supported Python
  processes and interoperable RFC 8785 implementations for accepted inputs.
  Bound action identities additionally require the same scoped HMAC key and key
  version.
- Some values accepted by the older internal JSON helper, such as integers
  outside the IEEE-754 safe range and negative zero, are intentionally rejected
  at the new action boundary.
- A small runtime dependency is added instead of maintaining a custom
  cryptographic canonicalizer.
- Runtime, approval, idempotency, and audit migration remain explicit follow-up
  work and cannot be inferred from the presence of these value objects.

## References

- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [Verified RFC 8785 errata](https://www.rfc-editor.org/errata/rfc8785)
- [rfc8785.py](https://github.com/trailofbits/rfc8785.py)
- [RFC 8949: Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949)
