# Governance Evidence Bundle schema compatibility

The Governance Evidence Bundle currently supports exactly one serialized
bundle version: v1. Its canonical historical vector is packaged with both the
wheel and source distribution at
`agent_runtime_governance/_compatibility/evidence/v1/` and is exercised in the
supported Python-version CI matrix.

## v1 contract

v1 is a closed, RFC 8785-canonical document. It has no extension namespace and
does not ignore unknown fields. Every required field is present, the in-bundle
`signature` is always `null`, and `execution.receipt` is always `null`.
Signatures, protected continuity anchors, provider payloads, and tool-specific
receipts are detached inputs; they are not additive v1 fields.

The parser rejects all of the following rather than guessing a compatible v1
meaning:

- an unknown `schema_version`, including a future version;
- an unknown top-level or nested field;
- a missing required v1 field;
- a non-canonical representation of an otherwise valid value.

This fail-closed behavior is intentional. A verifier must not interpret a
future producer's added semantics as an older, weaker record.

## Introducing a future version

A future bundle version must be proposed and processed explicitly. Its change
must include all of the following before it is accepted as compatible:

1. a separate schema version and an explicit parser/dispatch rule;
2. a new canonical historical fixture and exact digest vector;
3. documented semantics for each added, removed, or reinterpreted field;
4. compatibility tests for old vectors, the new vector, and forward-version
   rejection by old readers.

There is no implicit migration, defaulting, or v1 fallback. Detached sidecar
protocols may evolve independently, but they must remain bundle-external and
must not alter existing v1 canonical bytes or digest commitments.
