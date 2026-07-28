# ADR 0008: v0.8 private-service layout

## Status

Accepted for the focused internal extraction in #44.

## Context

The package root mixed stable v0.7-compatible facades with private runtime
dispatch, canonical-serialization, redaction, and optional-signing helpers.
That made dependency direction difficult to inspect even when the underlying
behavior was already separated.

Issue #44 forbids a broad package rename for aesthetics. The v0.7 API snapshot
also records module identity for public values, including the SQLite journal
capability objects. A wholesale module move would therefore add compatibility
risk without improving governance semantics.

## Decision

Only private implementation services move under
`agent_runtime_governance._internal`:

```text
_internal/
  runtime/          blocking, context-boundary, executor, dispatch, metadata,
                    and pipeline-runner services
  audit/            redaction primitive
  evidence/         optional Ed25519 binding
  serialization/    canonical-codec and immutable-value helpers
```

Stable public modules remain at their current paths. They may import a private
service, but private runtime services must not import the public `Runtime`
facade. The former private helper paths remain thin compatibility re-exports
to their new implementation locations throughout v0.8. Existing `middleware/` and
`plugins/` packages remain their own integration boundaries.

`_sqlite.py` remains at the package root as a compatibility exception: its
journal capability classes and functions are part of the v0.7 public API
snapshot. SQLite construction remains a boundary concern; this decision does
not change the database schema, journal policy, or adapter protocols.

## Consequences

- Public import paths, public object module identities, function signatures,
  audit bytes, evidence bytes, and SQLite formats remain unchanged.
- The source tree makes private domain ownership visible without adding a new
  public package or dynamic loading mechanism, while compatibility re-exports
  keep existing imports resolvable.
- Tests lock the private layout and prohibit a private runtime service from
  importing the public runtime facade. The established public API snapshot and
  behavior suites remain the compatibility gate.

## Non-goals

This is not a public package rename, a new storage abstraction, a plugin
marketplace, or an asyncio conversion. It introduces no user-facing feature.
