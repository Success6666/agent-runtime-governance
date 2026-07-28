# ADR 0007: v0.8 canonical codec compatibility profiles

## Status

Accepted for the v0.8 compatibility boundary.

## Context

The runtime already has several durable JSON byte contracts. They are all
sorted and compact, but they intentionally differ in ASCII escaping,
non-finite-number handling, and number canonicalization. Replacing them with
one generic encoder would change audit hashes, HMACs, JSONL records, SQLite
text columns, public contract bytes, or action/reconciliation commitments.

v0.8 evidence needs a stable portable commitment format without silently
migrating those historical contracts.

## Decision

`agent_runtime_governance._canonical` is a private, dependency-neutral facade
with named profiles. Callers retain normalization, redaction, schema
validation, and domain-specific exception translation at their existing
boundaries.

| Profile | Contract | Current callers |
| --- | --- | --- |
| `legacy_audit_json_*` | ASCII-escaped, sorted compact JSON; rejects non-finite values | audit event/state hashes and HMACs; snapshot hashes and signatures |
| `legacy_storage_json_text` | ASCII-escaped, sorted compact JSON; retains historical non-finite behavior | snapshot JSONL/state and SQLite text; approval rows and integrity payloads |
| `legacy_policy_json_bytes` | ASCII-escaped, sorted compact JSON; retains historical non-finite behavior | YAML policy semantic digest and downstream governance identity |
| `legacy_contract_json_bytes` | UTF-8 sorted compact JSON; rejects non-finite values | public `contracts.canonical_json_bytes()` |
| `rfc8785_json_*` | RFC 8785 bytes | bound actions, reconciliation, and new portable evidence |

Existing public functions and persisted schemas keep their paths and byte
semantics. New evidence must use the RFC 8785 profile with its own domain
separator; it must not reuse audit HMAC or storage serialization as a portable
commitment format.

## Consequences

- A profile is selected explicitly at each compatibility boundary.
- Unicode, floats, policy digests, audit hashes/HMACs, snapshot signatures,
  JSONL state, and SQLite text have v0.5/v0.7 regression fixtures.
- A future format migration needs its own compatibility decision, migration
  path, and fixtures; refactoring through this facade is not a migration.
- The facade imports only standard JSON support and RFC 8785, preventing
  cycles with contracts, audit, snapshots, reconciliation, or Runtime.

## Non-goals

This decision does not add a public codec API, CBOR, MessagePack, a schema
migration, an evidence bundle, a signer, or a CLI command.
