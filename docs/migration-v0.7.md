# Migrating to v0.7 durable reconciliation storage

v0.7 extends the durable SQLite path with deterministic `UNKNOWN`
reconciliation. It retains generation-aware idempotency records, uses a
prepared-action recovery descriptor, and upgrades the reconciliation schema to
version 4 with a transactional reconciliation-audit outbox. The migration is
deliberately conservative. It never converts an uncertain prior side effect
into a retryable one and never fabricates historical provider evidence.

This guide applies to a deployment that uses SQLite for durable state. It is a
single-host, multi-process coordination boundary, not a multi-host database.
For a strict idempotent tool, `SQLiteIdempotencyStore` and
`SQLiteReconciliationLedger` must point to the same database file. A signed
durable source-idempotent audit sink may use a separate audit database, but it
must be restored with its signing key and must remain available to idempotently
drain the reconciliation outbox. `SQLiteAuditSink` is the built-in tested
implementation, not the only valid adapter.

## What the schema migration changes

The reconciliation database is upgraded transactionally to schema version 4.
It creates `reconciliation_audit_outbox` and its ordering, payload-identity
immutability, and retention guards. Each reconciliation head/event lineage
mutation can then commit its fixed-allowlist audit-delivery intent in the same
transaction. Raw provider evidence, raw tenant identities, and idempotency keys
do not enter that delivery queue; delivery-attempt and acknowledgement fields
remain mutable operational state.

For a pre-outbox reconciliation head, the migration emits exactly one
`migration_snapshot_recorded` envelope when no outbox event already exists for
that execution. That envelope records the current durable lineage state. It
does **not** reconstruct old provider attempts, copy raw probe evidence, or
claim a historical delivery that did not occur. Deliver the snapshot through
the normal outbox worker after the upgrade.

Malformed legacy idempotency rows are normalized conservatively to `unknown`
or `applied_no_result`, never to a retryable state. Do not delete those rows to
force a new execution. Reconcile the downstream effect or follow the manual
incident process first.

## SQLite journal-mode change

SQLite documents a WAL-reset race in affected library versions. v0.7 enables
WAL only for runtimes containing the official fix (3.51.3+, the 3.50.7
backport, or the 3.44.6 backport). `journal_mode="auto"` persistently converts
an existing WAL database to rollback `DELETE` journaling when the linked
runtime is affected. This reduces reader/writer concurrency because a writer
can block readers, but avoids running the reconciliation writer/checkpoint path
on a known-unsafe WAL implementation.

The journal conversion requires exclusive database access. During a rolling
upgrade, an older process or WAL reader may keep the database open and cause
initialization to raise `SQLiteJournalModeError`. Do not bypass this failure.
Stop the remaining old processes, confirm no connection holds the database,
and retry initialization. If uninterrupted multi-process WAL is mandatory,
upgrade the linked SQLite library to a fixed release before deploying v0.7 and
set `journal_mode="wal"`; v0.7 rejects that explicit mode on affected versions.

## Rollout sequence

1. Inventory every SQLite path, its Python and `sqlite3.sqlite_version`, its
   configured journal mode, and the process owners. Verify that each strict
   idempotent runtime will use one shared path for idempotency and
   reconciliation.
2. Drain side-effecting calls where possible. Preserve all pending,
   `UNKNOWN`, `MANUAL_REVIEW`, and `applied_no_result` keys; reconcile them or
   document their incident owner before the migration.
3. Stop all processes that share each state database. Take and verify a backup
   of the idempotency/reconciliation database, the SQLite audit database, audit
   chain state, and the associated signing and identity-digest keys. Validate a
   restore in an isolated location before continuing.
4. Start exactly one v0.7 process against each state database. Let it perform
   the schema and journal migration. If journal initialization fails, return to
   step 3; do not disable the safety check.
5. Inspect the resulting state. Confirm the reconciliation schema is version 4,
   existing heads have either historical outbox records or one
   `migration_snapshot_recorded` envelope, and any normalized idempotency rows
   remain blocked as expected.
6. Validate strict readiness before accepting traffic: trusted verified
   identity, colocated `SQLiteIdempotencyStore` and
   `SQLiteReconciliationLedger`, a stable provider for every idempotent tool,
   and a signed fail-closed source-idempotent audit sink (`SQLiteAuditSink` is
   the built-in tested implementation).
7. Run the application's authorized outbox-recovery worker to deliver pending
   migration snapshots. In a strict profile this means calling
   `Runtime.adrain_reconciliation_audit_outbox()` with a verified identity that
   has the configured `reconciliation:audit:drain` permission. The drain does
   not run reconciliation providers.
8. Start the remaining v0.7 processes only after the first process reports a
   successful production-readiness check and the recovery worker reports a
   bounded, observable result.

## Recovery behavior after upgrade

An idempotent action acquired by the v0.7 strict path has a prepared recovery
descriptor before tool dispatch. If the process dies with an unexpired lease,
the action remains exclusive. On lease expiry it materializes a durable
`UNKNOWN` head, not a retryable claim.

If a reconciliation provider attempt has a durable start record but no terminal
record, a second runtime must not probe while that attempt deadline is valid.
After expiry, the ledger records `recovery_required` and moves the action to
`MANUAL_REVIEW`; it does not guess the external result or invoke a replacement
provider. Manual resolution requires verified operator identity, tenant access,
the expected revision, explicit evidence, and an explicit retry-safe assertion
before `CONFIRMED_NOT_APPLIED` can make a new action generation possible.

An outbox delivery timeout, acknowledgement failure, or process restart leaves
the envelope pending. Restart the authorized recovery worker; do not mutate
`delivered_at` directly. `SQLiteAuditSink` uses the outbox source ID to make a
same-payload redelivery idempotent and rejects a different payload under the
same source ID.

## Rollback and retention

Rolling back application code does not roll back the SQLite schema or journal
mode. Restore the verified pre-upgrade backup if a v0.6 binary must be
reinstated. Do not attempt a manual schema downgrade, delete reconciliation
history or immutable outbox payloads, or reuse unresolved idempotency keys as a
rollback mechanism. Retention and archival changes require a tested migration
because the outbox and reconciliation history are part of the evidence lineage.
