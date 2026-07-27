# Migrating to v0.7 storage

v0.7 adds generation-aware idempotency records and the durable UNKNOWN
reconciliation ledger. Back up every SQLite store and stop mutating traffic
before the first v0.7 process opens a v0.6 database. The schema rebuild is
transactional and preserves valid rows; malformed legacy rows are converted
conservatively to `unknown` or `applied_no_result`, never to a retryable state.

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

1. Drain side-effecting calls and reconcile all known pending/UNKNOWN keys.
2. Stop all processes that share each SQLite file and take a verified backup.
3. Record the Python and `sqlite3.sqlite_version` values for the deployment.
4. Start one v0.7 process to run the schema and journal migration.
5. Inspect the migrated idempotency states. Rows normalized to `unknown` or
   `applied_no_result` require operator reconciliation and must not be deleted
   to force a retry.
6. Start the remaining v0.7 processes only after the first process reports a
   successful production readiness check.

Rolling back application code does not roll back the storage schema or journal
mode. Restore the pre-upgrade backup if a v0.6 binary must be reinstated.
