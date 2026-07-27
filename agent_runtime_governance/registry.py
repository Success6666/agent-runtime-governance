from __future__ import annotations

import json
import re
import sqlite3
from collections import OrderedDict
from concurrent.futures import Future
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from time import monotonic
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generic,
    Mapping,
    ParamSpec,
    Protocol,
    TypeVar,
)

from ._sqlite import connect_sqlite, initialize_sqlite
from .action_contracts import ActionContract
from .context import ExecutionMode, RiskTier
from .contracts import canonical_json_bytes, validate_schema
from .errors import ContractValidationError, RegistryError
from .reconciliation import ProviderDescriptor

if TYPE_CHECKING:
    from .runtime import Runtime

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")

_IDEMPOTENCY_SCHEMA = """
CREATE TABLE idempotency_records (
    execution_record_id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'pending', 'completed', 'unknown', 'manual_review',
        'applied_no_result', 'not_applied'
    )),
    result_json TEXT,
    error TEXT,
    owner_token TEXT,
    lease_expires_at TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(namespace, key, generation),
    CHECK(
        (state = 'pending' AND owner_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state != 'pending' AND owner_token IS NULL AND lease_expires_at IS NULL)
    ),
    CHECK(
        (state = 'completed' AND result_json IS NOT NULL AND error IS NULL)
        OR (state != 'completed' AND result_json IS NULL)
    )
)
"""


@dataclass(frozen=True, slots=True)
class ToolSpec(Generic[P, R]):
    name: str
    function: Callable[P, R]
    risk: RiskTier
    requires_approval: bool
    description: str
    execution_mode: ExecutionMode = ExecutionMode.MUTATING
    parameters_schema: Mapping[str, Any] | None = None
    result_schema: Mapping[str, Any] | None = None
    max_parameters_bytes: int | None = None
    max_result_bytes: int | None = None
    action_contract: ActionContract | None = None
    reconciliation_provider: ProviderDescriptor | None = None
    reconciliation_probe_schema: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}", self.name):
            raise ValueError("tool name must be a 1-128 character stable identifier")
        if not callable(self.function):
            raise TypeError("tool function must be callable")
        if self.action_contract is not None and not isinstance(
            self.action_contract, ActionContract
        ):
            raise TypeError("action_contract must be an ActionContract")
        if self.reconciliation_provider is not None and not isinstance(
            self.reconciliation_provider, ProviderDescriptor
        ):
            raise TypeError("reconciliation_provider must be a ProviderDescriptor")
        for name, value in (
            ("max_parameters_bytes", self.max_parameters_bytes),
            ("max_result_bytes", self.max_result_bytes),
        ):
            if value is not None and value < 1:
                raise ValueError(f"{name} must be greater than zero")
        if self.parameters_schema is not None:
            validate_schema(self.parameters_schema, label="parameters")
            object.__setattr__(
                self,
                "parameters_schema",
                _freeze_schema(deepcopy(self.parameters_schema)),
            )
        if self.result_schema is not None:
            validate_schema(self.result_schema, label="result")
            object.__setattr__(
                self, "result_schema", _freeze_schema(deepcopy(self.result_schema))
            )
        if self.reconciliation_probe_schema is not None:
            validate_schema(self.reconciliation_probe_schema, label="reconciliation probe")
            object.__setattr__(
                self,
                "reconciliation_probe_schema",
                _freeze_schema(deepcopy(self.reconciliation_probe_schema)),
            )


class IdempotencyConflictError(RuntimeError):
    """Raised when a key is reused for a different tool request."""


class IdempotencyOutcomeUnknownError(RuntimeError):
    """Raised when the original execution may still have taken effect."""

    def __init__(
        self,
        message: str,
        *,
        execution_record_id: str | None = None,
    ) -> None:
        self.execution_record_id = execution_record_id
        super().__init__(message)


class IdempotencyAlreadyAppliedError(RuntimeError):
    """Raised when an effect is confirmed but no result can be reconstructed."""


class IdempotencyInProgressError(RuntimeError):
    """Raised when another process owns an unexpired idempotency lease."""


@dataclass(frozen=True, slots=True)
class IdempotencyClaim:
    namespace: str
    key: str
    fingerprint: str
    owner: bool
    future: Future[Any]
    owner_token: str | None = None
    lease_seconds: float | None = None
    execution_record_id: str | None = None
    generation: int | None = None


class IdempotencyStore(Protocol):
    """Blocking idempotency adapter contract.

    Implementations must bound every blocking operation, including network and
    lock waits, so it returns within the runtime's configured
    ``idempotency_operation_timeout_seconds``. Python cannot safely terminate a
    blocked worker thread; the runtime therefore fails closed and poisons the
    adapter after an operation exceeds that boundary.
    """

    def acquire(
        self, namespace: str, key: str, fingerprint: str
    ) -> IdempotencyClaim: ...

    def complete(self, claim: IdempotencyClaim, result: Any) -> None: ...

    def fail(self, claim: IdempotencyClaim, error: BaseException) -> None: ...

    def mark_unknown(self, claim: IdempotencyClaim, error: BaseException) -> None: ...

    def renew(self, claim: IdempotencyClaim) -> None: ...


@dataclass(slots=True)
class _IdempotencyEntry:
    fingerprint: str
    future: Future[Any]
    execution_record_id: str


class InMemoryIdempotencyStore:
    """Thread-safe process-local coordination with a bounded terminal cache.

    Completed and unknown outcomes are retained with idle-TTL and LRU bounds.
    In-flight claims are never evicted. Use :class:`SQLiteIdempotencyStore` when
    outcomes must survive process restarts or cache eviction.

    This non-durable adapter models only the first process-local generation and
    therefore reports ``generation=1`` for every claim. Generation advancement
    after reconciliation is intentionally exclusive to durable stores.
    """

    production_durable = False

    def __init__(
        self,
        *,
        max_completed_entries: int = 10_000,
        completed_ttl_seconds: float = 3_600.0,
    ) -> None:
        if max_completed_entries < 1:
            raise ValueError("max_completed_entries must be at least one")
        if completed_ttl_seconds <= 0:
            raise ValueError("completed_ttl_seconds must be positive")
        self.max_completed_entries = max_completed_entries
        self.completed_ttl_seconds = completed_ttl_seconds
        self._entries: dict[tuple[str, str], _IdempotencyEntry] = {}
        self._completed: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = Lock()

    def acquire(self, namespace: str, key: str, fingerprint: str) -> IdempotencyClaim:
        storage_key = (namespace, key)
        with self._lock:
            self._evict_completed(monotonic())
            entry = self._entries.get(storage_key)
            if entry is None:
                entry = _IdempotencyEntry(
                    fingerprint, Future(), _new_execution_record_id()
                )
                self._entries[storage_key] = entry
                return IdempotencyClaim(
                    namespace,
                    key,
                    fingerprint,
                    True,
                    entry.future,
                    execution_record_id=entry.execution_record_id,
                    generation=1,
                )
            if entry.fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    "idempotency key was already used with different parameters"
                )
            if entry.future.done():
                self._remember_completed(storage_key, monotonic())
            return IdempotencyClaim(
                namespace,
                key,
                fingerprint,
                False,
                entry.future,
                execution_record_id=entry.execution_record_id,
                generation=1,
            )

    def complete(self, claim: IdempotencyClaim, result: Any) -> None:
        if not claim.owner:
            return
        with self._lock:
            if not claim.future.done():
                claim.future.set_result(_clone_json(result))
            self._remember_completed((claim.namespace, claim.key), monotonic())
            self._evict_completed(monotonic())

    def fail(self, claim: IdempotencyClaim, error: BaseException) -> None:
        if not claim.owner:
            return
        storage_key = (claim.namespace, claim.key)
        with self._lock:
            entry = self._entries.get(storage_key)
            if entry is not None and entry.future is claim.future:
                self._entries.pop(storage_key)
                self._completed.pop(storage_key, None)
            if not claim.future.done():
                claim.future.set_exception(error)
                claim.future.exception()

    def mark_unknown(self, claim: IdempotencyClaim, error: BaseException) -> None:
        if not claim.owner:
            return
        with self._lock:
            if not claim.future.done():
                claim.future.set_exception(
                    IdempotencyOutcomeUnknownError(
                        str(error), execution_record_id=claim.execution_record_id
                    )
                )
                claim.future.exception()
            self._remember_completed((claim.namespace, claim.key), monotonic())
            self._evict_completed(monotonic())

    def renew(self, claim: IdempotencyClaim) -> None:
        if not claim.owner:
            raise RuntimeError("only an idempotency owner can renew a claim")

    def _remember_completed(self, storage_key: tuple[str, str], now: float) -> None:
        self._completed[storage_key] = now
        self._completed.move_to_end(storage_key)

    def _evict_completed(self, now: float) -> None:
        cutoff = now - self.completed_ttl_seconds
        while self._completed:
            storage_key, touched_at = next(iter(self._completed.items()))
            if (
                touched_at > cutoff
                and len(self._completed) <= self.max_completed_entries
            ):
                break
            self._completed.popitem(last=False)
            entry = self._entries.get(storage_key)
            if entry is not None and entry.future.done():
                self._entries.pop(storage_key, None)


class SQLiteIdempotencyStore:
    """Durable cross-process idempotency ledger with conservative crash recovery.

    An expired pending lease is converted to ``unknown`` and is never
    automatically re-executed. Operators must reconcile the external side effect
    before deleting or otherwise resolving that record.
    """

    production_durable = True

    _IDENTIFIER = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")

    def __init__(
        self,
        path: str | Path,
        *,
        lease_seconds: float = 300.0,
        timeout_seconds: float = 30.0,
        journal_mode: str = "auto",
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lease_seconds = lease_seconds
        self.timeout_seconds = timeout_seconds
        self.journal_mode = journal_mode
        self._initialize()

    def acquire(self, namespace: str, key: str, fingerprint: str) -> IdempotencyClaim:
        self._validate_identifier("namespace", namespace)
        self._validate_identifier("key", key)
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("fingerprint must be a SHA-256 hex digest")
        owner_token = _new_owner_token()
        now = datetime.now(timezone.utc)
        lease_expires_at = now + timedelta(seconds=self.lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT fingerprint, state, result_json, error, lease_expires_at,
                       execution_record_id, generation
                FROM idempotency_records
                WHERE namespace = ? AND key = ?
                ORDER BY generation DESC
                LIMIT 1
                """,
                (namespace, key),
            ).fetchone()
            if row is None:
                execution_record_id = _new_execution_record_id()
                connection.execute(
                    """
                    INSERT INTO idempotency_records(
                        execution_record_id, namespace, key, generation,
                        fingerprint, state, owner_token,
                        lease_expires_at, updated_at
                    ) VALUES (?, ?, ?, 1, ?, 'pending', ?, ?, ?)
                    """,
                    (
                        execution_record_id,
                        namespace,
                        key,
                        fingerprint,
                        owner_token,
                        lease_expires_at.isoformat(),
                        now.isoformat(),
                    ),
                )
                connection.commit()
                return IdempotencyClaim(
                    namespace,
                    key,
                    fingerprint,
                    True,
                    Future(),
                    owner_token,
                    self.lease_seconds,
                    execution_record_id,
                    1,
                )
            (
                recorded_fingerprint,
                state,
                result_json,
                error,
                lease_value,
                execution_record_id,
                generation,
            ) = row
            if recorded_fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    "idempotency key was already used with different parameters"
                )
            future: Future[Any] = Future()
            if state == "completed":
                future.set_result(json.loads(result_json))
            elif state in {"unknown", "manual_review"}:
                future.set_exception(
                    IdempotencyOutcomeUnknownError(
                        error or "outcome is unknown",
                        execution_record_id=execution_record_id,
                    )
                )
            elif state == "applied_no_result":
                future.set_exception(
                    IdempotencyAlreadyAppliedError(
                        error
                        or "side effect applied but no result can be reconstructed"
                    )
                )
            elif state == "not_applied":
                next_execution_record_id = _new_execution_record_id()
                next_generation = generation + 1
                connection.execute(
                    """
                    INSERT INTO idempotency_records(
                        execution_record_id, namespace, key, generation,
                        fingerprint, state, owner_token, lease_expires_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                    """,
                    (
                        next_execution_record_id,
                        namespace,
                        key,
                        next_generation,
                        fingerprint,
                        owner_token,
                        lease_expires_at.isoformat(),
                        now.isoformat(),
                    ),
                )
                connection.commit()
                return IdempotencyClaim(
                    namespace,
                    key,
                    fingerprint,
                    True,
                    Future(),
                    owner_token,
                    self.lease_seconds,
                    next_execution_record_id,
                    next_generation,
                )
            elif state == "pending":
                lease_deadline = datetime.fromisoformat(lease_value)
                if lease_deadline <= now:
                    message = "owner lease expired before an outcome was recorded"
                    cursor = connection.execute(
                        """
                        UPDATE idempotency_records
                        SET state = 'unknown', error = ?, owner_token = NULL,
                            lease_expires_at = NULL, updated_at = ?
                        WHERE execution_record_id = ? AND generation = ?
                          AND state = 'pending' AND lease_expires_at = ?
                        """,
                        (
                            message,
                            now.isoformat(),
                            execution_record_id,
                            generation,
                            lease_value,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise RuntimeError(
                            "idempotency lease changed before expiry recovery"
                        )
                    self._materialize_prepared_reconciliation_head(
                        connection,
                        execution_record_id=execution_record_id,
                        recovered_at=now,
                    )
                    future.set_exception(
                        IdempotencyOutcomeUnknownError(
                            message, execution_record_id=execution_record_id
                        )
                    )
                else:
                    future.set_exception(
                        IdempotencyInProgressError(
                            "another process owns this idempotency key"
                        )
                    )
            else:
                future.set_exception(
                    RuntimeError(f"invalid idempotency state {state!r}")
                )
            connection.commit()
            return IdempotencyClaim(
                namespace,
                key,
                fingerprint,
                False,
                future,
                execution_record_id=execution_record_id,
                generation=generation,
            )

    def complete(self, claim: IdempotencyClaim, result: Any) -> None:
        if not claim.owner:
            return
        encoded = canonical_json_bytes(result, label="idempotency result").decode(
            "utf-8"
        )
        self._transition(claim, "completed", result_json=encoded)
        if not claim.future.done():
            claim.future.set_result(json.loads(encoded))

    def fail(self, claim: IdempotencyClaim, error: BaseException) -> None:
        if not claim.owner:
            return
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                DELETE FROM idempotency_records
                WHERE execution_record_id = ?
                  AND namespace = ? AND key = ? AND fingerprint = ?
                  AND owner_token = ? AND state = 'pending'
                """,
                (
                    claim.execution_record_id,
                    claim.namespace,
                    claim.key,
                    claim.fingerprint,
                    claim.owner_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("idempotency ownership was lost before failure")
            connection.commit()
        if not claim.future.done():
            claim.future.set_exception(error)
            claim.future.exception()

    def mark_unknown(self, claim: IdempotencyClaim, error: BaseException) -> None:
        if not claim.owner:
            return
        self._transition(claim, "unknown", error=str(error)[:2048])
        if not claim.future.done():
            claim.future.set_exception(
                IdempotencyOutcomeUnknownError(
                    str(error), execution_record_id=claim.execution_record_id
                )
            )
            claim.future.exception()

    def renew(self, claim: IdempotencyClaim) -> None:
        if not claim.owner or not claim.owner_token:
            raise RuntimeError("only an idempotency owner can renew a claim")
        now = datetime.now(timezone.utc)
        lease_expires_at = now + timedelta(seconds=self.lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE idempotency_records
                SET lease_expires_at = ?, updated_at = ?
                WHERE execution_record_id = ?
                  AND namespace = ? AND key = ? AND fingerprint = ?
                  AND owner_token = ? AND state = 'pending'
                """,
                (
                    lease_expires_at.isoformat(),
                    now.isoformat(),
                    claim.execution_record_id,
                    claim.namespace,
                    claim.key,
                    claim.fingerprint,
                    claim.owner_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("idempotency ownership was lost before renewal")
            connection.commit()

    def prune_completed(self, *, older_than: datetime) -> int:
        if older_than.tzinfo is None or older_than.utcoffset() is None:
            raise ValueError("older_than must be timezone-aware")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            has_reconciliation_heads = (
                connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'reconciliation_heads'
                    """
                ).fetchone()
                is not None
            )
            has_prepared_actions = (
                connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'reconciliation_prepared_actions'
                    """
                ).fetchone()
                is not None
            )
            cutoff = older_than.astimezone(timezone.utc).isoformat()
            if has_reconciliation_heads and has_prepared_actions:
                connection.execute(
                    """
                    DELETE FROM reconciliation_prepared_actions
                    WHERE execution_record_id IN (
                        SELECT execution_record_id FROM idempotency_records
                        WHERE state = 'completed' AND updated_at < ?
                          AND NOT EXISTS (
                              SELECT 1 FROM reconciliation_heads
                              WHERE reconciliation_heads.execution_record_id =
                                    idempotency_records.execution_record_id
                          )
                    )
                    """,
                    (cutoff,),
                )
            cursor = connection.execute(
                (
                    """
                    DELETE FROM idempotency_records
                    WHERE state = 'completed' AND updated_at < ?
                      AND NOT EXISTS (
                          SELECT 1 FROM reconciliation_heads
                          WHERE reconciliation_heads.execution_record_id =
                                idempotency_records.execution_record_id
                      )
                    """
                    if has_reconciliation_heads
                    else """
                    DELETE FROM idempotency_records
                    WHERE state = 'completed' AND updated_at < ?
                    """
                ),
                (cutoff,),
            )
            connection.commit()
            return cursor.rowcount

    @staticmethod
    def _materialize_prepared_reconciliation_head(
        connection: sqlite3.Connection,
        *,
        execution_record_id: str,
        recovered_at: datetime,
    ) -> None:
        """Create the durable UNKNOWN head prepared before tool dispatch.

        This runs in the same ``BEGIN IMMEDIATE`` transaction as lease-expiry
        recovery.  The optional tables preserve compatibility with deployments
        that use idempotency without the reconciliation subsystem; when the
        v0.7 ledger is configured, a prepared action is always present before a
        side-effecting tool body starts.
        """

        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table'
                  AND name IN (
                      'reconciliation_heads',
                      'reconciliation_prepared_actions'
                  )
                """
            )
        }
        if tables != {
            "reconciliation_heads",
            "reconciliation_prepared_actions",
        }:
            return
        prepared = connection.execute(
            """
            SELECT action_json FROM reconciliation_prepared_actions
            WHERE execution_record_id = ?
            """,
            (execution_record_id,),
        ).fetchone()
        if prepared is None:
            return
        connection.execute(
            """
            INSERT OR IGNORE INTO reconciliation_heads(
                execution_record_id, action_json, state, revision,
                disposition, resolved_result_available, resolved_result_json,
                updated_at
            ) VALUES (?, ?, 'UNKNOWN', 0, 'blocked_unknown', 0, NULL, ?)
            """,
            (
                execution_record_id,
                prepared[0],
                recovered_at.astimezone(timezone.utc).isoformat(),
            ),
        )

    def _transition(
        self,
        claim: IdempotencyClaim,
        state: str,
        *,
        result_json: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE idempotency_records
                SET state = ?, result_json = ?, error = ?, owner_token = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE execution_record_id = ?
                  AND namespace = ? AND key = ? AND fingerprint = ?
                  AND owner_token = ? AND state = 'pending'
                """,
                (
                    state,
                    result_json,
                    error,
                    datetime.now(timezone.utc).isoformat(),
                    claim.execution_record_id,
                    claim.namespace,
                    claim.key,
                    claim.fingerprint,
                    claim.owner_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("idempotency ownership was lost before completion")
            connection.commit()

    def _initialize(self) -> None:
        with initialize_sqlite(
            self.path,
            self.timeout_seconds,
            journal_mode=self.journal_mode,
        ) as connection:
            connection.execute("BEGIN IMMEDIATE")
            table_exists = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'idempotency_records'
                """
            ).fetchone()
            if table_exists is None:
                connection.execute(_IDEMPOTENCY_SCHEMA)
            else:
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(idempotency_records)"
                    )
                }
                if not {"execution_record_id", "generation"}.issubset(columns):
                    self._migrate_v06(connection, columns)
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_schema (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    version INTEGER NOT NULL
                )
                """
            )
            schema_version = connection.execute(
                "SELECT version FROM idempotency_schema WHERE singleton = 1"
            ).fetchone()
            if schema_version is not None and schema_version[0] != 2:
                raise RuntimeError(
                    f"unsupported idempotency schema version {schema_version[0]}"
                )
            connection.execute(
                "INSERT OR IGNORE INTO idempotency_schema(singleton, version) VALUES (1, 2)"
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_idempotency_state_updated
                ON idempotency_records(state, updated_at)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_idempotency_key_generation
                ON idempotency_records(namespace, key, generation DESC)
                """
            )
            connection.commit()

    @staticmethod
    def _migrate_v06(connection: sqlite3.Connection, columns: set[str]) -> None:
        reconciliation_tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table'
                  AND name IN (
                      'reconciliation_heads',
                      'reconciliation_prepared_actions'
                  )
                """
            )
        }
        has_prepared_actions = "reconciliation_prepared_actions" in reconciliation_tables
        if has_prepared_actions:
            # SQLite validates trigger references while renaming the legacy
            # authority table. Reinstall the same retention guard after the
            # atomic table swap completes.
            connection.execute(
                "DROP TRIGGER IF EXISTS reconciliation_prepared_actions_delete_guard"
            )
        selected = [
            "namespace",
            "key",
            "fingerprint",
            "state",
            "result_json",
            "error",
            "owner_token",
            "lease_expires_at",
            "updated_at",
        ]
        if "execution_record_id" in columns:
            selected.append("execution_record_id")
        connection.execute(
            _IDEMPOTENCY_SCHEMA.replace(
                "CREATE TABLE idempotency_records",
                "CREATE TABLE idempotency_records_v07",
                1,
            )
        )
        rows = connection.execute(
            f"SELECT {', '.join(selected)} FROM idempotency_records"
        )
        insert_cursor = connection.cursor()
        for row in rows:
            namespace, key, fingerprint, *remaining = row[:9]
            migrated_id = (
                row[9] if len(row) == 10 and row[9] else _new_execution_record_id()
            )
            normalized = _normalize_legacy_idempotency_row(remaining)
            insert_cursor.execute(
                """
                INSERT INTO idempotency_records_v07(
                    execution_record_id, namespace, key, generation, fingerprint,
                    state, result_json, error, owner_token, lease_expires_at,
                    updated_at
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    migrated_id,
                    namespace,
                    key,
                    fingerprint,
                    *normalized,
                ),
            )
        connection.execute("DROP TABLE idempotency_records")
        connection.execute(
            "ALTER TABLE idempotency_records_v07 RENAME TO idempotency_records"
        )
        if reconciliation_tables == {
            "reconciliation_heads",
            "reconciliation_prepared_actions",
        }:
            connection.execute(
                """
                CREATE TRIGGER reconciliation_prepared_actions_delete_guard
                BEFORE DELETE ON reconciliation_prepared_actions
                WHEN EXISTS (
                    SELECT 1 FROM reconciliation_heads
                    WHERE reconciliation_heads.execution_record_id =
                          OLD.execution_record_id
                ) OR EXISTS (
                    SELECT 1 FROM idempotency_records
                    WHERE idempotency_records.execution_record_id =
                          OLD.execution_record_id
                      AND idempotency_records.state != 'completed'
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'prepared reconciliation action cannot be deleted before retention is safe'
                    );
                END
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.path, self.timeout_seconds)

    @classmethod
    def _validate_identifier(cls, label: str, value: str) -> None:
        if not cls._IDENTIFIER.fullmatch(value):
            raise ValueError(
                f"{label} must contain 1-256 URL-safe identifier characters"
            )


def _new_owner_token() -> str:
    import secrets

    return secrets.token_hex(32)


def _new_execution_record_id() -> str:
    import secrets

    return secrets.token_hex(32)


def _normalize_legacy_idempotency_row(
    values: list[Any],
) -> tuple[str, str | None, str | None, str | None, str | None, str]:
    state, result_json, error, owner_token, lease_expires_at, updated_at = values
    allowed = {
        "pending",
        "completed",
        "unknown",
        "manual_review",
        "applied_no_result",
        "not_applied",
    }
    if state not in allowed:
        error = error or f"unrecognized legacy idempotency state {state!r}"
        state = "unknown"

    if state == "pending":
        lease_valid = False
        if owner_token is not None and lease_expires_at is not None:
            try:
                lease_deadline = datetime.fromisoformat(lease_expires_at)
                lease_valid = (
                    lease_deadline.tzinfo is not None
                    and lease_deadline.utcoffset() is not None
                )
            except (TypeError, ValueError):
                lease_valid = False
        if not lease_valid or result_json is not None or error is not None:
            error = error or "legacy pending row has no trustworthy active lease"
            state = "unknown"

    if state != "pending":
        owner_token = None
        lease_expires_at = None

    if state == "completed":
        if result_json is None:
            state = "applied_no_result"
            error = error or "legacy completed row had no stored result"
        else:
            try:
                result_json = canonical_json_bytes(
                    json.loads(result_json), label="legacy idempotency result"
                ).decode("utf-8")
            except (TypeError, ValueError, ContractValidationError):
                state = "applied_no_result"
                result_json = None
                error = error or "legacy completed row had an invalid stored result"

    if state != "completed":
        result_json = None
    else:
        error = None

    return (
        state,
        result_json,
        None if error is None else str(error)[:2048],
        owner_token,
        lease_expires_at,
        updated_at,
    )


def _clone_json(value: Any) -> Any:
    return json.loads(canonical_json_bytes(value, label="idempotency result"))


def _freeze_schema(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_schema(item) for key, item in value.items()}
        )
    if isinstance(value, list | tuple):
        return tuple(_freeze_schema(item) for item in value)
    return value


class GovernedTool(Generic[P, R]):
    def __init__(self, runtime: "Runtime", spec: ToolSpec[P, R]) -> None:
        self.runtime = runtime
        self.spec = spec
        self.__name__ = spec.name
        self.__doc__ = spec.function.__doc__

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R:
        return self.runtime.invoke(self.spec.name, *args, **kwargs)

    async def ainvoke(self, *args: P.args, **kwargs: P.kwargs) -> R:
        return await self.runtime.ainvoke(self.spec.name, *args, **kwargs)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec[Any, Any]] = {}
        self._sealed = False
        self._lock = Lock()

    def register(self, spec: ToolSpec[Any, Any]) -> None:
        with self._lock:
            if self._sealed:
                raise RegistryError("tool registry is sealed")
            if spec.name in self._tools:
                raise RegistryError(f"tool {spec.name!r} is already registered")
            self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec[Any, Any]:
        with self._lock:
            try:
                return self._tools[name]
            except KeyError as exc:
                raise RegistryError(f"unknown tool {name!r}") from exc

    def list(self) -> tuple[ToolSpec[Any, Any], ...]:
        with self._lock:
            return tuple(self._tools.values())

    @property
    def is_sealed(self) -> bool:
        with self._lock:
            return self._sealed

    def seal(self) -> None:
        with self._lock:
            self._sealed = True

    def _seal_with(
        self, validator: Callable[[tuple[ToolSpec[Any, Any], ...]], T]
    ) -> T:
        with self._lock:
            if self._sealed:
                raise RegistryError("tool registry is already sealed")
            result = validator(tuple(self._tools.values()))
            self._sealed = True
            return result
