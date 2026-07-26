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
from .errors import RegistryError

if TYPE_CHECKING:
    from .runtime import Runtime

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


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

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}", self.name):
            raise ValueError("tool name must be a 1-128 character stable identifier")
        if not callable(self.function):
            raise TypeError("tool function must be callable")
        if self.action_contract is not None and not isinstance(
            self.action_contract, ActionContract
        ):
            raise TypeError("action_contract must be an ActionContract")
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


class IdempotencyConflictError(RuntimeError):
    """Raised when a key is reused for a different tool request."""


class IdempotencyOutcomeUnknownError(RuntimeError):
    """Raised when the original execution may still have taken effect."""


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


class InMemoryIdempotencyStore:
    """Thread-safe process-local coordination with a bounded terminal cache.

    Completed and unknown outcomes are retained with idle-TTL and LRU bounds.
    In-flight claims are never evicted. Use :class:`SQLiteIdempotencyStore` when
    outcomes must survive process restarts or cache eviction.
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
                entry = _IdempotencyEntry(fingerprint, Future())
                self._entries[storage_key] = entry
                return IdempotencyClaim(namespace, key, fingerprint, True, entry.future)
            if entry.fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    "idempotency key was already used with different parameters"
                )
            if entry.future.done():
                self._remember_completed(storage_key, monotonic())
            return IdempotencyClaim(namespace, key, fingerprint, False, entry.future)

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
                claim.future.set_exception(IdempotencyOutcomeUnknownError(str(error)))
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
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lease_seconds = lease_seconds
        self.timeout_seconds = timeout_seconds
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
                SELECT fingerprint, state, result_json, error, lease_expires_at
                FROM idempotency_records WHERE namespace = ? AND key = ?
                """,
                (namespace, key),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO idempotency_records(
                        namespace, key, fingerprint, state, owner_token,
                        lease_expires_at, updated_at
                    ) VALUES (?, ?, ?, 'pending', ?, ?, ?)
                    """,
                    (
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
                )
            recorded_fingerprint, state, result_json, error, lease_value = row
            if recorded_fingerprint != fingerprint:
                raise IdempotencyConflictError(
                    "idempotency key was already used with different parameters"
                )
            future: Future[Any] = Future()
            if state == "completed":
                future.set_result(json.loads(result_json))
            elif state == "unknown":
                future.set_exception(
                    IdempotencyOutcomeUnknownError(error or "outcome is unknown")
                )
            elif state == "pending":
                lease_deadline = datetime.fromisoformat(lease_value)
                if lease_deadline <= now:
                    message = "owner lease expired before an outcome was recorded"
                    connection.execute(
                        """
                        UPDATE idempotency_records
                        SET state = 'unknown', error = ?, owner_token = NULL,
                            lease_expires_at = NULL, updated_at = ?
                        WHERE namespace = ? AND key = ? AND state = 'pending'
                        """,
                        (message, now.isoformat(), namespace, key),
                    )
                    future.set_exception(IdempotencyOutcomeUnknownError(message))
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
            return IdempotencyClaim(namespace, key, fingerprint, False, future)

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
                WHERE namespace = ? AND key = ? AND fingerprint = ?
                  AND owner_token = ? AND state = 'pending'
                """,
                (claim.namespace, claim.key, claim.fingerprint, claim.owner_token),
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
            claim.future.set_exception(IdempotencyOutcomeUnknownError(str(error)))
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
                WHERE namespace = ? AND key = ? AND fingerprint = ?
                  AND owner_token = ? AND state = 'pending'
                """,
                (
                    lease_expires_at.isoformat(),
                    now.isoformat(),
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
            cursor = connection.execute(
                """
                DELETE FROM idempotency_records
                WHERE state = 'completed' AND updated_at < ?
                """,
                (older_than.astimezone(timezone.utc).isoformat(),),
            )
            connection.commit()
            return cursor.rowcount

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
                WHERE namespace = ? AND key = ? AND fingerprint = ?
                  AND owner_token = ? AND state = 'pending'
                """,
                (
                    state,
                    result_json,
                    error,
                    datetime.now(timezone.utc).isoformat(),
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
        with initialize_sqlite(self.path, self.timeout_seconds) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    namespace TEXT NOT NULL,
                    key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'completed', 'unknown')),
                    result_json TEXT,
                    error TEXT,
                    owner_token TEXT,
                    lease_expires_at TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(namespace, key),
                    CHECK(
                        (state = 'pending' AND owner_token IS NOT NULL AND lease_expires_at IS NOT NULL)
                        OR (state != 'pending' AND owner_token IS NULL AND lease_expires_at IS NULL)
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_idempotency_state_updated
                ON idempotency_records(state, updated_at)
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
