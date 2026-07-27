from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from filelock import FileLock


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args: object) -> bool:
        try:
            return bool(super().__exit__(*args))
        finally:
            self.close()


class SQLiteJournalModeError(RuntimeError):
    """Raised when WAL is required on a SQLite runtime with the reset-race bug."""


@dataclass(frozen=True, slots=True)
class SQLiteJournalCapabilities:
    sqlite_version: tuple[int, int, int]
    wal_safe: bool
    requested_mode: str
    selected_mode: str
    synchronous_level: int = 2


def sqlite_wal_is_safe(
    version: tuple[int, int, int] | None = None,
) -> bool:
    """Return whether the runtime contains an official WAL-reset race fix."""
    selected = sqlite3.sqlite_version_info if version is None else version
    if len(selected) != 3 or any(
        type(item) is not int or item < 0 for item in selected
    ):
        return False
    if selected >= (3, 51, 3):
        return True
    if (3, 50, 7) <= selected < (3, 51, 0):
        return True
    return (3, 44, 6) <= selected < (3, 45, 0)


def sqlite_journal_capabilities(
    requested_mode: str = "auto",
    *,
    version: tuple[int, int, int] | None = None,
) -> SQLiteJournalCapabilities:
    """Resolve a requested journal policy against the linked SQLite runtime."""
    if type(requested_mode) is not str:
        raise TypeError("requested_mode must be a string")
    requested = requested_mode.lower()
    if requested not in {"auto", "wal", "delete"}:
        raise ValueError("requested_mode must be 'auto', 'wal', or 'delete'")
    selected_version = sqlite3.sqlite_version_info if version is None else version
    safe = sqlite_wal_is_safe(selected_version)
    if requested == "wal" and not safe:
        rendered = ".".join(str(item) for item in selected_version)
        raise SQLiteJournalModeError(
            f"SQLite {rendered} is not approved for WAL because of the WAL-reset race"
        )
    selected_mode = (
        "wal" if requested == "wal" or (requested == "auto" and safe) else "delete"
    )
    return SQLiteJournalCapabilities(
        sqlite_version=selected_version,
        wal_safe=safe,
        requested_mode=requested,
        selected_mode=selected_mode,
        synchronous_level=2,
    )


def connect_sqlite(path: str | Path, timeout_seconds: float) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        timeout=timeout_seconds,
        isolation_level=None,
        factory=_ClosingConnection,
    )
    connection.execute("PRAGMA foreign_keys=ON")
    if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        connection.close()
        raise SQLiteJournalModeError("SQLite foreign-key enforcement is unavailable")
    connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1000)}")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


@contextmanager
def initialize_sqlite(
    path: str | Path,
    timeout_seconds: float,
    *,
    journal_mode: str = "auto",
) -> Iterator[sqlite3.Connection]:
    capabilities = sqlite_journal_capabilities(journal_mode)
    lock = FileLock(f"{path}.initialize.lock", timeout=timeout_seconds)
    with lock:
        with connect_sqlite(path, timeout_seconds) as connection:
            actual_mode = str(
                connection.execute(
                    f"PRAGMA journal_mode={capabilities.selected_mode.upper()}"
                ).fetchone()[0]
            ).lower()
            if actual_mode != capabilities.selected_mode:
                raise SQLiteJournalModeError(
                    f"SQLite selected journal mode {actual_mode!r}, expected "
                    f"{capabilities.selected_mode!r}"
                )
            connection.execute("PRAGMA synchronous=FULL")
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
            if synchronous != capabilities.synchronous_level:
                raise SQLiteJournalModeError(
                    f"SQLite synchronous level is {synchronous}, expected FULL (2)"
                )
            yield connection
