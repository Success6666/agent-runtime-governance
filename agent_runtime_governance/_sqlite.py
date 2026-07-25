from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from filelock import FileLock


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args: object) -> bool:
        try:
            return bool(super().__exit__(*args))
        finally:
            self.close()


def connect_sqlite(path: str | Path, timeout_seconds: float) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        timeout=timeout_seconds,
        isolation_level=None,
        factory=_ClosingConnection,
    )
    connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1000)}")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


@contextmanager
def initialize_sqlite(
    path: str | Path, timeout_seconds: float
) -> Iterator[sqlite3.Connection]:
    lock = FileLock(f"{path}.initialize.lock", timeout=timeout_seconds)
    with lock:
        with connect_sqlite(path, timeout_seconds) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
