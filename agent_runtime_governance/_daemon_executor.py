"""Compatibility re-export for the private daemon executor."""

from ._internal.runtime import daemon_executor as _implementation
from ._internal.runtime.daemon_executor import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
