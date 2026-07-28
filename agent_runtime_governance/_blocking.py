"""Compatibility re-export for private runtime blocking helpers."""

from ._internal.runtime import blocking as _implementation
from ._internal.runtime.blocking import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
