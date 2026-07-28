"""Compatibility re-export for private immutable-value helpers."""

from ._internal.serialization import values as _implementation
from ._internal.serialization.values import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
