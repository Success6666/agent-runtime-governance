"""Compatibility re-export for private canonical-codec helpers."""

from ._internal.serialization import canonical as _implementation
from ._internal.serialization.canonical import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
