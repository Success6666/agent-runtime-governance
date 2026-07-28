"""Compatibility re-export for private runtime metadata helpers."""

from ._internal.runtime import metadata as _implementation
from ._internal.runtime.metadata import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
