"""Compatibility re-export for private runtime context-boundary helpers."""

from ._internal.runtime import context_boundaries as _implementation
from ._internal.runtime.context_boundaries import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
