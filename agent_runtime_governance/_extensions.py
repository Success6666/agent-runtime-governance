"""Compatibility re-export for private extension-dispatch helpers."""

from ._internal.runtime import extensions as _implementation
from ._internal.runtime.extensions import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
