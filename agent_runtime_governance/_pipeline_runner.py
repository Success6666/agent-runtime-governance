"""Compatibility re-export for private pipeline services."""

from ._internal.runtime import pipeline_runner as _implementation
from ._internal.runtime.pipeline_runner import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
