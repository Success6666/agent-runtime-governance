"""Compatibility re-export for private audit redaction helpers."""

from ._internal.audit import redaction as _implementation
from ._internal.audit.redaction import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
