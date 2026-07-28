"""Compatibility re-export for private Ed25519 bindings."""

from ._internal.evidence import ed25519 as _implementation
from ._internal.evidence.ed25519 import *  # noqa: F401, F403


def __getattr__(name: str) -> object:
    return getattr(_implementation, name)
