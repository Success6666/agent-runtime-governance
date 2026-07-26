from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def metadata_text(metadata: Mapping[str, Any], key: str) -> str | None:
    """Return a metadata value as text without treating missing values as text."""
    value = metadata.get(key)
    return None if value is None else str(value)
