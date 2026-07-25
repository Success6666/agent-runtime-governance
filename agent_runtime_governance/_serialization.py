from __future__ import annotations

import json
from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Any


def freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _validate_mapping_keys(value)
    return MappingProxyType({key: freeze(item) for key, item in value.items()})


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return freeze_mapping(value)
    if isinstance(value, list | tuple):
        return tuple(freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        _validate_mapping_keys(value)
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [thaw(item) for item in value]
    if isinstance(value, set | frozenset):
        items = [thaw(item) for item in value]
        try:
            return sorted(items)
        except TypeError:
            return sorted(items, key=_deterministic_sort_key)
    return json_safe(value)


def json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return json_safe(value.value)
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping | list | tuple | set | frozenset):
        return thaw(value)
    return f"[UNSERIALIZABLE:{type(value).__module__}.{type(value).__qualname__}]"


def _validate_mapping_keys(value: Mapping[Any, Any]) -> None:
    if any(not isinstance(key, str) for key in value):
        raise TypeError("mapping keys must be strings")


def _deterministic_sort_key(value: Any) -> tuple[str, str, str]:
    safe = json_safe(value)
    return (
        type(value).__module__,
        type(value).__qualname__,
        json.dumps(
            safe,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ),
    )
