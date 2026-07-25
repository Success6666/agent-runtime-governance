from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Any


def freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({str(key): freeze(item) for key, item in value.items()})


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
        return {str(key): thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [thaw(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted(thaw(item) for item in value)
    return json_safe(value)


def json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return json_safe(value.value)
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping | list | tuple | set | frozenset):
        return thaw(value)
    return f"[UNSERIALIZABLE:{type(value).__module__}.{type(value).__qualname__}]"
