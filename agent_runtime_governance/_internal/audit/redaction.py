"""Private, dependency-neutral redaction compatibility primitives."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from fnmatch import fnmatchcase
from typing import Any

from ..serialization.values import json_safe as _json_safe

DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "authorization",
        "cookie",
        "identity_claims",
        "signature",
    }
)
DEFAULT_SENSITIVE_PATHS = frozenset(
    {
        "reason",
        "context.input_text",
        "context.result",
        "context.error",
        "context.tool_call.args.*",
        "context.tool_call.kwargs.*",
        "context.decision.reason",
        "context.history.*.reason",
    }
)
_REDACTED = "[REDACTED]"


def redact_sensitive_data(
    value: Any,
    *,
    sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
    sensitive_paths: Iterable[str] = DEFAULT_SENSITIVE_PATHS,
    value_patterns: Iterable[str | re.Pattern[str]] = (),
    allow_paths: Iterable[str] = (),
) -> Any:
    """Return a JSON-safe copy with configured secrets removed."""

    patterns = tuple(
        re.compile(pattern) if isinstance(pattern, str) else pattern
        for pattern in value_patterns
    )
    return _redact(
        _safe_json_value(value),
        frozenset(str(key).lower() for key in sensitive_keys),
        frozenset(str(path) for path in sensitive_paths),
        patterns,
        frozenset(str(path) for path in allow_paths),
    )


def _redact(
    value: Any,
    sensitive_keys: frozenset[str],
    sensitive_paths: frozenset[str],
    value_patterns: tuple[re.Pattern[str], ...],
    allow_paths: frozenset[str],
    *,
    path: str = "",
) -> Any:
    if path and _matches_path(path, allow_paths):
        return value
    if path and _matches_path(path, sensitive_paths):
        return _REDACTED
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            result[str(key)] = (
                _REDACTED
                if normalized in sensitive_keys and not _matches_path(child_path, allow_paths)
                else _redact(
                    item,
                    sensitive_keys,
                    sensitive_paths,
                    value_patterns,
                    allow_paths,
                    path=child_path,
                )
            )
        return result
    if isinstance(value, list | tuple):
        return [
            _redact(
                item,
                sensitive_keys,
                sensitive_paths,
                value_patterns,
                allow_paths,
                path=f"{path}.{index}" if path else str(index),
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        for pattern in value_patterns:
            value = pattern.sub(_REDACTED, value)
        return value
    return value


def _matches_path(path: str, patterns: frozenset[str]) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def _safe_json_value(value: Any) -> Any:
    if isinstance(value, float):
        return _json_safe(value)
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, Mapping):
        return {str(key): _safe_json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_safe_json_value(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted((_safe_json_value(item) for item in value), key=str)
    return f"[UNSERIALIZABLE:{type(value).__name__}]"
