from __future__ import annotations

import inspect
import json
import math
from collections.abc import Mapping
from enum import Enum
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .errors import ContractValidationError, RegistryError


def validate_schema(schema: Mapping[str, Any], *, label: str) -> None:
    """Validate a tool contract at registration time."""
    try:
        Draft202012Validator.check_schema(dict(schema))
    except SchemaError as exc:
        raise RegistryError(f"invalid {label} JSON Schema: {exc.message}") from exc


def bind_arguments(
    function: Callable[..., Any], args: tuple[Any, ...], kwargs: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind a call to stable parameter names before governance and hashing."""
    try:
        bound = inspect.signature(function).bind(*args, **dict(kwargs))
    except TypeError as exc:
        raise ContractValidationError("parameters", str(exc)) from exc
    bound.apply_defaults()
    return {name: value for name, value in bound.arguments.items()}


def materialize_call(
    function: Callable[..., Any], parameters: Mapping[str, Any]
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Rebuild a call from the exact parameter snapshot used by governance."""
    positional: list[Any] = []
    keyword: dict[str, Any] = {}
    for name, parameter in inspect.signature(function).parameters.items():
        if name not in parameters:
            continue
        value = parameters[name]
        if parameter.kind in {
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }:
            positional.append(value)
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            positional.extend(value)
        elif parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            keyword[name] = value
        elif parameter.kind is inspect.Parameter.VAR_KEYWORD:
            keyword.update(value)
    return tuple(positional), keyword


def validate_instance(
    value: Any, schema: Mapping[str, Any] | None, *, label: str
) -> Any:
    """Normalize a JSON-compatible value and evaluate its Draft 2020-12 contract."""
    normalized = normalize_json(value, path=label)
    if schema is None:
        return normalized
    validator = Draft202012Validator(dict(schema))
    errors = sorted(validator.iter_errors(normalized), key=_error_sort_key)
    if errors:
        raise ContractValidationError(label, _format_validation_error(errors[0]))
    return normalized


def canonical_json_bytes(value: Any, *, label: str) -> bytes:
    normalized = normalize_json(value, path=label)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def normalize_json(value: Any, *, path: str = "$", depth: int = 0) -> Any:
    """Return deterministic JSON data without invoking arbitrary object repr hooks."""
    if depth > 100:
        raise ContractValidationError(path, "maximum nesting depth exceeded")
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractValidationError(path, "non-finite numbers are not valid JSON")
        return value
    if isinstance(value, Enum):
        return normalize_json(value.value, path=path, depth=depth + 1)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractValidationError(path, "object keys must be strings")
            result[key] = normalize_json(
                item, path=f"{path}.{key}", depth=depth + 1
            )
        return result
    if isinstance(value, list | tuple):
        return [
            normalize_json(item, path=f"{path}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        ]
    raise ContractValidationError(
        path,
        f"unsupported value type {type(value).__module__}.{type(value).__qualname__}",
    )


def _error_sort_key(error: ValidationError) -> tuple[str, str]:
    return ("/".join(str(item) for item in error.absolute_path), error.message)


def _format_validation_error(error: ValidationError) -> str:
    path = "/".join(str(item) for item in error.absolute_path) or "$"
    return f"{path}: {error.message}"
