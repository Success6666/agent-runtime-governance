from __future__ import annotations

import dataclasses
import enum
import importlib
import inspect
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_FIXTURE = Path(__file__).parent / "fixtures" / "v0.7" / "public-api.json"
_ROOT = Path(__file__).resolve().parents[1]
_PROVENANCE = {
    "source_tag": "v0.7.0",
    "source_commit": "3998c975f88737c9e009b9d85c073122431ddb94",
    "source_file": "agent_runtime_governance/__init__.py",
}
_SNAPSHOT_COUNTS = {
    "root_exports": 156,
    "stable_submodule_imports": 152,
    "signatures": 140,
    "method_signatures": 244,
}
_POSITIONAL_KINDS = {"POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD"}


def _describe_annotation(annotation: object) -> dict[str, object]:
    if annotation is inspect.Signature.empty:
        return {"kind": "empty"}
    if annotation is None:
        return {"kind": "none"}
    if isinstance(annotation, str):
        return {"kind": "string", "value": annotation}
    return {
        "kind": "object",
        "module": type(annotation).__module__,
        "qualname": type(annotation).__qualname__,
        "value": repr(annotation),
    }


def _describe_default(value: object) -> dict[str, object]:
    value_type = type(value)
    if value_type.__module__ == "dataclasses" and value_type.__qualname__ == (
        "_HAS_DEFAULT_FACTORY_CLASS"
    ):
        return {"kind": "dataclass-default-factory"}
    if isinstance(value, enum.Enum):
        return {
            "kind": "enum",
            "module": value_type.__module__,
            "qualname": value_type.__qualname__,
            "name": value.name,
        }
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            "kind": "dataclass",
            "module": value_type.__module__,
            "qualname": value_type.__qualname__,
            "fields": {
                field.name: _describe_default(getattr(value, field.name))
                for field in dataclasses.fields(value)
            },
        }
    if isinstance(value, frozenset):
        items = [_describe_default(item) for item in value]
        return {
            "kind": "frozenset",
            "items": sorted(items, key=_canonical_json),
        }
    if isinstance(value, tuple):
        return {"kind": "tuple", "items": [_describe_default(item) for item in value]}
    if value is None or isinstance(value, (bool, float, int, str)):
        return {"kind": "literal", "type": value_type.__name__, "value": value}
    return {
        "kind": "repr",
        "module": value_type.__module__,
        "qualname": value_type.__qualname__,
        "value": repr(value),
    }


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _describe_signature(target: object) -> dict[str, object]:
    signature = inspect.signature(target)
    return {
        "parameters": [
            {
                "name": parameter.name,
                "kind": parameter.kind.name,
                "annotation": _describe_annotation(parameter.annotation),
                "default": (
                    {"kind": "empty"}
                    if parameter.default is inspect.Parameter.empty
                    else _describe_default(parameter.default)
                ),
            }
            for parameter in signature.parameters.values()
        ],
        "return_annotation": _describe_annotation(signature.return_annotation),
    }


def _describe_object(target: object) -> dict[str, str]:
    if inspect.isclass(target):
        kind = "class"
    elif inspect.isfunction(target):
        kind = "function"
    else:
        kind = type(target).__name__
    return {
        "kind": kind,
        "module": getattr(target, "__module__", type(target).__module__),
        "qualname": getattr(target, "__qualname__", type(target).__qualname__),
    }


def _resolve(module_name: str, qualname: str) -> object:
    target: object = importlib.import_module(module_name)
    for part in qualname.split("."):
        target = getattr(target, part)
    return target


def _descriptor_kind(descriptor: object) -> str:
    if isinstance(descriptor, classmethod):
        return "classmethod"
    if isinstance(descriptor, staticmethod):
        return "staticmethod"
    return "method"


def _load_snapshot() -> dict[str, Any]:
    snapshot = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert snapshot["schema_version"] == 1
    assert snapshot["provenance"] == _PROVENANCE
    assert {name: len(snapshot[name]) for name in _SNAPSHOT_COUNTS} == _SNAPSHOT_COUNTS
    return snapshot


def _assert_object(target: object, expected: dict[str, str], path: str) -> None:
    assert _describe_object(target) == expected, path
    canonical = _resolve(expected["module"], expected["qualname"])
    assert target is canonical, path


def _assert_backward_compatible_call_signature(
    actual: dict[str, object], expected: dict[str, object], path: str
) -> None:
    """Keep every v0.7 call form valid while allowing new optional v0.8 inputs.

    Annotations stay recorded in the fixture as source evidence. They are not
    part of Python argument binding, and the async extension boundary widens
    some protocol annotations without invalidating a v0.7 call form.
    """

    expected_parameters = expected["parameters"]
    actual_parameters = actual["parameters"]
    assert isinstance(expected_parameters, list)
    assert isinstance(actual_parameters, list)

    actual_by_name = {
        parameter["name"]: (index, parameter)
        for index, parameter in enumerate(actual_parameters)
    }
    expected_indices: list[int] = []
    for parameter in expected_parameters:
        name = parameter["name"]
        assert name in actual_by_name, f"{path}: missing parameter {name}"
        index, current = actual_by_name[name]
        expected_indices.append(index)
        assert current["kind"] == parameter["kind"], (
            f"{path}: parameter kind for {name}"
        )
        assert current["default"] == parameter["default"], f"{path}: default for {name}"

    assert expected_indices == sorted(expected_indices), f"{path}: parameter order"
    expected_names = {parameter["name"] for parameter in expected_parameters}
    last_historical_positional = max(
        (
            index
            for index, parameter in enumerate(actual_parameters)
            if parameter["name"] in expected_names
            and parameter["kind"] in _POSITIONAL_KINDS
        ),
        default=-1,
    )
    for index, parameter in enumerate(actual_parameters):
        if parameter["name"] in expected_names:
            continue
        assert parameter["default"]["kind"] != "empty", (
            f"{path}: new parameter {parameter['name']} must be optional"
        )
        assert parameter["kind"] in _POSITIONAL_KINDS | {"KEYWORD_ONLY"}, (
            f"{path}: unsupported new parameter kind {parameter['kind']}"
        )
        if parameter["kind"] in _POSITIONAL_KINDS:
            assert index > last_historical_positional, (
                f"{path}: new positional parameter {parameter['name']} shifts v0.7 calls"
            )


def test_v070_root_exports_remain_importable_and_identical() -> None:
    snapshot = _load_snapshot()
    api = importlib.import_module("agent_runtime_governance")
    expected_names = {entry["name"] for entry in snapshot["root_exports"]}

    assert expected_names <= set(api.__all__)
    for entry in snapshot["root_exports"]:
        name = entry["name"]
        _assert_object(getattr(api, name), entry["object"], f"root export {name}")


def test_v070_stable_submodule_imports_remain_equivalent_to_root_exports() -> None:
    snapshot = _load_snapshot()
    api = importlib.import_module("agent_runtime_governance")

    for entry in snapshot["stable_submodule_imports"]:
        target = getattr(
            importlib.import_module(entry["import_module"]), entry["import_name"]
        )
        _assert_object(
            target,
            entry["object"],
            f"{entry['import_module']}.{entry['import_name']}",
        )
        assert target is getattr(api, entry["root_name"])


def test_v070_public_call_signatures_remain_compatible() -> None:
    snapshot = _load_snapshot()
    api = importlib.import_module("agent_runtime_governance")

    for entry in snapshot["signatures"]:
        target = getattr(api, entry["root_name"])
        if inspect.isclass(target) and issubclass(target, enum.Enum):
            # EnumType's constructor signature differs across supported CPython versions.
            continue
        actual = _describe_signature(target)
        _assert_backward_compatible_call_signature(
            actual, entry["signature"], entry["root_name"]
        )

    for entry in snapshot["method_signatures"]:
        target = _resolve(entry["class_module"], entry["class_qualname"])
        descriptor = vars(target)[entry["method_name"]]
        assert _descriptor_kind(descriptor) == entry["descriptor_kind"]
        actual = _describe_signature(getattr(target, entry["method_name"]))
        _assert_backward_compatible_call_signature(
            actual,
            entry["signature"],
            (
                f"{entry['class_module']}.{entry['class_qualname']}."
                f"{entry['method_name']}"
            ),
        )


def _run(command: list[str], *, cwd: Path) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, (
        f"command failed: {' '.join(command)}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )


def _probe_script(snapshot_path: Path, target: Path) -> str:
    return "\n".join(
        [
            "import importlib",
            "import json",
            "import pathlib",
            "import sys",
            f"sys.path.insert(0, {str(target)!r})",
            f"installed_root = pathlib.Path({str(target)!r}).resolve()",
            f"snapshot = json.loads(pathlib.Path({str(snapshot_path)!r}).read_text(encoding='utf-8'))",
            "api = importlib.import_module('agent_runtime_governance')",
            "assert pathlib.Path(api.__file__).resolve().is_relative_to(installed_root), api.__file__",
            "assert {entry['name'] for entry in snapshot['root_exports']} <= set(api.__all__)",
            "for entry in snapshot['root_exports']:",
            "    target = getattr(api, entry['name'])",
            "    expected = entry['object']",
            "    actual = {'kind': 'class' if isinstance(target, type) else 'function' if callable(target) else type(target).__name__, 'module': getattr(target, '__module__', type(target).__module__), 'qualname': getattr(target, '__qualname__', type(target).__qualname__)}",
            "    assert actual == expected, entry['name']",
            "for entry in snapshot['stable_submodule_imports']:",
            "    module = importlib.import_module(entry['import_module'])",
            "    assert getattr(module, entry['import_name']) is getattr(api, entry['root_name'])",
        ]
    )


def test_v070_wheel_and_sdist_expose_stable_imports(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--outdir",
            str(dist),
        ],
        cwd=_ROOT,
    )

    wheels = list(dist.glob("*.whl"))
    sdists = list(dist.glob("*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    artifacts = [*wheels, *sdists]
    for artifact in artifacts:
        target = tmp_path / artifact.name.replace(".", "_")
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--target",
                str(target),
                str(artifact),
            ],
            cwd=tmp_path,
        )
        _run(
            [sys.executable, "-I", "-c", _probe_script(_FIXTURE, target)],
            cwd=tmp_path,
        )
