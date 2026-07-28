from __future__ import annotations

import ast
import importlib
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "agent_runtime_governance"
_LEGACY_PRIVATE_MODULES = {
    "_blocking": (
        "agent_runtime_governance._internal.runtime.blocking",
        "run_blocking",
    ),
    "_canonical": (
        "agent_runtime_governance._internal.serialization.canonical",
        "rfc8785_json_bytes",
    ),
    "_context_boundaries": (
        "agent_runtime_governance._internal.runtime.context_boundaries",
        "validate_middleware_transition",
    ),
    "_daemon_executor": (
        "agent_runtime_governance._internal.runtime.daemon_executor",
        "DaemonThreadPoolExecutor",
    ),
    "_evidence_ed25519": (
        "agent_runtime_governance._internal.evidence.ed25519",
        "sign",
    ),
    "_extensions": (
        "agent_runtime_governance._internal.runtime.extensions",
        "ExtensionDispatchSnapshot",
    ),
    "_metadata": (
        "agent_runtime_governance._internal.runtime.metadata",
        "metadata_text",
    ),
    "_pipeline_runner": (
        "agent_runtime_governance._internal.runtime.pipeline_runner",
        "PipelineRunner",
    ),
    "_redaction": (
        "agent_runtime_governance._internal.audit.redaction",
        "redact_sensitive_data",
    ),
    "_serialization": (
        "agent_runtime_governance._internal.serialization.values",
        "freeze_mapping",
    ),
}
_INTERNAL_MODULES = tuple(
    implementation for implementation, _ in _LEGACY_PRIVATE_MODULES.values()
)
_LEGACY_PRIVATE_MODULE_NAMES = frozenset(_LEGACY_PRIVATE_MODULES) | frozenset(
    f"agent_runtime_governance.{module}" for module in _LEGACY_PRIVATE_MODULES
)


def test_private_services_are_grouped_under_explicit_internal_domains() -> None:
    for module_name in _INTERNAL_MODULES:
        assert importlib.import_module(module_name).__name__ == module_name

    for legacy_name, (implementation_name, representative_name) in (
        _LEGACY_PRIVATE_MODULES.items()
    ):
        assert (_PACKAGE_ROOT / f"{legacy_name}.py").is_file()
        legacy_module = importlib.import_module(
            f"agent_runtime_governance.{legacy_name}"
        )
        implementation_module = importlib.import_module(implementation_name)
        assert getattr(legacy_module, representative_name) is getattr(
            implementation_module,
            representative_name,
        )
        for private_name in (
            name
            for name in vars(implementation_module)
            if name.startswith("_") and not name.startswith("__")
        ):
            assert getattr(legacy_module, private_name) is getattr(
                implementation_module,
                private_name,
            )


def test_internal_runtime_services_do_not_import_the_runtime_facade() -> None:
    runtime_root = _PACKAGE_ROOT / "_internal" / "runtime"
    for source_path in runtime_root.glob("*.py"):
        module = ast.parse(source_path.read_text(encoding="utf-8"))
        facade_imports = [node for node in ast.walk(module) if _is_runtime_facade(node)]
        assert not facade_imports, source_path.name


def test_package_sources_do_not_import_the_moved_private_modules() -> None:
    for source_path in _PACKAGE_ROOT.rglob("*.py"):
        module = ast.parse(source_path.read_text(encoding="utf-8"))
        legacy_imports = [
            node
            for node in ast.walk(module)
            if _is_legacy_private_import(node, source_path)
        ]
        assert not legacy_imports, source_path.relative_to(_PACKAGE_ROOT)


def _is_runtime_facade(node: ast.AST) -> bool:
    if isinstance(node, ast.Import):
        return any(alias.name == "agent_runtime_governance.runtime" for alias in node.names)
    if not isinstance(node, ast.ImportFrom):
        return False
    if node.module == "agent_runtime_governance.runtime":
        return True
    if node.module == "agent_runtime_governance":
        return any(alias.name == "runtime" for alias in node.names)
    return node.level == 3 and (
        node.module == "runtime"
        or (node.module is None and any(alias.name == "runtime" for alias in node.names))
    )


def test_legacy_private_import_detection_catches_package_and_relative_forms() -> None:
    package_import = ast.parse("from agent_runtime_governance import _blocking").body[0]
    assert _is_legacy_private_import(package_import, _PACKAGE_ROOT / "runtime.py")

    root_relative_import = ast.parse("from . import _blocking").body[0]
    assert _is_legacy_private_import(root_relative_import, _PACKAGE_ROOT / "runtime.py")

    root_package_relative_import = ast.parse("from . import _blocking").body[0]
    assert _is_legacy_private_import(
        root_package_relative_import,
        _PACKAGE_ROOT / "__init__.py",
    )

    nested_relative_import = ast.parse("from .. import _blocking").body[0]
    assert _is_legacy_private_import(
        nested_relative_import,
        _PACKAGE_ROOT / "middleware" / "audit.py",
    )

    nested_package_relative_import = ast.parse("from .. import _blocking").body[0]
    assert _is_legacy_private_import(
        nested_package_relative_import,
        _PACKAGE_ROOT / "middleware" / "__init__.py",
    )

    non_legacy_relative_import = ast.parse("from . import _blocking").body[0]
    assert not _is_legacy_private_import(
        non_legacy_relative_import,
        _PACKAGE_ROOT / "middleware" / "audit.py",
    )


def _is_legacy_private_import(node: ast.AST, source_path: Path) -> bool:
    if isinstance(node, ast.Import):
        return any(alias.name in _LEGACY_PRIVATE_MODULE_NAMES for alias in node.names)
    if not isinstance(node, ast.ImportFrom):
        return False
    if node.module in _LEGACY_PRIVATE_MODULE_NAMES:
        return True
    if node.module == "agent_runtime_governance":
        return any(alias.name in _LEGACY_PRIVATE_MODULES for alias in node.names)
    if node.level == 0:
        return False

    package_parts = [
        "agent_runtime_governance",
        *source_path.relative_to(_PACKAGE_ROOT).parent.parts,
    ]
    parent_parts = package_parts[: len(package_parts) - node.level + 1]
    if node.module is not None:
        parent_parts.extend(node.module.split("."))
    return any(
        ".".join((*parent_parts, alias.name)) in _LEGACY_PRIVATE_MODULE_NAMES
        for alias in node.names
    )
