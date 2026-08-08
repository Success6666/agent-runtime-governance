"""Regression coverage for release and optional-dependency metadata."""

import re
from pathlib import Path

from agent_runtime_governance import __version__

ROOT = Path(__file__).resolve().parents[1]


def _optional_dependency(pyproject: str, extra: str) -> tuple[str, ...]:
    section = re.search(
        r"(?ms)^\[project\.optional-dependencies\]\s*$\n(?P<body>.*?)(?=^\[|\Z)",
        pyproject,
    )
    assert section is not None
    value = re.search(
        rf"(?ms)^{re.escape(extra)}\s*=\s*\[(?P<body>.*?)\]\s*$",
        section.group("body"),
    )
    assert value is not None
    return tuple(re.findall(r'"([^"]+)"', value.group("body")))


def test_release_version_and_security_fixed_evidence_constraint_are_in_sync() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dev_dependencies = _optional_dependency(pyproject, "dev")
    evidence_dependencies = _optional_dependency(pyproject, "evidence")

    assert f'version = "{__version__}"' in pyproject
    assert "cryptography>=46,<51" in dev_dependencies
    assert evidence_dependencies == ("cryptography>=46,<51",)
    assert all("cryptography>=46,<50" not in dependency for dependency in dev_dependencies)
    assert all(
        "cryptography>=46,<50" not in dependency
        for dependency in evidence_dependencies
    )
