"""Regression coverage for release and optional-dependency metadata."""

from pathlib import Path

from agent_runtime_governance import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_release_version_and_security_fixed_evidence_constraint_are_in_sync() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert f'version = "{__version__}"' in pyproject
    assert pyproject.count('"cryptography>=46,<51"') == 2
    assert '"cryptography>=46,<50"' not in pyproject
