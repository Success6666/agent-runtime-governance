"""Regression coverage for the release verification manifest tool and gates."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest

from agent_runtime_governance import __version__

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "release_manifest.py"
SOURCE_COMMIT = "a" * 40
SERVICE_IMAGES = {
    "opa": "openpolicyagent/opa@sha256:" + "1" * 64,
    "otel": "otel/opentelemetry-collector-contrib@sha256:" + "2" * 64,
}
V070_PACKAGE_VERSION = "0.7.0"
V070_RELEASE_TAG = f"v{V070_PACKAGE_VERSION}"
CURRENT_RELEASE_TAG = f"v{__version__}"


def _load_release_manifest() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release_manifest_test_module",
        SCRIPT_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def release_manifest() -> ModuleType:
    return _load_release_manifest()


def _write_release_inputs(
    root: Path,
    *,
    artifact_package_version: str = V070_PACKAGE_VERSION,
) -> None:
    evidence = root / "release-evidence"
    dist = root / "dist"
    evidence.mkdir()
    dist.mkdir()
    (evidence / "pytest.xml").write_text(
        """<?xml version=\"1.0\" encoding=\"utf-8\"?>
<testsuites><testsuite name=\"pytest\">
  <testcase name=\"one\" />
  <testcase name=\"two\" />
  <testcase name=\"three\"><skipped /></testcase>
</testsuite></testsuites>
""",
        encoding="utf-8",
    )
    (evidence / "coverage.json").write_text(
        json.dumps({"totals": {"percent_covered": 91.67}}),
        encoding="utf-8",
    )
    (evidence / "integration.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "command": "python integration/production_smoke.py --skip-kind",
                "status": "passed",
            }
        ),
        encoding="utf-8",
    )
    (evidence / "dependency-audit.json").write_text(
        json.dumps([{"name": "example", "version": "1.0", "vulns": []}]),
        encoding="utf-8",
    )
    (dist / f"agent_runtime_governance-{artifact_package_version}-py3-none-any.whl").write_bytes(
        b"wheel"
    )
    (dist / f"agent_runtime_governance-{artifact_package_version}.tar.gz").write_bytes(
        b"sdist"
    )
    (dist / "sbom.spdx.json").write_text("{}\n", encoding="utf-8")


def _manifest(release_manifest: ModuleType, root: Path) -> dict[str, Any]:
    return release_manifest.generate_manifest(
        root,
        release_tag=V070_RELEASE_TAG,
        source_commit=SOURCE_COMMIT,
        package_version=V070_PACKAGE_VERSION,
        service_images=SERVICE_IMAGES,
    )


def _write_checksums(
    root: Path,
    document: dict[str, Any],
    *,
    omit_manifest: bool = False,
    duplicate_manifest: bool = False,
    corrupt_manifest_digest: bool = False,
) -> None:
    subjects = list(document["checksums"]["subjects"])
    if omit_manifest:
        subjects.remove("dist/release-manifest.json")
    lines: list[str] = []
    for subject in subjects:
        digest = hashlib.sha256((root / subject).read_bytes()).hexdigest()
        if corrupt_manifest_digest and subject == "dist/release-manifest.json":
            digest = "0" * 64
        lines.append(f"{digest}  {subject}")
    if duplicate_manifest:
        digest = hashlib.sha256(
            (root / "dist/release-manifest.json").read_bytes()
        ).hexdigest()
        lines.append(f"{digest}  dist/release-manifest.json")
    (root / "dist" / "SHA256SUMS").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def _written_manifest(
    release_manifest: ModuleType,
    root: Path,
) -> dict[str, Any]:
    document = _manifest(release_manifest, root)
    release_manifest.write_manifest(root, document)
    return document


def test_generates_and_validates_same_job_release_evidence(
    tmp_path: Path,
    release_manifest: ModuleType,
) -> None:
    _write_release_inputs(tmp_path)

    document = _written_manifest(release_manifest, tmp_path)
    _write_checksums(tmp_path, document)

    release_manifest.validate_manifest(
        document,
        root=tmp_path,
        service_images=SERVICE_IMAGES,
        checksum_file="dist/SHA256SUMS",
    )

    assert document["tests"] == {
        "report_path": "release-evidence/pytest.xml",
        "total": 3,
        "passed": 2,
        "failed": 0,
        "errors": 0,
        "skipped": 1,
    }
    assert document["coverage"]["percent"] == 91.67
    assert document["dependency_audit"]["vulnerability_count"] == 0
    assert document["checksums"]["subjects"][-1] == "dist/release-manifest.json"
    assert "dist/release-manifest.json" in document["provenance"]["subject_paths"]
    assert "dist/SHA256SUMS" in document["provenance"]["subject_paths"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.pop("generated_at"),
        lambda document: document.update({"unexpected": True}),
        lambda document: document["release"].update({"unexpected": True}),
        lambda document: document.update({"generated_at": "not-a-timestamp"}),
        lambda document: document["release"].update({"source_commit": "bad"}),
        lambda document: document["service_images"].update({"opa": "opa:latest"}),
    ],
    ids=[
        "missing-field",
        "extra-top-level-field",
        "extra-nested-field",
        "malformed-timestamp",
        "malformed-source-commit",
        "unpinned-service-image",
    ],
)
def test_schema_rejects_missing_extra_and_malformed_evidence(
    tmp_path: Path,
    release_manifest: ModuleType,
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    _write_release_inputs(tmp_path)
    document = _manifest(release_manifest, tmp_path)

    mutate(document)

    with pytest.raises(release_manifest.ReleaseManifestError, match="schema validation"):
        release_manifest.validate_manifest(
            document,
            root=tmp_path,
            service_images=SERVICE_IMAGES,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document["release"].update({"tag": "v0.7.1"}),
            "tag and package version",
        ),
        (
            lambda document: document["provenance"].update({"source_commit": "b" * 40}),
            "source commit",
        ),
        (
            lambda document: document["tests"].update({"failed": 1, "passed": 1}),
            "failed tests",
        ),
        (
            lambda document: document["coverage"].update({"percent": 79.99}),
            "coverage is below",
        ),
        (
            lambda document: document["dependency_audit"].update(
                {"vulnerability_count": 1}
            ),
            "vulnerable audit",
        ),
        (
            lambda document: document["service_images"].update(
                {"opa": SERVICE_IMAGES["otel"]}
            ),
            "service image evidence drifts",
        ),
    ],
    ids=[
        "tag-version",
        "provenance-commit",
        "test-status",
        "coverage-threshold",
        "audit-status",
        "service-image-drift",
    ],
)
def test_semantic_validation_rejects_contradictory_evidence(
    tmp_path: Path,
    release_manifest: ModuleType,
    mutate: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    _write_release_inputs(tmp_path)
    document = _manifest(release_manifest, tmp_path)

    mutate(document)

    with pytest.raises(release_manifest.ReleaseManifestError, match=message):
        release_manifest.validate_manifest(
            document,
            root=tmp_path,
            service_images=SERVICE_IMAGES,
        )


@pytest.mark.parametrize(
    ("filename", "contents", "message"),
    [
        ("coverage.json", "{", "JSON is malformed"),
        ("integration.json", "{}", "integration report"),
        ("dependency-audit.json", "{}", "dependency audit report"),
    ],
    ids=["coverage", "integration", "dependency-audit"],
)
def test_generation_rejects_malformed_trusted_job_outputs(
    tmp_path: Path,
    release_manifest: ModuleType,
    filename: str,
    contents: str,
    message: str,
) -> None:
    _write_release_inputs(tmp_path)
    (tmp_path / "release-evidence" / filename).write_text(contents, encoding="utf-8")

    with pytest.raises(release_manifest.ReleaseManifestError, match=message):
        _manifest(release_manifest, tmp_path)


def test_generation_rejects_a_dependency_audit_with_vulnerabilities(
    tmp_path: Path,
    release_manifest: ModuleType,
) -> None:
    _write_release_inputs(tmp_path)
    (tmp_path / "release-evidence" / "dependency-audit.json").write_text(
        json.dumps([{"name": "example", "version": "1.0", "vulns": [{"id": "CVE"}]}]),
        encoding="utf-8",
    )

    with pytest.raises(release_manifest.ReleaseManifestError, match="vulnerable audit"):
        _manifest(release_manifest, tmp_path)


@pytest.mark.parametrize(
    "skip_reason",
    ("dependency could not be audited", "", False, 0, [], {}),
    ids=("message", "empty-string", "false", "zero", "empty-list", "empty-object"),
)
def test_generation_rejects_a_dependency_audit_with_skipped_dependency(
    tmp_path: Path,
    release_manifest: ModuleType,
    skip_reason: object,
) -> None:
    _write_release_inputs(tmp_path)
    (tmp_path / "release-evidence" / "dependency-audit.json").write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        "name": "unresolved-example",
                        "skip_reason": skip_reason,
                        "vulns": [],
                    }
                ],
                "fixes": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(release_manifest.ReleaseManifestError, match="skipped a dependency"):
        _manifest(release_manifest, tmp_path)


def test_generation_allows_a_dependency_audit_with_null_skip_reason(
    tmp_path: Path,
    release_manifest: ModuleType,
) -> None:
    _write_release_inputs(tmp_path)
    (tmp_path / "release-evidence" / "dependency-audit.json").write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        "name": "audited-example",
                        "skip_reason": None,
                        "vulns": [],
                    }
                ],
                "fixes": [],
            }
        ),
        encoding="utf-8",
    )

    assert (
        _manifest(release_manifest, tmp_path)["dependency_audit"]["vulnerability_count"]
        == 0
    )


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"omit_manifest": True}, "subjects do not match"),
        ({"duplicate_manifest": True}, "duplicate subject"),
        ({"corrupt_manifest_digest": True}, "digest values do not match"),
    ],
    ids=["missing-manifest", "duplicate-manifest", "tampered-manifest"],
)
def test_validation_rejects_missing_or_invalid_manifest_checksums(
    tmp_path: Path,
    release_manifest: ModuleType,
    options: dict[str, bool],
    message: str,
) -> None:
    _write_release_inputs(tmp_path)
    document = _written_manifest(release_manifest, tmp_path)
    _write_checksums(tmp_path, document, **options)

    with pytest.raises(release_manifest.ReleaseManifestError, match=message):
        release_manifest.validate_manifest(
            document,
            root=tmp_path,
            service_images=SERVICE_IMAGES,
            checksum_file="dist/SHA256SUMS",
        )


def test_rejects_workspace_path_escape(
    tmp_path: Path,
    release_manifest: ModuleType,
) -> None:
    _write_release_inputs(tmp_path)

    with pytest.raises(release_manifest.ReleaseManifestError, match="not allowed"):
        release_manifest._safe_workspace_path(
            tmp_path,
            "release-evidence/../outside.json",
            allowed_roots=("release-evidence",),
        )


def test_rejects_symbolic_link_escape(
    tmp_path: Path,
    release_manifest: ModuleType,
) -> None:
    _write_release_inputs(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = tmp_path / "release-evidence" / "linked.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")

    with pytest.raises(release_manifest.ReleaseManifestError, match="symbolic link"):
        release_manifest._safe_workspace_path(
            tmp_path,
            "release-evidence/linked.json",
            allowed_roots=("release-evidence",),
        )


def test_rejects_report_content_that_disagrees_with_valid_manifest_shape(
    tmp_path: Path,
    release_manifest: ModuleType,
) -> None:
    _write_release_inputs(tmp_path)
    document = _manifest(release_manifest, tmp_path)
    document["tests"].update({"passed": 1, "skipped": 2})

    with pytest.raises(release_manifest.ReleaseManifestError, match="differs from the JUnit"):
        release_manifest.validate_manifest(
            document,
            root=tmp_path,
            service_images=SERVICE_IMAGES,
        )


def test_rejects_manifest_not_bound_to_the_trusted_release_source(
    tmp_path: Path,
    release_manifest: ModuleType,
) -> None:
    _write_release_inputs(tmp_path)
    document = _manifest(release_manifest, tmp_path)

    with pytest.raises(release_manifest.ReleaseManifestError, match="trusted source"):
        release_manifest.validate_manifest(
            document,
            root=tmp_path,
            service_images=SERVICE_IMAGES,
            expected_release_tag=V070_RELEASE_TAG,
            expected_source_commit="b" * 40,
        )


def test_cli_records_generates_and_validates_manifest(tmp_path: Path) -> None:
    _write_release_inputs(tmp_path, artifact_package_version=__version__)
    record = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "record-integration",
            "--command",
            "python integration/production_smoke.py --skip-kind",
            "--root",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert record.returncode == 0, record.stderr

    generated = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "generate",
            "--release-tag",
            CURRENT_RELEASE_TAG,
            "--source-commit",
            SOURCE_COMMIT,
            "--root",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert generated.returncode == 0, generated.stderr
    document = json.loads((tmp_path / "dist" / "release-manifest.json").read_text())
    _write_checksums(tmp_path, document)

    validated = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "validate",
            "--release-tag",
            CURRENT_RELEASE_TAG,
            "--source-commit",
            SOURCE_COMMIT,
            "--root",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert validated.returncode == 0, validated.stderr


def test_release_service_image_mapping_matches_the_smoke_harness(
    release_manifest: ModuleType,
) -> None:
    smoke_path = ROOT / "integration" / "production_smoke.py"
    spec = importlib.util.spec_from_file_location("production_smoke_release_images", smoke_path)
    assert spec is not None
    assert spec.loader is not None
    smoke = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = smoke
    spec.loader.exec_module(smoke)

    assert smoke.release_service_images() == smoke.RELEASE_SERVICE_IMAGES
    assert release_manifest._release_service_images() == smoke.release_service_images()


def test_release_and_publish_workflows_gate_manifest_before_distribution() -> None:
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    publish = (ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text(
        encoding="utf-8"
    )

    assert "python scripts/release_manifest.py generate" in release
    assert "python scripts/release_manifest.py validate" in release
    assert release.index("python scripts/release_manifest.py generate") < release.index(
        "Generate SHA256 checksums"
    )
    assert release.index("python scripts/release_manifest.py validate") < release.index(
        "Attest release artifacts"
    )
    assert release.index("python scripts/release_manifest.py validate") < release.index(
        "Upload verified artifacts to release"
    )
    checksum_step = release[
        release.index("Generate SHA256 checksums") : release.index("Verify checksums")
    ]
    attestation_step = release[
        release.index("Attest release artifacts") : release.index(
            "Upload verified artifacts to release"
        )
    ]
    upload_step = release[release.index("Upload verified artifacts to release") :]
    assert "dist/release-manifest.json" in checksum_step
    assert "dist/release-manifest.json" in attestation_step
    assert "dist/release-manifest.json" in upload_step
    assert "actions/download-artifact" not in release
    assert "gh run download" not in release
    assert "continue-on-error" not in release
    assert "if: always()" not in release

    assert "--pattern 'release-manifest.json'" in publish
    assert "test -s dist/release-manifest.json" in publish
    assert "gh attestation verify dist/release-manifest.json" in publish
    assert publish.index("release-manifest.json") < publish.index(
        "Publish with PyPI Trusted Publishing"
    )


def test_release_documentation_keeps_the_manifest_claim_bounded() -> None:
    releasing = (ROOT / "RELEASING.md").read_text(encoding="utf-8").lower()
    verification = (ROOT / "docs" / "release-verification.md").read_text(
        encoding="utf-8"
    ).lower()
    assert "release verification manifest" in releasing

    for value in ("point-in-time", "uptime", "security", "latency", "compliance"):
        assert value in verification
