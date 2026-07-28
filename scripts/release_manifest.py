"""Generate and validate the release verification manifest kept with a release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ElementTree
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    REPOSITORY_ROOT / "schemas" / "release-verification-manifest-v1.schema.json"
)
SCHEMA_VERSION = "1"
EVIDENCE_DIRECTORY = "release-evidence"
DIST_DIRECTORY = "dist"
TEST_REPORT_PATH = f"{EVIDENCE_DIRECTORY}/pytest.xml"
COVERAGE_REPORT_PATH = f"{EVIDENCE_DIRECTORY}/coverage.json"
INTEGRATION_REPORT_PATH = f"{EVIDENCE_DIRECTORY}/integration.json"
DEPENDENCY_AUDIT_REPORT_PATH = f"{EVIDENCE_DIRECTORY}/dependency-audit.json"
MANIFEST_PATH = f"{DIST_DIRECTORY}/release-manifest.json"
CHECKSUM_PATH = f"{DIST_DIRECTORY}/SHA256SUMS"
RELEASE_WORKFLOW_PATH = ".github/workflows/release.yml"
DEFAULT_MINIMUM_COVERAGE = 80.0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))


class ReleaseManifestError(ValueError):
    """Raised when release evidence cannot support a manifest claim."""


def _load_schema() -> dict[str, Any]:
    try:
        document = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("release manifest schema is unreadable") from exc
    if not isinstance(document, dict):
        raise RuntimeError("release manifest schema must be an object")
    try:
        Draft202012Validator.check_schema(document)
    except Exception as exc:  # jsonschema exposes multiple schema-error types.
        raise RuntimeError("release manifest schema is invalid") from exc
    return document


_SCHEMA = _load_schema()
if "date-time" not in Draft202012Validator.FORMAT_CHECKER.checkers:
    raise RuntimeError("rfc3339-validator is required for release manifest validation")
_SCHEMA_VALIDATOR = Draft202012Validator(
    _SCHEMA,
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def _workspace_root(value: Path | str) -> Path:
    root = Path(value).resolve()
    if not root.is_dir():
        raise ReleaseManifestError(f"workspace root is not a directory: {root}")
    return root


def _safe_workspace_path(
    root: Path,
    relative_path: str,
    *,
    allowed_roots: tuple[str, ...],
) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ReleaseManifestError("release evidence path must be a non-empty string")
    path = Path(relative_path)
    if path.is_absolute() or not path.parts:
        raise ReleaseManifestError(f"release evidence path must be relative: {relative_path!r}")
    if path.parts[0] not in allowed_roots or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ReleaseManifestError(f"release evidence path is not allowed: {relative_path!r}")

    candidate = root.joinpath(*path.parts)
    for ancestor in (candidate, *candidate.parents):
        try:
            ancestor.relative_to(root)
        except ValueError:
            break
        if ancestor.is_symlink():
            raise ReleaseManifestError(
                f"release evidence path must not traverse a symbolic link: {relative_path!r}"
            )
        if ancestor == root:
            break

    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ReleaseManifestError(
            f"release evidence path escapes the workspace: {relative_path!r}"
        ) from exc
    return resolved


def _existing_file(
    root: Path,
    relative_path: str,
    *,
    allowed_roots: tuple[str, ...],
) -> Path:
    path = _safe_workspace_path(root, relative_path, allowed_roots=allowed_roots)
    if not path.is_file():
        raise ReleaseManifestError(f"release evidence file is missing: {relative_path}")
    return path


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise ReleaseManifestError(f"release evidence file escapes the workspace: {path}") from exc


def _load_json(
    root: Path,
    relative_path: str,
    *,
    allowed_roots: tuple[str, ...],
) -> Any:
    path = _existing_file(root, relative_path, allowed_roots=allowed_roots)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseManifestError(
            f"release evidence JSON is malformed: {relative_path}"
        ) from exc


def _as_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseManifestError(f"{label} must be an object")
    return dict(value)


def _read_junit(root: Path) -> dict[str, int]:
    path = _existing_file(
        root,
        TEST_REPORT_PATH,
        allowed_roots=(EVIDENCE_DIRECTORY,),
    )
    try:
        document = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        raise ReleaseManifestError("JUnit report is malformed") from exc
    if _element_name(document) not in {"testsuite", "testsuites"}:
        raise ReleaseManifestError("JUnit report has no testsuite root")

    testcases = [
        element
        for element in document.iter()
        if _element_name(element) == "testcase"
    ]
    if not testcases:
        raise ReleaseManifestError("JUnit report contains no test cases")

    counts = {"total": len(testcases), "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for testcase in testcases:
        outcomes = {_element_name(child) for child in testcase}
        if "error" in outcomes:
            counts["errors"] += 1
        elif "failure" in outcomes:
            counts["failed"] += 1
        elif "skipped" in outcomes:
            counts["skipped"] += 1
        else:
            counts["passed"] += 1
    return counts


def _element_name(element: ElementTree.Element) -> str:
    return element.tag.rsplit("}", maxsplit=1)[-1]


def _read_coverage(root: Path) -> float:
    document = _as_object(
        _load_json(
            root,
            COVERAGE_REPORT_PATH,
            allowed_roots=(EVIDENCE_DIRECTORY,),
        ),
        "coverage report",
    )
    totals = _as_object(document.get("totals"), "coverage report totals")
    percent = totals.get("percent_covered")
    if isinstance(percent, bool) or not isinstance(percent, int | float):
        raise ReleaseManifestError("coverage report has no numeric totals.percent_covered")
    value = float(percent)
    if not 0 <= value <= 100:
        raise ReleaseManifestError("coverage report percent must be between 0 and 100")
    return value


def _read_integration(root: Path) -> dict[str, str]:
    document = _as_object(
        _load_json(
            root,
            INTEGRATION_REPORT_PATH,
            allowed_roots=(EVIDENCE_DIRECTORY,),
        ),
        "integration report",
    )
    if set(document) != {"schema_version", "command", "status"}:
        raise ReleaseManifestError("integration report has unexpected fields")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ReleaseManifestError("integration report schema version is unsupported")
    command = document["command"]
    if not isinstance(command, str) or not command:
        raise ReleaseManifestError("integration report command must be non-empty")
    if document["status"] != "passed":
        raise ReleaseManifestError("integration report did not pass")
    return {"command": command, "status": "passed"}


def _read_dependency_audit(root: Path) -> int:
    document = _load_json(
        root,
        DEPENDENCY_AUDIT_REPORT_PATH,
        allowed_roots=(EVIDENCE_DIRECTORY,),
    )
    if isinstance(document, list):
        dependencies = document
    elif isinstance(document, Mapping) and isinstance(document.get("dependencies"), list):
        dependencies = document["dependencies"]
    else:
        raise ReleaseManifestError("dependency audit report has an unsupported format")

    vulnerability_count = 0
    for dependency in dependencies:
        entry = _as_object(dependency, "dependency audit entry")
        if entry.get("skip_reason") is not None:
            raise ReleaseManifestError("dependency audit skipped a dependency")
        vulnerabilities = entry.get("vulns")
        if not isinstance(vulnerabilities, list):
            raise ReleaseManifestError("dependency audit entry has no vulnerabilities list")
        if any(not isinstance(item, Mapping) for item in vulnerabilities):
            raise ReleaseManifestError("dependency audit vulnerabilities must be objects")
        vulnerability_count += len(vulnerabilities)
    return vulnerability_count


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _single_artifact(root: Path, pattern: str, label: str) -> Path:
    dist = _safe_workspace_path(root, DIST_DIRECTORY, allowed_roots=(DIST_DIRECTORY,))
    if not dist.is_dir():
        raise ReleaseManifestError("distribution directory is missing")
    matches = sorted(dist.glob(pattern))
    if any(path.is_symlink() for path in matches):
        raise ReleaseManifestError(f"{label} artifact must not be a symbolic link")
    files = [path for path in matches if path.is_file()]
    if len(files) != 1:
        raise ReleaseManifestError(f"expected exactly one {label} artifact")
    return files[0]


def _artifact(root: Path, path: Path) -> dict[str, str]:
    return {"path": _relative_path(root, path), "sha256": _sha256(path)}


def _release_service_images() -> dict[str, str]:
    from integration.production_smoke import release_service_images

    images = release_service_images()
    if not isinstance(images, Mapping):
        raise ReleaseManifestError("production smoke service image mapping is invalid")
    return dict(images)


def _package_version() -> str:
    from agent_runtime_governance import __version__

    if not isinstance(__version__, str):
        raise ReleaseManifestError("package version is invalid")
    return __version__


def generate_manifest(
    root: Path | str,
    *,
    release_tag: str,
    source_commit: str,
    package_version: str | None = None,
    minimum_coverage: float = DEFAULT_MINIMUM_COVERAGE,
    service_images: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a manifest from same-job release evidence without writing it."""

    workspace = _workspace_root(root)
    version = _package_version() if package_version is None else package_version
    if not isinstance(version, str):
        raise ReleaseManifestError("package version must be a string")
    if isinstance(minimum_coverage, bool) or not isinstance(
        minimum_coverage, int | float
    ):
        raise ReleaseManifestError("minimum coverage must be numeric")

    tests = _read_junit(workspace)
    coverage = _read_coverage(workspace)
    integration = _read_integration(workspace)
    vulnerability_count = _read_dependency_audit(workspace)
    artifacts = {
        "wheel": _artifact(workspace, _single_artifact(workspace, "*.whl", "wheel")),
        "sdist": _artifact(workspace, _single_artifact(workspace, "*.tar.gz", "sdist")),
        "sbom": _artifact(
            workspace,
            _existing_file(
                workspace,
                f"{DIST_DIRECTORY}/sbom.spdx.json",
                allowed_roots=(DIST_DIRECTORY,),
            ),
        ),
    }
    checksum_subjects = [
        artifacts["wheel"]["path"],
        artifacts["sdist"]["path"],
        artifacts["sbom"]["path"],
        MANIFEST_PATH,
    ]
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _timestamp(),
        "release": {
            "tag": release_tag,
            "package_version": version,
            "source_commit": source_commit,
        },
        "tests": {"report_path": TEST_REPORT_PATH, **tests},
        "coverage": {
            "report_path": COVERAGE_REPORT_PATH,
            "percent": coverage,
            "minimum": float(minimum_coverage),
            "status": "passed",
        },
        "integration": {
            "report_path": INTEGRATION_REPORT_PATH,
            **integration,
        },
        "dependency_audit": {
            "report_path": DEPENDENCY_AUDIT_REPORT_PATH,
            "vulnerability_count": vulnerability_count,
            "status": "passed",
        },
        "artifacts": artifacts,
        "service_images": dict(
            _release_service_images() if service_images is None else service_images
        ),
        "checksums": {"path": CHECKSUM_PATH, "subjects": checksum_subjects},
        "provenance": {
            "workflow_path": RELEASE_WORKFLOW_PATH,
            "source_ref": f"refs/tags/{release_tag}",
            "source_commit": source_commit,
            "subject_paths": [*checksum_subjects, CHECKSUM_PATH],
        },
    }
    validate_manifest(
        document,
        root=workspace,
        service_images=service_images,
        expected_release_tag=release_tag,
        expected_source_commit=source_commit,
    )
    return document


def write_manifest(root: Path | str, document: Mapping[str, Any]) -> Path:
    """Write one validated manifest to its fixed release asset location."""

    workspace = _workspace_root(root)
    output = _safe_workspace_path(
        workspace,
        MANIFEST_PATH,
        allowed_roots=(DIST_DIRECTORY,),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ReleaseManifestError("release manifest output must not be a symbolic link")
    output.write_text(
        json.dumps(dict(document), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def record_integration_success(root: Path | str, command: str) -> Path:
    """Record a successful release integration command after the command returns."""

    if not isinstance(command, str) or not command:
        raise ReleaseManifestError("integration command must be non-empty")
    workspace = _workspace_root(root)
    output = _safe_workspace_path(
        workspace,
        INTEGRATION_REPORT_PATH,
        allowed_roots=(EVIDENCE_DIRECTORY,),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ReleaseManifestError("integration report output must not be a symbolic link")
    output.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "status": "passed",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output


def validate_manifest(
    document: Mapping[str, Any],
    *,
    root: Path | str,
    service_images: Mapping[str, str] | None = None,
    checksum_file: str | None = None,
    expected_release_tag: str | None = None,
    expected_source_commit: str | None = None,
) -> None:
    """Fail closed unless the manifest and its same-job inputs agree."""

    workspace = _workspace_root(root)
    manifest = _as_object(document, "release manifest")
    _validate_schema(manifest)
    _validate_semantics(manifest)
    _validate_trusted_source(
        manifest,
        expected_release_tag=expected_release_tag,
        expected_source_commit=expected_source_commit,
    )
    _validate_report_values(workspace, manifest)
    _validate_artifacts(workspace, manifest)

    expected_images = dict(
        _release_service_images() if service_images is None else service_images
    )
    if manifest["service_images"] != expected_images:
        raise ReleaseManifestError("service image evidence drifts from production smoke")

    _validate_checksum_metadata(manifest)
    if checksum_file is not None:
        _validate_checksum_file(workspace, manifest, checksum_file)


def _validate_schema(document: dict[str, Any]) -> None:
    errors = sorted(
        _SCHEMA_VALIDATOR.iter_errors(document),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        error = errors[0]
        path = "/".join(str(item) for item in error.absolute_path) or "$"
        raise ReleaseManifestError(
            f"release manifest schema validation failed at {path}: {error.message}"
        )


def _validate_semantics(manifest: dict[str, Any]) -> None:
    release = manifest["release"]
    if release["tag"].removeprefix("v") != release["package_version"]:
        raise ReleaseManifestError("release tag and package version disagree")
    if manifest["provenance"]["source_ref"] != f"refs/tags/{release['tag']}":
        raise ReleaseManifestError("provenance source ref does not match release tag")
    if manifest["provenance"]["source_commit"] != release["source_commit"]:
        raise ReleaseManifestError("provenance source commit does not match release")

    tests = manifest["tests"]
    if tests["passed"] + tests["failed"] + tests["errors"] + tests["skipped"] != tests[
        "total"
    ]:
        raise ReleaseManifestError("test result counts do not add up")
    if tests["failed"] or tests["errors"]:
        raise ReleaseManifestError("release manifest cannot claim failed tests passed")

    coverage = manifest["coverage"]
    if coverage["percent"] < coverage["minimum"]:
        raise ReleaseManifestError("release manifest coverage is below its minimum")
    if manifest["dependency_audit"]["vulnerability_count"]:
        raise ReleaseManifestError("release manifest cannot claim a vulnerable audit passed")

    version = release["package_version"]
    for label in ("wheel", "sdist"):
        artifact = manifest["artifacts"][label]
        if version not in Path(artifact["path"]).name:
            raise ReleaseManifestError("artifact filename does not contain package version")


def _validate_trusted_source(
    manifest: dict[str, Any],
    *,
    expected_release_tag: str | None,
    expected_source_commit: str | None,
) -> None:
    release = manifest["release"]
    if expected_release_tag is not None and release["tag"] != expected_release_tag:
        raise ReleaseManifestError("release tag does not match the trusted source")
    if (
        expected_source_commit is not None
        and release["source_commit"] != expected_source_commit
    ):
        raise ReleaseManifestError("release commit does not match the trusted source")


def _validate_report_values(root: Path, manifest: dict[str, Any]) -> None:
    expected_tests = {"report_path": TEST_REPORT_PATH, **_read_junit(root)}
    if manifest["tests"] != expected_tests:
        raise ReleaseManifestError("manifest test evidence differs from the JUnit report")

    expected_coverage = _read_coverage(root)
    if manifest["coverage"]["percent"] != expected_coverage:
        raise ReleaseManifestError("manifest coverage differs from the coverage report")

    integration = _read_integration(root)
    expected_integration = {"report_path": INTEGRATION_REPORT_PATH, **integration}
    if manifest["integration"] != expected_integration:
        raise ReleaseManifestError(
            "manifest integration evidence differs from the integration report"
        )

    expected_vulnerabilities = _read_dependency_audit(root)
    if manifest["dependency_audit"]["vulnerability_count"] != expected_vulnerabilities:
        raise ReleaseManifestError(
            "manifest audit evidence differs from the dependency audit report"
        )


def _validate_artifacts(root: Path, manifest: dict[str, Any]) -> None:
    expected_files = {
        "wheel": _single_artifact(root, "*.whl", "wheel"),
        "sdist": _single_artifact(root, "*.tar.gz", "sdist"),
        "sbom": _existing_file(
            root,
            f"{DIST_DIRECTORY}/sbom.spdx.json",
            allowed_roots=(DIST_DIRECTORY,),
        ),
    }
    for label, path in expected_files.items():
        artifact = manifest["artifacts"][label]
        if artifact["path"] != _relative_path(root, path):
            raise ReleaseManifestError(f"manifest {label} artifact path is incorrect")
        if artifact["sha256"] != _sha256(path):
            raise ReleaseManifestError(f"manifest {label} artifact digest is incorrect")


def _validate_checksum_metadata(manifest: dict[str, Any]) -> None:
    artifact_paths = [item["path"] for item in manifest["artifacts"].values()]
    expected_subjects = {*artifact_paths, MANIFEST_PATH}
    subjects = manifest["checksums"]["subjects"]
    if set(subjects) != expected_subjects or len(subjects) != len(expected_subjects):
        raise ReleaseManifestError("checksum subjects must cover artifacts and manifest exactly")

    provenance_subjects = manifest["provenance"]["subject_paths"]
    expected_provenance = {*expected_subjects, CHECKSUM_PATH}
    if set(provenance_subjects) != expected_provenance or len(provenance_subjects) != len(
        expected_provenance
    ):
        raise ReleaseManifestError(
            "provenance subjects must cover checksums, artifacts, and manifest exactly"
        )


def _validate_checksum_file(
    root: Path,
    manifest: dict[str, Any],
    checksum_file: str,
) -> None:
    if checksum_file != CHECKSUM_PATH:
        raise ReleaseManifestError("checksum validation must use dist/SHA256SUMS")
    path = _existing_file(
        root,
        checksum_file,
        allowed_roots=(DIST_DIRECTORY,),
    )
    entries: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleaseManifestError("checksum file is unreadable") from exc
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (dist/.+)", line)
        if match is None:
            raise ReleaseManifestError("checksum file has an invalid entry")
        digest, subject = match.groups()
        if subject in entries:
            raise ReleaseManifestError("checksum file contains a duplicate subject")
        _existing_file(root, subject, allowed_roots=(DIST_DIRECTORY,))
        entries[subject] = digest

    subjects = manifest["checksums"]["subjects"]
    if set(entries) != set(subjects):
        raise ReleaseManifestError("checksum file subjects do not match the manifest")

    artifacts = manifest["artifacts"]
    expected_digests = {
        artifacts["wheel"]["path"]: artifacts["wheel"]["sha256"],
        artifacts["sdist"]["path"]: artifacts["sdist"]["sha256"],
        artifacts["sbom"]["path"]: artifacts["sbom"]["sha256"],
    }
    manifest_file = _existing_file(
        root,
        MANIFEST_PATH,
        allowed_roots=(DIST_DIRECTORY,),
    )
    expected_digests[MANIFEST_PATH] = _sha256(manifest_file)
    if entries != expected_digests:
        raise ReleaseManifestError("checksum file digest values do not match release assets")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate and validate a release verification manifest."
    )
    subcommands = parser.add_subparsers(dest="operation", required=True)

    record = subcommands.add_parser(
        "record-integration",
        help="Record a completed release integration command.",
    )
    record.add_argument("--command", dest="integration_command", required=True)
    record.add_argument("--root", default=".")

    generate = subcommands.add_parser("generate", help="Generate a release manifest.")
    generate.add_argument("--release-tag", required=True)
    generate.add_argument("--source-commit", required=True)
    generate.add_argument("--package-version")
    generate.add_argument("--minimum-coverage", type=float, default=DEFAULT_MINIMUM_COVERAGE)
    generate.add_argument("--root", default=".")

    validate = subcommands.add_parser("validate", help="Validate a release manifest.")
    validate.add_argument("--release-tag", required=True)
    validate.add_argument("--source-commit", required=True)
    validate.add_argument("--root", default=".")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.operation == "record-integration":
            output = record_integration_success(arguments.root, arguments.integration_command)
            print(_relative_path(_workspace_root(arguments.root), output))
            return 0
        if arguments.operation == "generate":
            document = generate_manifest(
                arguments.root,
                release_tag=arguments.release_tag,
                source_commit=arguments.source_commit,
                package_version=arguments.package_version,
                minimum_coverage=arguments.minimum_coverage,
            )
            output = write_manifest(arguments.root, document)
            print(_relative_path(_workspace_root(arguments.root), output))
            return 0
        if arguments.operation == "validate":
            workspace = _workspace_root(arguments.root)
            document = _as_object(
                _load_json(
                    workspace,
                    MANIFEST_PATH,
                    allowed_roots=(DIST_DIRECTORY,),
                ),
                "release manifest",
            )
            validate_manifest(
                document,
                root=workspace,
                checksum_file=CHECKSUM_PATH,
                expected_release_tag=arguments.release_tag,
                expected_source_commit=arguments.source_commit,
            )
            print(MANIFEST_PATH)
            return 0
    except ReleaseManifestError as exc:
        parser.error(str(exc))
    raise AssertionError(f"unexpected command: {arguments.operation}")


if __name__ == "__main__":
    raise SystemExit(main())
