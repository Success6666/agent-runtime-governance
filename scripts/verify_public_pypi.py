from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

PACKAGE_NAME = "agent-runtime-governance"
PYPI_API_HOST = "pypi.org"
PYPI_FILE_HOST = "files.pythonhosted.org"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PublicPyPIVerificationError(RuntimeError):
    """Raised when the public distribution does not match the release record."""


class PublicPyPINotReady(PublicPyPIVerificationError):
    """Raised while an exact release is not yet visible on the public index."""


@dataclass(frozen=True)
class ExpectedArtifact:
    kind: str
    filename: str
    sha256: str


@dataclass(frozen=True)
class PublicArtifact:
    kind: str
    filename: str
    sha256: str
    size: int
    url: str


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicPyPIVerificationError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise PublicPyPIVerificationError(f"{path.name} must contain a JSON object")
    return value


def _checksums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PublicPyPIVerificationError(f"cannot read {path.name}: {exc}") from exc
    values: dict[str, str] = {}
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not _SHA256.fullmatch(parts[0]):
            raise PublicPyPIVerificationError("SHA256SUMS contains an invalid entry")
        artifact_path = parts[1].lstrip(" *")
        if not artifact_path or artifact_path in values:
            raise PublicPyPIVerificationError("SHA256SUMS contains a duplicate entry")
        values[artifact_path] = parts[0]
    return values


def load_release_record(
    manifest_path: Path,
    checksums_path: Path,
    release_tag: str,
) -> tuple[str, str, dict[str, ExpectedArtifact]]:
    if not release_tag.startswith("v"):
        raise PublicPyPIVerificationError("release tag must start with v")
    manifest = _read_json(manifest_path)
    release = manifest.get("release")
    provenance = manifest.get("provenance")
    artifacts = manifest.get("artifacts")
    if not isinstance(release, dict) or not isinstance(provenance, dict):
        raise PublicPyPIVerificationError("release manifest identity is missing")
    if not isinstance(artifacts, dict):
        raise PublicPyPIVerificationError("release manifest artifacts are missing")

    version = release.get("package_version")
    source_commit = release.get("source_commit")
    if release.get("tag") != release_tag or version != release_tag.removeprefix("v"):
        raise PublicPyPIVerificationError("release tag and package version do not match")
    if not isinstance(version, str) or not version:
        raise PublicPyPIVerificationError("release package version is invalid")
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise PublicPyPIVerificationError("release source commit is invalid")
    if provenance.get("source_ref") != f"refs/tags/{release_tag}":
        raise PublicPyPIVerificationError("release provenance is not bound to the tag")
    if provenance.get("source_commit") != source_commit:
        raise PublicPyPIVerificationError("release provenance commit does not match")

    checksum_values = _checksums(checksums_path)
    expected: dict[str, ExpectedArtifact] = {}
    for kind in ("wheel", "sdist"):
        value = artifacts.get(kind)
        if not isinstance(value, dict):
            raise PublicPyPIVerificationError(f"release {kind} entry is missing")
        artifact_path = value.get("path")
        digest = value.get("sha256")
        if not isinstance(artifact_path, str) or not artifact_path.startswith("dist/"):
            raise PublicPyPIVerificationError(f"release {kind} path is invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise PublicPyPIVerificationError(f"release {kind} digest is invalid")
        if checksum_values.get(artifact_path) != digest:
            raise PublicPyPIVerificationError(
                f"release {kind} digest does not match SHA256SUMS"
            )
        filename = Path(artifact_path).name
        if version not in filename:
            raise PublicPyPIVerificationError(f"release {kind} filename has the wrong version")
        expected[filename] = ExpectedArtifact(
            kind=kind,
            filename=filename,
            sha256=digest,
        )
    if len(expected) != 2:
        raise PublicPyPIVerificationError("release artifact filenames must be unique")
    return version, source_commit, expected


def select_public_artifacts(
    document: Mapping[str, Any],
    expected: Mapping[str, ExpectedArtifact],
) -> dict[str, PublicArtifact]:
    urls = document.get("urls")
    if not isinstance(urls, list):
        raise PublicPyPINotReady("public PyPI release files are not visible")
    by_name: dict[str, list[Mapping[str, Any]]] = {name: [] for name in expected}
    for value in urls:
        if isinstance(value, dict) and value.get("filename") in by_name:
            by_name[value["filename"]].append(value)

    selected: dict[str, PublicArtifact] = {}
    for filename, release_artifact in expected.items():
        matches = by_name[filename]
        if not matches:
            raise PublicPyPINotReady(f"public PyPI artifact is not visible: {filename}")
        if len(matches) != 1:
            raise PublicPyPIVerificationError(
                f"public PyPI contains duplicate artifact metadata: {filename}"
            )
        value = matches[0]
        expected_type = "bdist_wheel" if release_artifact.kind == "wheel" else "sdist"
        digest = value.get("digests", {}).get("sha256") if isinstance(value.get("digests"), dict) else None
        url = value.get("url")
        size = value.get("size")
        if value.get("packagetype") != expected_type or value.get("yanked") is True:
            raise PublicPyPIVerificationError(f"public PyPI artifact metadata is invalid: {filename}")
        if digest != release_artifact.sha256:
            raise PublicPyPIVerificationError(
                f"public PyPI digest does not match the release record: {filename}"
            )
        if not isinstance(url, str) or not isinstance(size, int) or size < 1:
            raise PublicPyPIVerificationError(f"public PyPI artifact metadata is incomplete: {filename}")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != PYPI_FILE_HOST:
            raise PublicPyPIVerificationError(f"public PyPI artifact URL is not trusted: {filename}")
        selected[filename] = PublicArtifact(
            kind=release_artifact.kind,
            filename=filename,
            sha256=digest,
            size=size,
            url=url,
        )
    return selected


def _fetch_json(url: str, timeout_seconds: float) -> Mapping[str, Any]:
    request = Request(url, headers={"User-Agent": "agent-runtime-governance-release-verifier"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            value = json.loads(response.read())
    except json.JSONDecodeError as exc:
        raise PublicPyPIVerificationError("public PyPI response is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PublicPyPIVerificationError("public PyPI response must be a JSON object")
    return value


def wait_for_public_artifacts(
    version: str,
    expected: Mapping[str, ExpectedArtifact],
    *,
    attempts: int,
    delay_seconds: float,
    timeout_seconds: float,
    fetch_json: Callable[[str, float], Mapping[str, Any]] = _fetch_json,
) -> dict[str, PublicArtifact]:
    if attempts < 1 or delay_seconds < 0 or timeout_seconds <= 0:
        raise PublicPyPIVerificationError("public PyPI retry settings are invalid")
    url = (
        f"https://{PYPI_API_HOST}/pypi/"
        f"{quote(PACKAGE_NAME, safe='')}/{quote(version, safe='')}/json"
    )
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return select_public_artifacts(fetch_json(url, timeout_seconds), expected)
        except HTTPError as exc:
            if exc.code != 404:
                raise PublicPyPIVerificationError(f"public PyPI request failed: {exc}") from exc
            last_error = exc
        except (URLError, TimeoutError, PublicPyPINotReady) as exc:
            last_error = exc
        if attempt + 1 < attempts:
            time.sleep(delay_seconds)
    raise PublicPyPIVerificationError(
        f"public PyPI did not expose the exact release after {attempts} attempts: {last_error}"
    )


def _fetch_bytes(url: str, timeout_seconds: float) -> bytes:
    request = Request(url, headers={"User-Agent": "agent-runtime-governance-release-verifier"})
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


def download_and_verify(
    artifacts: Mapping[str, PublicArtifact],
    output_dir: Path,
    *,
    timeout_seconds: float,
    fetch_bytes: Callable[[str, float], bytes] = _fetch_bytes,
) -> list[dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for filename in sorted(artifacts):
        artifact = artifacts[filename]
        payload = fetch_bytes(artifact.url, timeout_seconds)
        digest = hashlib.sha256(payload).hexdigest()
        if len(payload) != artifact.size or digest != artifact.sha256:
            raise PublicPyPIVerificationError(
                f"downloaded public PyPI artifact does not match metadata: {filename}"
            )
        target = output_dir / filename
        if target.exists() or target.is_symlink():
            raise PublicPyPIVerificationError(f"public artifact target already exists: {filename}")
        target.write_bytes(payload)
        results.append(
            {
                "kind": artifact.kind,
                "filename": filename,
                "sha256": digest,
                "size": len(payload),
                "url": artifact.url,
            }
        )
    return results


def verify_public_pypi(
    *,
    release_tag: str,
    manifest_path: Path,
    checksums_path: Path,
    output_dir: Path,
    attempts: int,
    delay_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    version, source_commit, expected = load_release_record(
        manifest_path,
        checksums_path,
        release_tag,
    )
    public_artifacts = wait_for_public_artifacts(
        version,
        expected,
        attempts=attempts,
        delay_seconds=delay_seconds,
        timeout_seconds=timeout_seconds,
    )
    artifacts = download_and_verify(
        public_artifacts,
        output_dir,
        timeout_seconds=timeout_seconds,
    )
    return {
        "schema_version": 1,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "package": PACKAGE_NAME,
        "package_version": version,
        "release_tag": release_tag,
        "source_commit": source_commit,
        "index_url": "https://pypi.org/simple",
        "artifacts": artifacts,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify public PyPI artifacts against an immutable release record."
    )
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--delay-seconds", type=float, default=10)
    parser.add_argument("--timeout-seconds", type=float, default=30)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        report = verify_public_pypi(
            release_tag=args.release_tag,
            manifest_path=args.manifest,
            checksums_path=args.checksums,
            output_dir=args.output_dir,
            attempts=args.attempts,
            delay_seconds=args.delay_seconds,
            timeout_seconds=args.timeout_seconds,
        )
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except PublicPyPIVerificationError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
