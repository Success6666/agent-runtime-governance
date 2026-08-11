from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "verify_public_pypi.py"
VERSION = "0.9.1"
RELEASE_TAG = f"v{VERSION}"
SOURCE_COMMIT = "a" * 40


@pytest.fixture
def verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_public_pypi", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _release_record(tmp_path: Path) -> tuple[Path, Path, dict[str, bytes]]:
    artifacts = {
        f"agent_runtime_governance-{VERSION}-py3-none-any.whl": b"wheel payload",
        f"agent_runtime_governance-{VERSION}.tar.gz": b"sdist payload",
    }
    artifact_entries = {}
    checksum_lines = []
    for kind, filename in zip(("wheel", "sdist"), artifacts, strict=True):
        digest = hashlib.sha256(artifacts[filename]).hexdigest()
        artifact_path = f"dist/{filename}"
        artifact_entries[kind] = {"path": artifact_path, "sha256": digest}
        checksum_lines.append(f"{digest}  {artifact_path}")
    manifest = {
        "release": {
            "tag": RELEASE_TAG,
            "package_version": VERSION,
            "source_commit": SOURCE_COMMIT,
        },
        "artifacts": artifact_entries,
        "provenance": {
            "source_ref": f"refs/tags/{RELEASE_TAG}",
            "source_commit": SOURCE_COMMIT,
        },
    }
    manifest_path = tmp_path / "release-manifest.json"
    checksums_path = tmp_path / "SHA256SUMS"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    checksums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    return manifest_path, checksums_path, artifacts


def _public_document(artifacts: dict[str, bytes]) -> dict[str, object]:
    urls = []
    for filename, payload in artifacts.items():
        urls.append(
            {
                "filename": filename,
                "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
                "digests": {"sha256": hashlib.sha256(payload).hexdigest()},
                "size": len(payload),
                "url": f"https://files.pythonhosted.org/packages/example/{filename}",
                "yanked": False,
            }
        )
    return {"urls": urls}


def test_public_artifacts_match_release_manifest_and_downloaded_bytes(
    tmp_path: Path,
    verifier: ModuleType,
) -> None:
    manifest_path, checksums_path, payloads = _release_record(tmp_path)
    version, source_commit, expected = verifier.load_release_record(
        manifest_path,
        checksums_path,
        RELEASE_TAG,
    )
    public = verifier.select_public_artifacts(_public_document(payloads), expected)
    by_url = {artifact.url: payloads[filename] for filename, artifact in public.items()}
    byte_limits: dict[str, int] = {}

    def fetch_bytes(url: str, _timeout: float, max_bytes: int) -> bytes:
        byte_limits[url] = max_bytes
        return by_url[url]

    results = verifier.download_and_verify(
        public,
        tmp_path / "downloaded",
        timeout_seconds=1,
        fetch_bytes=fetch_bytes,
    )

    assert version == VERSION
    assert source_commit == SOURCE_COMMIT
    assert byte_limits == {artifact.url: artifact.size for artifact in public.values()}
    assert {item["filename"] for item in results} == set(payloads)
    assert {item["kind"] for item in results} == {"wheel", "sdist"}
    for item in results:
        payload = payloads[item["filename"]]
        assert item["sha256"] == hashlib.sha256(payload).hexdigest()
        assert item["size"] == len(payload)
    for filename, payload in payloads.items():
        assert (tmp_path / "downloaded" / filename).read_bytes() == payload


def test_public_artifact_digest_mismatch_is_rejected(
    tmp_path: Path,
    verifier: ModuleType,
) -> None:
    manifest_path, checksums_path, payloads = _release_record(tmp_path)
    _, _, expected = verifier.load_release_record(
        manifest_path,
        checksums_path,
        RELEASE_TAG,
    )
    document = _public_document(payloads)
    document["urls"][0]["digests"]["sha256"] = "b" * 64

    with pytest.raises(
        verifier.PublicPyPIVerificationError,
        match="does not match the release record",
    ):
        verifier.select_public_artifacts(document, expected)


def test_public_index_retry_only_waits_for_missing_release_files(
    tmp_path: Path,
    verifier: ModuleType,
) -> None:
    manifest_path, checksums_path, payloads = _release_record(tmp_path)
    _, _, expected = verifier.load_release_record(
        manifest_path,
        checksums_path,
        RELEASE_TAG,
    )
    responses = iter(({"urls": []}, _public_document(payloads)))

    selected = verifier.wait_for_public_artifacts(
        VERSION,
        expected,
        attempts=2,
        delay_seconds=0,
        timeout_seconds=1,
        fetch_json=lambda _url, _timeout: next(responses),
    )

    assert set(selected) == set(payloads)


def test_release_record_must_be_bound_to_the_requested_tag(
    tmp_path: Path,
    verifier: ModuleType,
) -> None:
    manifest_path, checksums_path, _ = _release_record(tmp_path)

    with pytest.raises(
        verifier.PublicPyPIVerificationError,
        match="tag and package version",
    ):
        verifier.load_release_record(manifest_path, checksums_path, "v0.9.0")


def test_release_record_package_version_must_match_the_requested_tag(
    tmp_path: Path,
    verifier: ModuleType,
) -> None:
    manifest_path, checksums_path, _ = _release_record(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["release"]["package_version"] = "0.9.0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(
        verifier.PublicPyPIVerificationError,
        match="tag and package version",
    ):
        verifier.load_release_record(manifest_path, checksums_path, RELEASE_TAG)


def test_untrusted_artifact_url_is_rejected(tmp_path: Path, verifier: ModuleType) -> None:
    manifest, checksums, payloads = _release_record(tmp_path)
    _, _, expected = verifier.load_release_record(manifest, checksums, RELEASE_TAG)
    document = _public_document(payloads)
    document["urls"][0]["url"] = "https://files.pythonhosted.org.evil.example/x.whl"
    with pytest.raises(verifier.PublicPyPIVerificationError, match="not trusted"):
        verifier.select_public_artifacts(document, expected)


def test_downloaded_bytes_must_match_metadata(tmp_path: Path, verifier: ModuleType) -> None:
    manifest, checksums, payloads = _release_record(tmp_path)
    _, _, expected = verifier.load_release_record(manifest, checksums, RELEASE_TAG)
    public = verifier.select_public_artifacts(_public_document(payloads), expected)
    with pytest.raises(verifier.PublicPyPIVerificationError, match="does not match metadata"):
        verifier.download_and_verify(
            public,
            tmp_path / "tampered",
            timeout_seconds=1,
            fetch_bytes=lambda _url, _timeout, _max_bytes: b"tampered",
        )


def test_manifest_digest_must_match_checksums(tmp_path: Path, verifier: ModuleType) -> None:
    manifest, checksums, _ = _release_record(tmp_path)
    lines = checksums.read_text(encoding="utf-8").splitlines()
    checksums.write_text("c" * 64 + lines[0][64:] + "\n" + lines[1] + "\n", encoding="utf-8")
    with pytest.raises(verifier.PublicPyPIVerificationError, match="does not match SHA256SUMS"):
        verifier.load_release_record(manifest, checksums, RELEASE_TAG)
