from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agent_runtime_governance.verify as verifier_module
from agent_runtime_governance import (
    ActionContract,
    Ed25519EvidenceSigner,
    EvidenceBundle,
    EvidenceExecution,
    EvidenceTrustRoot,
    EvidenceTrustRoots,
    ExecutionMode,
    ReconciliationEvidenceEntry,
    sign_evidence_bundle,
)
from agent_runtime_governance.verify import (
    EXIT_SUCCESS,
    EXIT_UNSUPPORTED,
    EXIT_VERIFICATION_FAILURE,
    main,
    verify_evidence_bundle_document,
)

_ROOT = Path(__file__).resolve().parents[1]
_PRIVATE_KEY = b"\x01" * 32
_IDENTITY_KEY = b"0123456789abcdef0123456789abcdef"


def _at(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 7, day, hour, tzinfo=timezone.utc)


def _bundle() -> EvidenceBundle:
    action = ActionContract(
        contract_id="ops.evidence.verify",
        contract_version=2,
        tool_name="verify_evidence",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        effect_class="governance.verify",
    ).bind(
        {"target": "external-ledger"},
        identity_issuer="issuer-v1",
        principal="principal-v1",
        tenant="tenant-v1",
        identity_digest_key=_IDENTITY_KEY,
        identity_digest_key_version="key-v1",
        policy_version="policy-v1",
        policy_digest="a" * 64,
    )
    return EvidenceBundle.from_bound_action(
        action,
        bundle_id="evidence-verifier-bundle-1",
        created_at=_at(3),
        execution=EvidenceExecution(
            execution_record_id="evidence-verifier-execution-1",
            status="succeeded",
            started_at=_at(2),
            finished_at=_at(2, 1),
        ),
        reconciliation=(
            ReconciliationEvidenceEntry(
                seq=1,
                prior_state="UNKNOWN",
                new_state="MANUAL_REVIEW",
                provider_id="receipt-probe-v1",
                evidence_kind="receipt",
                created_at=_at(2, 2),
            ),
            ReconciliationEvidenceEntry(
                seq=2,
                prior_state="MANUAL_REVIEW",
                new_state="CONFIRMED_SUCCEEDED",
                provider_id="manual-resolution-v1",
                evidence_kind="manual-resolution",
                created_at=_at(2, 3),
            ),
        ),
    )


def _root() -> EvidenceTrustRoot:
    private_key = Ed25519PrivateKey.from_private_bytes(_PRIVATE_KEY)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return EvidenceTrustRoot(
        key_id="evidence-key-1",
        algorithm="ed25519",
        public_key=base64.b64encode(public_key).decode("ascii"),
        not_before=_at(1),
        not_after=_at(10),
        revoked=False,
    )


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def _run_cli(
    bundle_path: Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_runtime_governance.verify",
            str(bundle_path),
            *arguments,
        ],
        cwd=_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _report(completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert completed.stderr == ""
    return json.loads(completed.stdout)


def _signed_inputs(tmp_path: Path) -> tuple[EvidenceBundle, Path, Path, Path]:
    bundle = _bundle()
    attachment = sign_evidence_bundle(
        bundle,
        Ed25519EvidenceSigner.from_private_key_bytes("evidence-key-1", _PRIVATE_KEY),
    )
    return (
        bundle,
        _write_json(tmp_path / "bundle.json", bundle.to_dict()),
        _write_json(tmp_path / "signature.json", attachment.to_dict()),
        _write_json(
            tmp_path / "trust-roots.json", EvidenceTrustRoots(keys=(_root(),)).to_dict()
        ),
    )


def test_library_verifier_and_main_share_signed_report_semantics(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle, bundle_path, signature_path, trust_roots_path = _signed_inputs(tmp_path)
    attachment = sign_evidence_bundle(
        bundle,
        Ed25519EvidenceSigner.from_private_key_bytes("evidence-key-1", _PRIVATE_KEY),
    )
    roots = EvidenceTrustRoots(keys=(_root(),))

    library_report = verify_evidence_bundle_document(
        bundle.to_dict(),
        signature=attachment,
        trust_roots=roots,
        expected_bundle_digest=bundle.bundle_digest,
        expected_tenant_digest=bundle.identity.tenant_digest,
        expected_policy_version=bundle.policy.version,
        expected_policy_digest=bundle.policy.digest,
        expected_contract_id=bundle.action.contract_id,
        expected_contract_version=bundle.action.contract_version,
        expected_contract_digest=bundle.action.contract_digest,
        verification_time=_at(3),
    )
    exit_code = main(
        [
            str(bundle_path),
            "--signature",
            str(signature_path),
            "--trust-roots",
            str(trust_roots_path),
            "--expected-bundle-digest",
            bundle.bundle_digest,
            "--at",
            "2026-07-03T00:00:00Z",
        ]
    )
    cli_report = json.loads(capsys.readouterr().out)

    assert library_report["integrity"]["ok"] is True
    assert library_report["authenticity"]["state"] == "passed"
    assert exit_code == EXIT_SUCCESS
    assert cli_report["integrity"]["bundle_digest"] == bundle.bundle_digest
    assert cli_report["authenticity"]["state"] == "passed"


def test_main_emits_json_reports_for_invalid_input_and_request_time(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text('{"bundle_id":"one","bundle_id":"two"}', encoding="utf-8")

    duplicate_exit = main([str(duplicate_path)])
    duplicate_report = json.loads(capsys.readouterr().out)

    bundle_path = _write_json(tmp_path / "bundle.json", _bundle().to_dict())
    time_exit = main([str(bundle_path), "--at", "not-a-timestamp"])
    time_report = json.loads(capsys.readouterr().out)

    assert duplicate_exit == EXIT_VERIFICATION_FAILURE
    assert duplicate_report["integrity"]["reasons"] == ["bundle_invalid_json"]
    assert time_exit == EXIT_VERIFICATION_FAILURE
    assert time_report["integrity"]["reasons"] == ["verification_time_invalid"]


def test_main_fails_closed_for_usage_unreadable_and_invalid_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    usage_exit = main([])
    usage_report = json.loads(capsys.readouterr().out)

    missing_exit = main([str(tmp_path / "missing.json")])
    missing_report = json.loads(capsys.readouterr().out)

    bundle_path = _write_json(tmp_path / "bundle.json", _bundle().to_dict())
    invalid_signature = _write_json(tmp_path / "signature.json", {"not": "valid"})
    invalid_roots = _write_json(tmp_path / "roots.json", {"not": "valid"})
    sidecar_exit = main(
        [
            str(bundle_path),
            "--signature",
            str(invalid_signature),
            "--trust-roots",
            str(invalid_roots),
        ]
    )
    sidecar_report = json.loads(capsys.readouterr().out)

    assert usage_exit == EXIT_VERIFICATION_FAILURE
    assert usage_report["integrity"]["reasons"] == ["cli_usage_invalid"]
    assert missing_exit == EXIT_VERIFICATION_FAILURE
    assert missing_report["integrity"]["reasons"] == ["bundle_unreadable"]
    assert sidecar_exit == EXIT_VERIFICATION_FAILURE
    assert sidecar_report["integrity"]["ok"] is False
    assert sidecar_report["integrity"]["reasons"] == [
        "signature_attachment_invalid",
    ]
    assert sidecar_report["integrity"]["commitment"] == {
        "ok": False,
        "reasons": ["signature_attachment_invalid"],
        "state": "failed",
    }
    assert sidecar_report["authenticity"] == {
        "ok": False,
        "reasons": ["signature_attachment_invalid", "trust_roots_invalid"],
        "state": "failed",
    }


@pytest.mark.parametrize(
    ("option", "filename", "document", "reason", "integrity_fails"),
    (
        pytest.param(
            "--signature",
            "signature.json",
            {"not": "valid"},
            "signature_attachment_invalid",
            True,
            id="signature",
        ),
        pytest.param(
            "--trust-roots",
            "roots.json",
            {"not": "valid"},
            "trust_roots_invalid",
            False,
            id="trust-roots",
        ),
    ),
)
def test_main_fails_closed_for_malformed_requested_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    option: str,
    filename: str,
    document: dict[str, str],
    reason: str,
    integrity_fails: bool,
) -> None:
    bundle_path = _write_json(tmp_path / "bundle.json", _bundle().to_dict())
    sidecar_path = _write_json(tmp_path / filename, document)

    exit_code = main([str(bundle_path), option, str(sidecar_path)])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_VERIFICATION_FAILURE
    if integrity_fails:
        assert report["integrity"]["reasons"] == [reason]
        assert report["integrity"]["commitment"] == {
            "ok": False,
            "reasons": [reason],
            "state": "failed",
        }
    else:
        assert report["integrity"]["ok"] is True
        assert report["integrity"]["reasons"] == []
        assert report["integrity"]["commitment"] == {
            "ok": None,
            "reasons": [],
            "state": "unanchored",
        }
    assert report["authenticity"] == {
        "ok": False,
        "reasons": [reason],
        "state": "failed",
    }


def test_main_keeps_signature_commitment_separate_from_invalid_trust_roots(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle, bundle_path, signature_path, _ = _signed_inputs(tmp_path)
    invalid_roots = _write_json(tmp_path / "roots.json", {"not": "valid"})

    exit_code = main(
        [
            str(bundle_path),
            "--signature",
            str(signature_path),
            "--trust-roots",
            str(invalid_roots),
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_VERIFICATION_FAILURE
    assert report["integrity"]["ok"] is True
    assert report["integrity"]["commitment"] == {
        "ok": True,
        "reasons": [],
        "state": "passed",
    }
    assert report["authenticity"] == {
        "ok": False,
        "reasons": ["trust_roots_invalid"],
        "state": "failed",
    }


def test_run_emits_at_most_one_json_report_when_stdout_breaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[str] = []

    def broken_print(value: str) -> None:
        emitted.append(value)
        raise BrokenPipeError

    monkeypatch.setattr(verifier_module, "print", broken_print, raising=False)
    monkeypatch.setattr(sys, "argv", ["verify"])

    assert verifier_module._run() == EXIT_VERIFICATION_FAILURE
    assert len(emitted) == 1
    assert '"cli_usage_invalid"' in emitted[0]


def test_library_verifier_fails_closed_for_bindings_and_incomplete_authentication() -> None:
    bundle = _bundle()
    attachment = sign_evidence_bundle(
        bundle,
        Ed25519EvidenceSigner.from_private_key_bytes("evidence-key-1", _PRIVATE_KEY),
    )
    roots = EvidenceTrustRoots(keys=(_root(),))

    bindings = verify_evidence_bundle_document(
        bundle.to_dict(),
        expected_bundle_digest="invalid",
        expected_tenant_digest="invalid",
        expected_policy_version="different-policy",
        expected_policy_digest="b" * 64,
        expected_contract_id="different-contract",
        expected_contract_version=0,
        expected_contract_digest="b" * 64,
    )
    missing_roots = verify_evidence_bundle_document(
        bundle.to_dict(), signature=attachment
    )
    missing_signature = verify_evidence_bundle_document(
        bundle.to_dict(), trust_roots=roots
    )
    malformed = verify_evidence_bundle_document(
        {}, signature=attachment, trust_roots=roots
    )

    assert bindings["integrity"]["reasons"] == [
        "expected_bundle_digest_invalid",
        "expected_tenant_digest_invalid",
        "policy_digest_mismatch",
        "contract_digest_mismatch",
        "policy_version_mismatch",
        "contract_id_mismatch",
        "expected_contract_version_invalid",
    ]
    assert missing_roots["authenticity"]["reasons"] == ["trust_roots_missing"]
    assert missing_signature["authenticity"]["reasons"] == [
        "signature_attachment_missing"
    ]
    assert malformed["integrity"]["reasons"] == ["bundle_invalid"]
    assert malformed["authenticity"]["state"] == "not_evaluated"


def test_cli_verifies_signed_bundle_and_never_claims_an_external_outcome(
    tmp_path: Path,
) -> None:
    bundle, bundle_path, signature_path, trust_roots_path = _signed_inputs(tmp_path)

    completed = _run_cli(
        bundle_path,
        "--signature",
        str(signature_path),
        "--trust-roots",
        str(trust_roots_path),
        "--at",
        "2026-07-03T00:00:00Z",
    )
    report = _report(completed)

    assert completed.returncode == EXIT_SUCCESS
    assert report["integrity"] == {
        "audit_continuity": {
            "ok": False,
            "reasons": ["anchor_verifier_unsupported"],
            "state": "unsupported",
        },
        "bundle_digest": bundle.bundle_digest,
        "commitment": {"ok": True, "reasons": [], "state": "passed"},
        "ok": True,
        "reasons": [],
        "state": "passed",
    }
    assert report["authenticity"] == {"ok": True, "reasons": [], "state": "passed"}
    assert report["outcome_verified"] == {
        "ok": False,
        "reasons": ["receipt_verifier_unsupported"],
        "state": "unsupported",
    }


def test_cli_marks_unsigned_bundle_as_unanchored_and_outcome_as_unsupported(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    bundle_path = _write_json(tmp_path / "bundle.json", bundle.to_dict())

    completed = _run_cli(bundle_path)
    report = _report(completed)

    assert completed.returncode == EXIT_SUCCESS
    assert report["integrity"]["commitment"] == {
        "ok": None,
        "reasons": [],
        "state": "unanchored",
    }
    assert report["authenticity"] == {
        "ok": None,
        "reasons": [],
        "state": "not_requested",
    }
    assert report["outcome_verified"]["state"] == "unsupported"


def test_cli_returns_unsupported_exit_code_when_outcome_is_requested(
    tmp_path: Path,
) -> None:
    bundle_path = _write_json(tmp_path / "unsigned-bundle.json", _bundle().to_dict())

    completed = _run_cli(bundle_path, "--require-outcome")
    report = _report(completed)

    assert completed.returncode == EXIT_UNSUPPORTED
    assert report["integrity"]["ok"] is True
    assert report["outcome_verified"]["state"] == "unsupported"


def test_cli_detects_mutation_against_detached_signature_and_expected_digest(
    tmp_path: Path,
) -> None:
    bundle, bundle_path, signature_path, trust_roots_path = _signed_inputs(tmp_path)
    mutated = bundle.to_dict()
    mutated["action"]["parameters_digest"] = "f" * 64
    _write_json(bundle_path, mutated)

    signed = _run_cli(
        bundle_path,
        "--signature",
        str(signature_path),
        "--trust-roots",
        str(trust_roots_path),
        "--at",
        "2026-07-03T00:00:00Z",
    )
    expected_digest = _run_cli(
        bundle_path,
        "--expected-bundle-digest",
        bundle.bundle_digest,
    )

    signed_report = _report(signed)
    expected_digest_report = _report(expected_digest)
    assert signed.returncode == EXIT_VERIFICATION_FAILURE
    assert signed_report["integrity"]["reasons"] == ["signature_bundle_digest_mismatch"]
    assert signed_report["authenticity"]["state"] == "failed"
    assert expected_digest.returncode == EXIT_VERIFICATION_FAILURE
    assert expected_digest_report["integrity"]["reasons"] == [
        "expected_bundle_digest_mismatch"
    ]


@pytest.mark.parametrize(
    ("option", "value", "reason"),
    [
        ("--expected-tenant-digest", "b" * 64, "tenant_digest_mismatch"),
        ("--expected-policy-digest", "b" * 64, "policy_digest_mismatch"),
        ("--expected-contract-digest", "b" * 64, "contract_digest_mismatch"),
    ],
)
def test_cli_detects_cross_tenant_and_stale_binding_substitution(
    tmp_path: Path,
    option: str,
    value: str,
    reason: str,
) -> None:
    bundle_path = _write_json(tmp_path / "bundle.json", _bundle().to_dict())

    completed = _run_cli(bundle_path, option, value)
    report = _report(completed)

    assert completed.returncode == EXIT_VERIFICATION_FAILURE
    assert report["integrity"]["reasons"] == [reason]
    assert report["authenticity"]["state"] == "not_requested"


@pytest.mark.parametrize(
    "mutation",
    ["reordered", "illegal_transition", "sequence_gap", "missing_genesis"],
)
def test_cli_rejects_broken_reconciliation_lineage(
    tmp_path: Path,
    mutation: str,
) -> None:
    document = _bundle().to_dict()
    reconciliation = document["reconciliation"]
    if mutation == "reordered":
        reconciliation.reverse()
    elif mutation == "illegal_transition":
        reconciliation[1]["new_state"] = "UNKNOWN"
    elif mutation == "missing_genesis":
        document["reconciliation"] = [
            {
                "seq": 1,
                "prior_state": "MANUAL_REVIEW",
                "new_state": "CONFIRMED_SUCCEEDED",
                "provider_id": "manual-resolution-v1",
                "evidence_kind": "manual-resolution",
                "created_at": "2026-07-02T02:00:00Z",
            }
        ]
    else:
        reconciliation[1]["seq"] = 3
    bundle_path = _write_json(tmp_path / "bundle.json", document)

    completed = _run_cli(bundle_path)
    report = _report(completed)

    assert completed.returncode == EXIT_VERIFICATION_FAILURE
    assert report["integrity"] == {
        "ok": False,
        "reasons": ["bundle_invalid"],
        "state": "failed",
    }


def test_cli_rejects_duplicate_json_keys_without_a_traceback(tmp_path: Path) -> None:
    document = _bundle().to_dict()
    encoded = json.dumps(document, sort_keys=True)
    duplicate = '{"bundle_id":"replacement",' + encoded.removeprefix("{")
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(duplicate, encoding="utf-8")

    completed = _run_cli(bundle_path)
    report = _report(completed)

    assert completed.returncode == EXIT_VERIFICATION_FAILURE
    assert report["integrity"] == {
        "ok": False,
        "reasons": ["bundle_invalid_json"],
        "state": "failed",
    }
    assert "Traceback" not in completed.stdout


@pytest.mark.parametrize("nonfinite", [float("nan"), float("inf"), float("-inf")])
def test_cli_rejects_nonfinite_json_without_a_traceback(
    tmp_path: Path,
    nonfinite: float,
) -> None:
    document = _bundle().to_dict()
    document["action"]["contract_version"] = nonfinite
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        json.dumps(document, sort_keys=True, allow_nan=True),
        encoding="utf-8",
    )

    completed = _run_cli(bundle_path)
    report = _report(completed)

    assert completed.returncode == EXIT_VERIFICATION_FAILURE
    assert report["integrity"] == {
        "ok": False,
        "reasons": ["bundle_invalid_json"],
        "state": "failed",
    }
    assert "Traceback" not in completed.stdout


def test_cli_honors_expired_trust_root_at_requested_time(tmp_path: Path) -> None:
    bundle, bundle_path, signature_path, _ = _signed_inputs(tmp_path)
    expired_root = _root()
    expired_roots = EvidenceTrustRoots(
        keys=(
            EvidenceTrustRoot(
                key_id=expired_root.key_id,
                algorithm=expired_root.algorithm,
                public_key=expired_root.public_key,
                not_before=expired_root.not_before,
                not_after=_at(3),
                revoked=False,
            ),
        )
    )
    roots_path = _write_json(tmp_path / "expired-roots.json", expired_roots.to_dict())

    completed = _run_cli(
        bundle_path,
        "--signature",
        str(signature_path),
        "--trust-roots",
        str(roots_path),
        "--at",
        "2026-07-03T00:00:00Z",
    )
    report = _report(completed)

    assert bundle.bundle_digest == report["integrity"]["bundle_digest"]
    assert completed.returncode == EXIT_VERIFICATION_FAILURE
    assert report["authenticity"] == {
        "ok": False,
        "reasons": ["signature_not_verified"],
        "state": "failed",
    }


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, (
        f"command failed: {' '.join(command)}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )
    return completed


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def test_wheel_and_sdist_execute_offline_verifier_entry_point(tmp_path: Path) -> None:
    distribution = tmp_path / "dist"
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--outdir",
            str(distribution),
        ],
        cwd=_ROOT,
    )
    bundle_path = _write_json(tmp_path / "unsigned-bundle.json", _bundle().to_dict())
    _, signed_bundle_path, signature_path, trust_roots_path = _signed_inputs(tmp_path)
    artifacts = [*distribution.glob("*.whl"), *distribution.glob("*.tar.gz")]
    assert len(artifacts) == 2

    for artifact in artifacts:
        venv = tmp_path / artifact.name.replace(".", "_")
        _run([sys.executable, "-m", "venv", str(venv)], cwd=tmp_path)
        python = _venv_python(venv)
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                str(artifact),
            ],
            cwd=tmp_path,
        )
        completed = subprocess.run(
            [
                str(python),
                "-I",
                "-m",
                "agent_runtime_governance.verify",
                str(bundle_path),
            ],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        report = _report(completed)
        assert completed.returncode == EXIT_SUCCESS
        assert report["integrity"]["ok"] is True
        assert report["authenticity"]["state"] == "not_requested"

        signed = subprocess.run(
            [
                str(python),
                "-I",
                "-m",
                "agent_runtime_governance.verify",
                str(signed_bundle_path),
                "--signature",
                str(signature_path),
                "--trust-roots",
                str(trust_roots_path),
                "--at",
                "2026-07-03T00:00:00Z",
            ],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        signed_report = _report(signed)
        assert signed.returncode == EXIT_UNSUPPORTED
        assert signed_report["integrity"]["ok"] is True
        assert signed_report["authenticity"] == {
            "ok": False,
            "reasons": ["ed25519_verifier_unavailable"],
            "state": "unsupported",
        }

        if artifact.suffix == ".whl":
            _run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    f"{artifact}[evidence]",
                ],
                cwd=tmp_path,
            )
            authenticated = subprocess.run(
                [
                    str(python),
                    "-I",
                    "-m",
                    "agent_runtime_governance.verify",
                    str(signed_bundle_path),
                    "--signature",
                    str(signature_path),
                    "--trust-roots",
                    str(trust_roots_path),
                    "--at",
                    "2026-07-03T00:00:00Z",
                ],
                cwd=tmp_path,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            authenticated_report = _report(authenticated)
            assert authenticated.returncode == EXIT_SUCCESS
            assert authenticated_report["authenticity"] == {
                "ok": True,
                "reasons": [],
                "state": "passed",
            }
