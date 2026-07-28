from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from importlib.resources import files
from pathlib import Path

import pytest

from agent_runtime_governance import EvidenceBundle, EvidenceBundleValidationError
from agent_runtime_governance.verify import EXIT_VERIFICATION_FAILURE, main

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_FIXTURE = _ROOT / "tests" / "fixtures" / "evidence" / "v1" / "bundle.json"
_FUTURE_FIXTURE = (
    _ROOT / "tests" / "fixtures" / "evidence" / "future" / "unsupported-v2-bundle.json"
)
_PACKAGE_FIXTURES = files("agent_runtime_governance").joinpath(
    "_compatibility", "evidence", "v1"
)


def _fixture() -> dict[str, object]:
    return json.loads(_PACKAGE_FIXTURES.joinpath("bundle.json").read_text("utf-8"))


def test_historical_v1_vector_is_packaged_and_byte_stable() -> None:
    fixture = _fixture()
    source = json.loads(_SOURCE_FIXTURE.read_text(encoding="utf-8"))
    canonical = bytes.fromhex(
        _PACKAGE_FIXTURES.joinpath("canonical-unsigned.hex").read_text("ascii").strip()
    )

    bundle = EvidenceBundle.from_dict(fixture["document"])

    assert fixture == source
    assert bundle.to_dict() == fixture["document"]
    assert bundle.canonical_unsigned_bytes() == canonical
    assert bundle.commitment_bytes() == b"arg.evidence.v1\0" + canonical
    assert bundle.bundle_digest == fixture["bundle_digest"]
    assert hashlib.sha256(bundle.commitment_bytes()).hexdigest() == fixture[
        "bundle_digest"
    ]
    assert bundle.to_dict()["signature"] is None
    assert bundle.to_dict()["execution"]["receipt"] is None


@pytest.mark.parametrize("version", ["2", "999"])
def test_future_bundle_versions_are_never_interpreted_as_v1(version: str) -> None:
    document = copy.deepcopy(_fixture()["document"])
    document["schema_version"] = version

    with pytest.raises(EvidenceBundleValidationError):
        EvidenceBundle.from_dict(document)


def test_physical_future_fixture_is_rejected_by_library_and_cli(
    capsys: pytest.CaptureFixture[str],
) -> None:
    document = json.loads(_FUTURE_FIXTURE.read_text(encoding="utf-8"))

    with pytest.raises(EvidenceBundleValidationError):
        EvidenceBundle.from_dict(document)

    exit_code = main([str(_FUTURE_FIXTURE)])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_VERIFICATION_FAILURE
    assert report["integrity"] == {
        "ok": False,
        "reasons": ["bundle_invalid"],
        "state": "failed",
    }

@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda document: document.__setitem__("future_field", "value"),
            id="unknown-top-level-field",
        ),
        pytest.param(
            lambda document: document["action"].__setitem__(
                "future_field", "value"
            ),
            id="unknown-nested-field",
        ),
        pytest.param(
            lambda document: document["execution"].__setitem__(
                "receipt", {"future": "receipt"}
            ),
            id="receipt-remains-null",
        ),
        pytest.param(
            lambda document: document.__setitem__("signature", {"future": "key"}),
            id="signature-remains-detached",
        ),
    ],
)
def test_v1_rejects_unknown_or_future_additive_semantics(mutation: object) -> None:
    document = copy.deepcopy(_fixture()["document"])

    mutation(document)

    with pytest.raises(EvidenceBundleValidationError):
        EvidenceBundle.from_dict(document)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(("schema_version",), id="schema-version"),
        pytest.param(("signature",), id="signature"),
        pytest.param(("action",), id="action"),
        pytest.param(("execution",), id="execution"),
        pytest.param(("action", "action_digest"), id="nested-action-digest"),
    ],
)
def test_v1_rejects_missing_required_fields(path: tuple[str, ...]) -> None:
    document = copy.deepcopy(_fixture()["document"])
    target = document
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]

    with pytest.raises(EvidenceBundleValidationError):
        EvidenceBundle.from_dict(document)


def test_restored_v1_projection_is_immutable_and_receipt_free() -> None:
    bundle = EvidenceBundle.from_dict(_fixture()["document"])

    with pytest.raises(FrozenInstanceError):
        bundle.bundle_id = "replacement"  # type: ignore[misc]

    projection = bundle.to_dict()
    assert set(projection) == {
        "action",
        "approval",
        "audit_anchor",
        "bundle_id",
        "created_at",
        "execution",
        "identity",
        "policy",
        "reconciliation",
        "redactions",
        "schema_version",
        "signature",
    }
    assert projection["execution"] == {
        "execution_record_id": "execution-record-1",
        "finished_at": "2026-07-02T02:00:00Z",
        "receipt": None,
        "started_at": "2026-07-02T01:00:00Z",
        "status": "succeeded",
    }
