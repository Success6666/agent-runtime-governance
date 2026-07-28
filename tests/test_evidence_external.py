from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import agent_runtime_governance.verify as verifier_module
from agent_runtime_governance import (
    ActionContract,
    EvidenceBundle,
    EvidenceExecution,
    ExecutionMode,
)
from agent_runtime_governance.evidence_external import (
    ANCHOR_PROVIDER_ENTRY_POINT_GROUP,
    RECEIPT_VERIFIER_ENTRY_POINT_GROUP,
    AnchorSequenceEntry,
    AnchorVerificationRequest,
    AnchorVerificationResult,
    EvidenceExternalValidationError,
    InMemoryAnchorProvider,
    InMemoryReceiptVerifier,
    ReceiptAttachment,
    ReceiptVerificationExpectation,
    ReceiptVerificationRequest,
    ReceiptVerificationResult,
    UnsupportedReceiptVerifier,
)
from agent_runtime_governance.verify import (
    EXIT_SUCCESS,
    EXIT_UNSUPPORTED,
    EXIT_VERIFICATION_FAILURE,
    main,
    verify_evidence_bundle_document,
)

_IDENTITY_KEY = b"0123456789abcdef0123456789abcdef"


def _at(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 7, day, hour, tzinfo=timezone.utc)


def _bundle(
    *,
    tenant: str = "tenant-v1",
    bundle_id: str = "evidence-external-bundle-1",
    status: str = "succeeded",
) -> EvidenceBundle:
    action = ActionContract(
        contract_id="ops.evidence.external",
        contract_version=1,
        tool_name="external_receipt",
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
        tenant=tenant,
        identity_digest_key=_IDENTITY_KEY,
        identity_digest_key_version="key-v1",
        policy_version="policy-v1",
        policy_digest="a" * 64,
    )
    return EvidenceBundle.from_bound_action(
        action,
        bundle_id=bundle_id,
        created_at=_at(3),
        execution=EvidenceExecution(
            execution_record_id="evidence-external-execution-1",
            status=status,
            started_at=_at(2),
            finished_at=_at(2, 1),
        ),
    )


def _entry(position: int, label: str) -> AnchorSequenceEntry:
    return AnchorSequenceEntry(
        position=position,
        bundle_id=f"evidence-anchor-{label}",
        bundle_digest=(label * 64)[:64],
    )


def _anchor_request(
    bundle: EvidenceBundle, entries: tuple[AnchorSequenceEntry, ...]
) -> AnchorVerificationRequest:
    return AnchorVerificationRequest(
        sequence_id="production-sequence-v1",
        entries=entries,
        subject_bundle_id=bundle.bundle_id,
        subject_bundle_digest=bundle.bundle_digest,
        tenant_digest=bundle.identity.tenant_digest,
    )


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def test_anchor_provider_detects_deletion_and_reordering_without_changing_bundle() -> None:
    bundle = _bundle()
    first = _entry(1, "1")
    middle = _entry(2, "2")
    subject = AnchorSequenceEntry(3, bundle.bundle_id, bundle.bundle_digest)
    provider = InMemoryAnchorProvider(
        sequence_id="production-sequence-v1",
        tenant_digest=bundle.identity.tenant_digest,
        protected_entries=(first, middle, subject),
    )

    matching = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=provider,
        anchor_request=_anchor_request(bundle, (first, middle, subject)),
    )
    deleted_subject = AnchorSequenceEntry(2, bundle.bundle_id, bundle.bundle_digest)
    deleted = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=provider,
        anchor_request=_anchor_request(bundle, (first, deleted_subject)),
    )
    reordered_middle = AnchorSequenceEntry(3, middle.bundle_id, middle.bundle_digest)
    reordered_subject = AnchorSequenceEntry(2, bundle.bundle_id, bundle.bundle_digest)
    reordered = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=provider,
        anchor_request=_anchor_request(
            bundle,
            (first, reordered_subject, reordered_middle),
        ),
    )

    assert matching["integrity"]["ok"] is True
    assert matching["integrity"]["audit_continuity"] == {
        "ok": True,
        "provider_id": "in-memory-anchor-v1",
        "provider_protocol_version": "1",
        "reasons": [],
        "state": "passed",
    }
    assert deleted["integrity"]["reasons"] == ["anchor_sequence_deletion_detected"]
    assert deleted["integrity"]["audit_continuity"]["state"] == "failed"
    assert reordered["integrity"]["reasons"] == ["anchor_sequence_reordered"]
    assert reordered["integrity"]["audit_continuity"]["state"] == "failed"
    assert bundle.to_dict()["execution"]["receipt"] is None
    assert "anchor" not in bundle.to_dict()


def test_anchor_request_is_strict_and_binds_the_subject_before_provider_entry() -> None:
    bundle = _bundle()
    subject = AnchorSequenceEntry(1, bundle.bundle_id, bundle.bundle_digest)
    provider = InMemoryAnchorProvider(
        sequence_id="production-sequence-v1",
        tenant_digest=bundle.identity.tenant_digest,
        protected_entries=(subject,),
    )
    request = _anchor_request(bundle, (subject,))
    document = request.to_dict()

    assert AnchorVerificationRequest.from_dict(document) == request
    with pytest.raises(EvidenceExternalValidationError, match="fields are invalid"):
        AnchorVerificationRequest.from_dict({**document, "provider_payload": "secret"})
    with pytest.raises(EvidenceExternalValidationError, match="contiguous"):
        _anchor_request(
            bundle,
            (
                AnchorSequenceEntry(1, "one", "1" * 64),
                AnchorSequenceEntry(3, bundle.bundle_id, bundle.bundle_digest),
            ),
        )

    wrong_subject = AnchorVerificationRequest(
        sequence_id=request.sequence_id,
        entries=(subject,),
        subject_bundle_id="different-bundle",
        subject_bundle_digest=bundle.bundle_digest,
        tenant_digest=bundle.identity.tenant_digest,
    )
    report = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=provider,
        anchor_request=wrong_subject,
    )
    wrong_sequence = AnchorVerificationRequest(
        sequence_id="another-sequence-v1",
        entries=(subject,),
        subject_bundle_id=bundle.bundle_id,
        subject_bundle_digest=bundle.bundle_digest,
        tenant_digest=bundle.identity.tenant_digest,
    )
    wrong_tenant = AnchorVerificationRequest(
        sequence_id=request.sequence_id,
        entries=(subject,),
        subject_bundle_id=bundle.bundle_id,
        subject_bundle_digest=bundle.bundle_digest,
        tenant_digest="b" * 64,
    )
    unavailable = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=provider,
        anchor_request=wrong_sequence,
    )
    cross_tenant = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=provider,
        anchor_request=wrong_tenant,
    )

    assert report["integrity"]["reasons"] == ["anchor_subject_bundle_mismatch"]
    assert report["integrity"]["audit_continuity"]["state"] == "failed"
    assert unavailable["integrity"]["audit_continuity"]["reasons"] == [
        "anchor_sequence_unavailable"
    ]
    assert cross_tenant["integrity"]["reasons"] == ["anchor_tenant_digest_mismatch"]


def test_absent_or_unsupported_anchor_never_claims_continuity() -> None:
    bundle = _bundle()
    subject = AnchorSequenceEntry(1, bundle.bundle_id, bundle.bundle_digest)
    request = _anchor_request(bundle, (subject,))

    default = verify_evidence_bundle_document(bundle.to_dict())
    requested = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_request=request,
    )
    unavailable = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_input_reasons=("anchor_provider_unavailable",),
        anchor_requested=True,
    )

    assert default["integrity"]["audit_continuity"] == {
        "ok": False,
        "reasons": ["anchor_verifier_unsupported"],
        "state": "unsupported",
    }
    assert requested["integrity"]["audit_continuity"] == {
        "ok": False,
        "reasons": ["anchor_provider_missing"],
        "state": "unsupported",
    }
    assert unavailable["integrity"]["audit_continuity"] == {
        "ok": False,
        "reasons": ["anchor_provider_unavailable"],
        "state": "unsupported",
    }


def test_receipt_verifier_projects_only_bounded_identity_and_never_leaks_receipt() -> None:
    bundle = _bundle()
    raw_receipt = b"receipt-secret-v1"
    attachment = ReceiptAttachment(
        bundle_digest=bundle.bundle_digest,
        value=base64.b64encode(raw_receipt).decode("ascii"),
    )
    request = ReceiptVerificationRequest.from_bundle(bundle, attachment)
    verifier = InMemoryReceiptVerifier(
        (ReceiptVerificationExpectation.from_request(request, outcome="succeeded"),)
    )

    report = verify_evidence_bundle_document(
        bundle.to_dict(),
        receipt_verifier=verifier,
        receipt=attachment,
    )

    assert report["outcome_verified"] == {
        "ok": True,
        "outcome": "succeeded",
        "reasons": [],
        "state": "passed",
        "verifier_id": "in-memory-receipt-verifier-v1",
        "verifier_protocol_version": "1",
    }
    assert raw_receipt.decode("ascii") not in json.dumps(report)
    assert attachment.value not in repr(attachment)
    assert attachment.value not in json.dumps(bundle.to_dict())
    assert bundle.to_dict()["execution"]["receipt"] is None


def test_receipt_binding_and_outcome_disagreement_fail_closed() -> None:
    bundle = _bundle()
    raw_receipt = b"receipt-v1"
    mismatched_attachment = ReceiptAttachment(
        bundle_digest="b" * 64,
        value=base64.b64encode(raw_receipt).decode("ascii"),
    )
    wrong_outcome_attachment = ReceiptAttachment(
        bundle_digest=bundle.bundle_digest,
        value=base64.b64encode(raw_receipt).decode("ascii"),
    )
    verifier = InMemoryReceiptVerifier(
        (
            ReceiptVerificationExpectation.from_request(
                ReceiptVerificationRequest.from_bundle(bundle, wrong_outcome_attachment),
                outcome="failed",
            ),
        )
    )

    mismatched = verify_evidence_bundle_document(
        bundle.to_dict(),
        receipt_verifier=verifier,
        receipt=mismatched_attachment,
    )
    wrong_outcome = verify_evidence_bundle_document(
        bundle.to_dict(),
        receipt_verifier=verifier,
        receipt=wrong_outcome_attachment,
    )
    unsupported = verify_evidence_bundle_document(
        bundle.to_dict(),
        receipt_verifier=UnsupportedReceiptVerifier(),
        receipt=wrong_outcome_attachment,
    )

    assert mismatched["outcome_verified"]["reasons"] == [
        "receipt_bundle_digest_mismatch"
    ]
    assert wrong_outcome["outcome_verified"]["reasons"] == [
        "receipt_outcome_mismatch"
    ]
    assert unsupported["outcome_verified"] == {
        "ok": False,
        "reasons": ["receipt_verifier_unsupported"],
        "state": "unsupported",
        "verifier_id": "unsupported-receipt-verifier-v1",
        "verifier_protocol_version": "1",
    }


def test_reference_receipt_verifier_binds_bundle_and_tenant_identity() -> None:
    raw_receipt = b"receipt-v1"
    original = _bundle()
    original_attachment = ReceiptAttachment(
        bundle_digest=original.bundle_digest,
        value=base64.b64encode(raw_receipt).decode("ascii"),
    )
    original_request = ReceiptVerificationRequest.from_bundle(
        original,
        original_attachment,
    )
    verifier = InMemoryReceiptVerifier(
        (ReceiptVerificationExpectation.from_request(original_request, outcome="succeeded"),)
    )
    substituted = _bundle(
        tenant="tenant-v2",
        bundle_id="evidence-external-bundle-2",
    )
    substituted_attachment = ReceiptAttachment(
        bundle_digest=substituted.bundle_digest,
        value=base64.b64encode(raw_receipt).decode("ascii"),
    )
    substituted_request = ReceiptVerificationRequest.from_bundle(
        substituted,
        substituted_attachment,
    )

    report = verify_evidence_bundle_document(
        substituted.to_dict(),
        receipt_verifier=verifier,
        receipt=substituted_attachment,
    )

    assert original_request.binding_digest != substituted_request.binding_digest
    assert report["outcome_verified"]["reasons"] == ["receipt_not_found"]


def test_receipt_can_resolve_an_unknown_recorded_execution_status() -> None:
    bundle = _bundle(status="unknown")
    raw_receipt = b"receipt-v1"
    attachment = ReceiptAttachment(
        bundle_digest=bundle.bundle_digest,
        value=base64.b64encode(raw_receipt).decode("ascii"),
    )
    request = ReceiptVerificationRequest.from_bundle(bundle, attachment)
    verifier = InMemoryReceiptVerifier(
        (ReceiptVerificationExpectation.from_request(request, outcome="succeeded"),)
    )

    report = verify_evidence_bundle_document(
        bundle.to_dict(),
        receipt_verifier=verifier,
        receipt=attachment,
    )

    assert report["outcome_verified"] == {
        "ok": True,
        "outcome": "succeeded",
        "recorded_execution_status": "unknown",
        "reasons": [],
        "state": "passed",
        "verifier_id": "in-memory-receipt-verifier-v1",
        "verifier_protocol_version": "1",
    }


class _AnchorEntryPoint:
    def __init__(self, name: str, provider: object) -> None:
        self.name = name
        self._provider = provider
        self.loaded = False

    def load(self) -> object:
        self.loaded = True
        print("entrypoint-output-must-not-reach-json")
        return self._provider


class _EntryPoints:
    def __init__(self, entries: tuple[_AnchorEntryPoint, ...]) -> None:
        self._entries = entries
        self.groups: list[str] = []

    def select(self, *, group: str) -> tuple[_AnchorEntryPoint, ...]:
        self.groups.append(group)
        return self._entries


class _NoisyAnchorProvider:
    @property
    def provider_id(self) -> str:
        print("provider-metadata-output-must-not-reach-json")
        return "test-anchor-provider-v1"

    @property
    def protocol_version(self) -> str:
        print("provider-protocol-output-must-not-reach-json")
        return "1"

    def verify_continuity(
        self, request: AnchorVerificationRequest
    ) -> AnchorVerificationResult:
        print("provider-output-must-not-reach-json")
        return AnchorVerificationResult("passed")


class _NoisyReceiptVerifier:
    verifier_id = "test-receipt-verifier-v1"
    protocol_version = "1"

    def verify(self, request: object) -> ReceiptVerificationResult:
        print("receipt-output-must-not-reach-json")
        return ReceiptVerificationResult("passed", outcome="succeeded")


def test_cli_loads_only_selected_provider_and_preserves_one_json_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _bundle()
    subject = AnchorSequenceEntry(1, bundle.bundle_id, bundle.bundle_digest)
    bundle_path = _write_json(tmp_path / "bundle.json", bundle.to_dict())
    sequence_path = _write_json(
        tmp_path / "sequence.json",
        _anchor_request(bundle, (subject,)).to_dict(),
    )
    selected = _AnchorEntryPoint("selected-anchor", _NoisyAnchorProvider)
    unselected = _AnchorEntryPoint("unselected-anchor", _NoisyAnchorProvider)
    entries = _EntryPoints((selected, unselected))
    monkeypatch.setattr(verifier_module.metadata, "entry_points", lambda: entries)

    exit_code = main(
        [
            str(bundle_path),
            "--anchor-provider",
            "selected-anchor",
            "--anchor-sequence",
            str(sequence_path),
        ]
    )
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert exit_code == EXIT_SUCCESS
    assert output.err == ""
    assert "provider-output" not in output.out
    assert "provider-metadata-output" not in output.out
    assert "provider-protocol-output" not in output.out
    assert "entrypoint-output" not in output.out
    assert report["integrity"]["audit_continuity"]["state"] == "passed"
    assert selected.loaded is True
    assert unselected.loaded is False
    assert entries.groups == [ANCHOR_PROVIDER_ENTRY_POINT_GROUP]


class _MalformedResultAnchorProvider:
    provider_id = "malformed-result-provider-v1"
    protocol_version = "1"

    def verify_continuity(
        self, request: AnchorVerificationRequest
    ) -> AnchorVerificationResult:
        return object.__new__(AnchorVerificationResult)


class _OpaqueReasonAnchorProvider:
    provider_id = "opaque-reason-provider-v1"
    protocol_version = "1"

    def verify_continuity(
        self, request: AnchorVerificationRequest
    ) -> AnchorVerificationResult:
        return AnchorVerificationResult("failed", "encoded-secret-value")


class _AsyncAnchorProvider:
    provider_id = "async-anchor-provider-v1"
    protocol_version = "1"

    async def verify_continuity(
        self, request: AnchorVerificationRequest
    ) -> AnchorVerificationResult:
        return AnchorVerificationResult("passed")


def test_provider_result_is_normalized_without_leaking_or_leaving_coroutines() -> None:
    bundle = _bundle()
    subject = AnchorSequenceEntry(1, bundle.bundle_id, bundle.bundle_digest)
    request = _anchor_request(bundle, (subject,))

    malformed = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=_MalformedResultAnchorProvider(),
        anchor_request=request,
    )
    opaque = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=_OpaqueReasonAnchorProvider(),
        anchor_request=request,
    )
    asynchronous = verify_evidence_bundle_document(
        bundle.to_dict(),
        anchor_provider=_AsyncAnchorProvider(),
        anchor_request=request,
    )

    assert malformed["integrity"]["audit_continuity"]["reasons"] == [
        "anchor_provider_invalid_result"
    ]
    assert opaque["integrity"]["audit_continuity"]["reasons"] == [
        "anchor_provider_not_verified"
    ]
    assert "encoded-secret-value" not in json.dumps(opaque)
    assert asynchronous["integrity"]["audit_continuity"]["reasons"] == [
        "anchor_provider_async_unsupported"
    ]


def test_cli_returns_stable_external_provider_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _bundle()
    raw_receipt = b"receipt-v1"
    bundle_path = _write_json(tmp_path / "bundle.json", bundle.to_dict())
    subject = AnchorSequenceEntry(1, bundle.bundle_id, bundle.bundle_digest)
    sequence_path = _write_json(
        tmp_path / "sequence.json",
        _anchor_request(bundle, (subject,)).to_dict(),
    )
    receipt_path = _write_json(
        tmp_path / "receipt.json",
        ReceiptAttachment(
            bundle_digest=bundle.bundle_digest,
            value=base64.b64encode(raw_receipt).decode("ascii"),
        ).to_dict(),
    )
    receipt_entry = _AnchorEntryPoint("receipt-provider", _NoisyReceiptVerifier)
    entries = _EntryPoints((receipt_entry,))
    monkeypatch.setattr(verifier_module.metadata, "entry_points", lambda: entries)

    unavailable_exit = main(
        [
            str(bundle_path),
            "--anchor-provider",
            "not-installed",
            "--anchor-sequence",
            str(sequence_path),
        ]
    )
    unavailable = json.loads(capsys.readouterr().out)
    receipt_exit = main(
        [
            str(bundle_path),
            "--receipt-verifier",
            "receipt-provider",
            "--receipt",
            str(receipt_path),
        ]
    )
    receipt = json.loads(capsys.readouterr().out)

    assert unavailable_exit == EXIT_UNSUPPORTED
    assert unavailable["integrity"]["audit_continuity"]["reasons"] == [
        "anchor_provider_unavailable"
    ]
    assert receipt_exit == EXIT_SUCCESS
    assert receipt["outcome_verified"]["state"] == "passed"
    assert entries.groups == [
        ANCHOR_PROVIDER_ENTRY_POINT_GROUP,
        RECEIPT_VERIFIER_ENTRY_POINT_GROUP,
    ]


def test_cli_never_imports_a_provider_for_invalid_or_incomplete_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invalid_bundle_path = _write_json(tmp_path / "invalid-bundle.json", {"no": "v1"})
    unrelated = AnchorSequenceEntry(1, "other-bundle", "a" * 64)
    sequence_path = _write_json(
        tmp_path / "sequence.json",
        AnchorVerificationRequest(
            sequence_id="production-sequence-v1",
            entries=(unrelated,),
            subject_bundle_id=unrelated.bundle_id,
            subject_bundle_digest=unrelated.bundle_digest,
            tenant_digest="b" * 64,
        ).to_dict(),
    )
    entry = _AnchorEntryPoint("selected-anchor", _NoisyAnchorProvider)
    monkeypatch.setattr(
        verifier_module.metadata,
        "entry_points",
        lambda: _EntryPoints((entry,)),
    )

    invalid_exit = main(
        [
            str(invalid_bundle_path),
            "--anchor-provider",
            "selected-anchor",
            "--anchor-sequence",
            str(sequence_path),
        ]
    )
    invalid_report = json.loads(capsys.readouterr().out)
    valid_bundle_path = _write_json(tmp_path / "bundle.json", _bundle().to_dict())
    incomplete_exit = main(
        [str(valid_bundle_path), "--anchor-provider", "selected-anchor"]
    )
    incomplete_report = json.loads(capsys.readouterr().out)

    assert invalid_exit == EXIT_VERIFICATION_FAILURE
    assert invalid_report["integrity"]["reasons"] == ["bundle_invalid"]
    assert incomplete_exit == EXIT_UNSUPPORTED
    assert incomplete_report["integrity"]["audit_continuity"]["reasons"] == [
        "anchor_provider_missing"
    ]
    assert entry.loaded is False


def test_cli_fails_closed_for_malformed_external_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = _bundle()
    bundle_path = _write_json(tmp_path / "bundle.json", bundle.to_dict())
    invalid_sequence = _write_json(tmp_path / "sequence.json", {"invalid": True})
    invalid_receipt = _write_json(tmp_path / "receipt.json", {"invalid": True})

    anchor = main([str(bundle_path), "--anchor-sequence", str(invalid_sequence)])
    anchor_report = json.loads(capsys.readouterr().out)
    receipt = main([str(bundle_path), "--receipt", str(invalid_receipt)])
    receipt_report = json.loads(capsys.readouterr().out)

    assert anchor == EXIT_VERIFICATION_FAILURE
    assert receipt == EXIT_VERIFICATION_FAILURE
    assert anchor_report["integrity"]["audit_continuity"]["reasons"] == [
        "anchor_sequence_invalid"
    ]
    assert receipt_report["outcome_verified"]["reasons"] == [
        "receipt_attachment_invalid"
    ]
