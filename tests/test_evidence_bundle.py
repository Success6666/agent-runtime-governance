from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import agent_runtime_governance.evidence as evidence_module
from agent_runtime_governance import (
    EVIDENCE_BUNDLE_SCHEMA_V1,
    ActionContract,
    ApprovalRequest,
    AuditAnchor,
    BoundAction,
    DecisionOutcome,
    DecisionRecord,
    EvidenceBundle,
    EvidenceBundleValidationError,
    EvidenceExecution,
    ExecutionMode,
    ReconciliationEvidenceEntry,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "evidence" / "v1" / "bundle.json"
_CANONICAL_FIXTURE = _FIXTURE.with_name("canonical-unsigned.hex")
_IDENTITY_KEY = b"0123456789abcdef0123456789abcdef"
_POLICY_DIGEST = "a" * 64
_PRECONDITION_DIGEST = "b" * 64
_AUDIT_HASH = "c" * 64


def _at(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 7, day, hour, tzinfo=timezone.utc)


def _action(*, secret: str = "tool-parameter-secret") -> BoundAction:
    contract = ActionContract(
        contract_id="ops.evidence.export",
        contract_version=2,
        tool_name="export_evidence",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "secret": {"type": "string"},
            },
            "required": ["target", "secret"],
            "additionalProperties": False,
        },
        effect_class="governance.export",
        precondition_requirements=("record.version",),
    )
    return contract.bind(
        {"target": "external-ledger", "secret": secret},
        identity_issuer="issuer:privacy-secret",
        principal="principal:privacy-secret",
        tenant="tenant:privacy-secret",
        identity_digest_key=_IDENTITY_KEY,
        identity_digest_key_version="key-v1",
        policy_version="policy-v1",
        policy_digest=_POLICY_DIGEST,
        precondition_digest=_PRECONDITION_DIGEST,
    )


def _approval(action: BoundAction) -> tuple[ApprovalRequest, DecisionRecord]:
    request = ApprovalRequest(
        trace_id="trace-evidence-1",
        request_id="approval-request-1",
        tool_name=action.contract.tool_name,
        arguments={"confirmation": "approval-argument-secret"},
        risk_tier="HIGH",
        reason="approval-request-reason-secret",
        issued_at="2026-07-01T00:00:00+00:00",
        expires_at="2026-07-04T00:00:00+00:00",
        policy_version=action.policy_version,
        policy_digest=action.policy_digest,
        subject="approval-subject-secret",
        tenant="approval-tenant-secret",
        identity_issuer="approval-issuer-secret",
        action_digest=action.action_digest,
    )
    decision = DecisionRecord(
        outcome=DecisionOutcome.ALLOW,
        reason="approval-decision-reason-secret",
        source="approval-source-secret",
        approver="approval-approver-secret",
        decision_id="approval-decision-1",
        issued_at="2026-07-02T00:00:00+00:00",
    )
    return request, decision


def _bundle(action: BoundAction | None = None) -> EvidenceBundle:
    bound_action = action or _action()
    request, decision = _approval(bound_action)
    return EvidenceBundle.from_bound_action(
        bound_action,
        bundle_id="evidence-bundle-1",
        created_at=_at(3),
        approval_request=request,
        decision=decision,
        execution=EvidenceExecution(
            execution_record_id="execution-record-1",
            status="succeeded",
            started_at=_at(2, 1),
            finished_at=_at(2, 2),
        ),
        reconciliation=(
            ReconciliationEvidenceEntry(
                seq=1,
                prior_state="UNKNOWN",
                new_state="MANUAL_REVIEW",
                provider_id="receipt-probe-v1",
                evidence_kind="receipt",
                created_at=_at(2, 3),
            ),
            ReconciliationEvidenceEntry(
                seq=2,
                prior_state="MANUAL_REVIEW",
                new_state="CONFIRMED_SUCCEEDED",
                evidence_kind="manual-resolution",
                created_at=_at(2, 4),
            ),
        ),
        audit_anchor=AuditAnchor(chain_head_hash=_AUDIT_HASH, record_count=17),
        redactions=("/parameters", "/approval/arguments"),
    )


def test_evidence_bundle_matches_v1_golden_fixture() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    bundle = _bundle()
    canonical = bytes.fromhex(_CANONICAL_FIXTURE.read_text(encoding="ascii").strip())

    assert bundle.to_dict() == fixture["document"]
    assert bundle.canonical_unsigned_bytes() == canonical
    assert bundle.commitment_bytes() == b"arg.evidence.v1\0" + canonical
    assert bundle.bundle_digest == fixture["bundle_digest"]
    assert bundle.digest == bundle.bundle_digest
    assert hashlib.sha256(bundle.commitment_bytes()).hexdigest() == bundle.bundle_digest
    assert b'"signature"' not in bundle.canonical_unsigned_bytes()
    assert bundle.signature is None
    assert EVIDENCE_BUNDLE_SCHEMA_V1 is evidence_module.EVIDENCE_BUNDLE_SCHEMA_V1


def test_evidence_bundle_from_dict_restores_v1_golden_fixture() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))

    restored = EvidenceBundle.from_dict(fixture["document"])

    assert restored.to_dict() == fixture["document"]
    assert restored.bundle_digest == fixture["bundle_digest"]


def test_bundle_projects_only_allowlisted_values_and_never_serializes_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = _action(secret="tool-parameter-secret-unique")
    request, decision = _approval(action)

    def fail(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unsafe persistence serializer must not be used")

    monkeypatch.setattr(BoundAction, "to_dict", fail)
    monkeypatch.setattr(BoundAction, "to_evidence_dict", fail)
    monkeypatch.setattr(ApprovalRequest, "to_dict", fail)
    monkeypatch.setattr(DecisionRecord, "to_dict", fail)

    bundle = EvidenceBundle.from_bound_action(
        action,
        bundle_id="privacy-bundle-1",
        created_at=_at(3),
        approval_request=request,
        decision=decision,
        execution=EvidenceExecution("privacy-execution-1", "failed", _at(2)),
    )
    encoded = json.dumps(bundle.to_dict(), sort_keys=True)

    for secret in (
        "tool-parameter-secret-unique",
        "issuer:privacy-secret",
        "principal:privacy-secret",
        "tenant:privacy-secret",
        "approval-argument-secret",
        "approval-request-reason-secret",
        "approval-decision-reason-secret",
        "approval-source-secret",
        "approval-approver-secret",
        "approval-subject-secret",
        "approval-tenant-secret",
        "approval-issuer-secret",
    ):
        assert secret not in encoded
    assert bundle.to_dict()["action"]["precondition_digest"] == action.precondition_digest


def test_approval_binding_keeps_approval_and_parameter_digest_domains_distinct() -> None:
    action = _action()
    request, decision = _approval(action)

    assert request.arguments_digest != action.parameters_digest
    bundle = EvidenceBundle.from_bound_action(
        action,
        bundle_id="approval-bundle-1",
        created_at=_at(3),
        approval_request=request,
        decision=decision,
        execution=EvidenceExecution("approval-execution-1", "unknown", _at(2)),
    )

    assert bundle.to_dict()["approval"] == {
        "request_id": request.request_id,
        "decision_id": decision.decision_id,
        "outcome": "allow",
        "arguments_digest": request.arguments_digest,
        "decided_at": "2026-07-02T00:00:00Z",
        "expires_at": "2026-07-04T00:00:00Z",
    }


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("action_digest", "d" * 64, "action_digest mismatch"),
        ("tool_name", "different_tool", "tool_name mismatch"),
        ("policy_version", "policy-v2", "policy_version mismatch"),
        ("policy_digest", "d" * 64, "policy_digest mismatch"),
    ],
)
def test_approval_binding_rejects_data_not_bound_to_the_action(
    field: str, value: str, message: str
) -> None:
    action = _action()
    request, decision = _approval(action)

    with pytest.raises(EvidenceBundleValidationError, match=message):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="invalid-approval-bundle-1",
            created_at=_at(3),
            approval_request=replace(request, **{field: value}),
            decision=decision,
            execution=EvidenceExecution("invalid-approval-execution-1", "failed", _at(2)),
        )


def test_bundle_requires_complete_typed_safe_inputs() -> None:
    action = _action()

    with pytest.raises(TypeError, match="BoundAction"):
        EvidenceBundle.from_bound_action(
            object(),  # type: ignore[arg-type]
            bundle_id="unbound-action-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("unbound-action-execution-1", "failed", _at(2)),
        )
    with pytest.raises(EvidenceBundleValidationError, match="supplied together"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="partial-approval-bundle-1",
            created_at=_at(3),
            approval_request=_approval(action)[0],
            execution=EvidenceExecution("partial-approval-execution-1", "failed", _at(2)),
        )
    with pytest.raises(TypeError, match="EvidenceExecution"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="mapping-execution-bundle-1",
            created_at=_at(3),
            execution={"result": "raw-result-secret"},  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="AuditAnchor"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="sink-anchor-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("sink-anchor-execution-1", "failed", _at(2)),
            audit_anchor=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="ApprovalRequest"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="unsafe-request-bundle-1",
            created_at=_at(3),
            approval_request=object(),  # type: ignore[arg-type]
            decision=object(),  # type: ignore[arg-type]
            execution=EvidenceExecution("unsafe-request-execution-1", "failed", _at(2)),
        )
    with pytest.raises(TypeError, match="DecisionRecord"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="unsafe-decision-bundle-1",
            created_at=_at(3),
            approval_request=_approval(action)[0],
            decision=object(),  # type: ignore[arg-type]
            execution=EvidenceExecution("unsafe-decision-execution-1", "failed", _at(2)),
        )
    with pytest.raises(TypeError, match="reconciliation must be a sequence"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="mapping-reconciliation-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution(
                "mapping-reconciliation-execution-1", "failed", _at(2)
            ),
            reconciliation={"payload": "raw-provider-payload-secret"},  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="ReconciliationEvidenceEntry"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="unsafe-entry-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("unsafe-entry-execution-1", "failed", _at(2)),
            reconciliation=(object(),),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="redactions must be a sequence"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="mapping-redactions-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("mapping-redactions-execution-1", "failed", _at(2)),
            redactions={"path": "raw-secret"},  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        ReconciliationEvidenceEntry(
            seq=1,
            prior_state="UNKNOWN",
            new_state="MANUAL_REVIEW",
            evidence_kind="receipt",
            created_at=_at(2),
            payload={"provider-secret": "raw"},  # type: ignore[call-arg]
        )


def test_bundle_rejects_invalid_redactions_and_reconciliation_lineage() -> None:
    action = _action()

    with pytest.raises(EvidenceBundleValidationError, match="JSON Pointer"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="invalid-redaction-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("invalid-redaction-execution-1", "failed", _at(2)),
            redactions=("not-a-json-pointer",),
        )
    with pytest.raises(EvidenceBundleValidationError, match="duplicates"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="duplicate-redaction-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("duplicate-redaction-execution-1", "failed", _at(2)),
            redactions=("/parameters", "/parameters"),
        )
    with pytest.raises(EvidenceBundleValidationError, match="allowlisted"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="unsafe-redaction-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("unsafe-redaction-execution-1", "failed", _at(2)),
            redactions=("/parameters/tool-parameter-secret-unique",),
        )
    with pytest.raises(EvidenceBundleValidationError, match="contiguous"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="lineage-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("lineage-execution-1", "failed", _at(2)),
            reconciliation=(
                ReconciliationEvidenceEntry(
                    seq=2,
                    prior_state="UNKNOWN",
                    new_state="MANUAL_REVIEW",
                    evidence_kind="receipt",
                    created_at=_at(2),
                ),
            ),
        )
    with pytest.raises(EvidenceBundleValidationError, match="begin at UNKNOWN"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="truncated-lineage-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("truncated-lineage-execution-1", "failed", _at(2)),
            reconciliation=(
                ReconciliationEvidenceEntry(
                    seq=1,
                    prior_state="MANUAL_REVIEW",
                    new_state="CONFIRMED_SUCCEEDED",
                    evidence_kind="manual-resolution",
                    created_at=_at(2),
                ),
            ),
        )
    with pytest.raises(EvidenceBundleValidationError, match="discontinuous"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="discontinuous-lineage-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution(
                "discontinuous-lineage-execution-1", "failed", _at(2)
            ),
            reconciliation=(
                ReconciliationEvidenceEntry(
                    seq=1,
                    prior_state="UNKNOWN",
                    new_state="MANUAL_REVIEW",
                    evidence_kind="receipt",
                    created_at=_at(2),
                ),
                ReconciliationEvidenceEntry(
                    seq=2,
                    prior_state="UNKNOWN",
                    new_state="CONFIRMED_SUCCEEDED",
                    evidence_kind="manual-resolution",
                    created_at=_at(2, 1),
                ),
            ),
        )
    with pytest.raises(EvidenceBundleValidationError, match="illegal state transition"):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="illegal-transition-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("illegal-transition-execution-1", "failed", _at(2)),
            reconciliation=(
                ReconciliationEvidenceEntry(
                    seq=1,
                    prior_state="UNKNOWN",
                    new_state="CONFIRMED_SUCCEEDED",
                    evidence_kind="receipt",
                    created_at=_at(2),
                ),
                ReconciliationEvidenceEntry(
                    seq=2,
                    prior_state="CONFIRMED_SUCCEEDED",
                    new_state="UNKNOWN",
                    evidence_kind="invalid-rollback",
                    created_at=_at(2, 1),
                ),
            ),
        )


def test_bundle_rejects_reconciliation_lineage_timestamp_regression() -> None:
    action = _action()

    with pytest.raises(
        EvidenceBundleValidationError,
        match="timestamps must not move backwards",
    ):
        EvidenceBundle.from_bound_action(
            action,
            bundle_id="backwards-lineage-bundle-1",
            created_at=_at(3),
            execution=EvidenceExecution("backwards-lineage-execution-1", "failed", _at(2)),
            reconciliation=(
                ReconciliationEvidenceEntry(
                    seq=1,
                    prior_state="UNKNOWN",
                    new_state="MANUAL_REVIEW",
                    evidence_kind="receipt",
                    created_at=_at(2, 1),
                ),
                ReconciliationEvidenceEntry(
                    seq=2,
                    prior_state="MANUAL_REVIEW",
                    new_state="CONFIRMED_SUCCEEDED",
                    evidence_kind="manual-resolution",
                    created_at=_at(2),
                ),
            ),
        )


def test_evidence_leaf_values_reject_invalid_public_inputs() -> None:
    with pytest.raises(EvidenceBundleValidationError, match="execution status"):
        EvidenceExecution("invalid-status-execution-1", "running", _at(2))
    with pytest.raises(EvidenceBundleValidationError, match="must not precede"):
        EvidenceExecution(
            "out-of-order-execution-1",
            "failed",
            _at(2),
            finished_at=_at(1),
        )
    with pytest.raises(EvidenceBundleValidationError, match="execution_record_id"):
        EvidenceExecution("", "failed", _at(2))
    with pytest.raises(EvidenceBundleValidationError, match="timezone-aware"):
        EvidenceExecution(
            "naive-time-execution-1",
            "failed",
            datetime(2026, 7, 2),
        )
    with pytest.raises(EvidenceBundleValidationError, match="reconciliation seq"):
        ReconciliationEvidenceEntry(0, "UNKNOWN", "MANUAL_REVIEW", "receipt", _at(2))
    with pytest.raises(EvidenceBundleValidationError, match="prior_state"):
        ReconciliationEvidenceEntry(1, "INVALID", "MANUAL_REVIEW", "receipt", _at(2))
    with pytest.raises(EvidenceBundleValidationError, match="new_state"):
        ReconciliationEvidenceEntry(1, "UNKNOWN", "INVALID", "receipt", _at(2))
    with pytest.raises(EvidenceBundleValidationError, match="chain_head_hash"):
        AuditAnchor("not-a-digest", 0)
    with pytest.raises(EvidenceBundleValidationError, match="record_count"):
        AuditAnchor(_AUDIT_HASH, -1)


def test_closed_schema_rejects_extra_fields_and_non_null_receipts() -> None:
    validator = Draft202012Validator(
        EVIDENCE_BUNDLE_SCHEMA_V1,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    document = _bundle().to_dict()
    document["unexpected"] = "not-allowed"

    assert any(
        error.validator == "additionalProperties"
        and list(error.absolute_path) == []
        for error in validator.iter_errors(document)
    )
    document.pop("unexpected")
    document["execution"]["receipt"] = "raw-receipt-secret"
    assert any(
        error.validator == "type"
        and list(error.absolute_path) == ["execution", "receipt"]
        for error in validator.iter_errors(document)
    )
    document["execution"]["receipt"] = None
    document["created_at"] = "not-an-rfc3339-timestamp"
    assert any(
        error.validator == "format" and list(error.absolute_path) == ["created_at"]
        for error in validator.iter_errors(document)
    )


def test_evidence_values_are_frozen_and_signature_is_fixed_null() -> None:
    bundle = _bundle()

    with pytest.raises(FrozenInstanceError):
        bundle.bundle_id = "other"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        bundle.execution.status = "failed"  # type: ignore[misc]
    assert bundle.to_dict()["signature"] is None


def test_distribution_contains_evidence_module_and_golden_fixture(tmp_path: Path) -> None:
    repository = Path(__file__).parents[1]
    dist = tmp_path / "dist"
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(dist)],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr

    wheel = next(dist.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        assert "agent_runtime_governance/evidence.py" in archive.namelist()

    sdist = next(dist.glob("*.tar.gz"))
    with tarfile.open(sdist) as archive:
        names = archive.getnames()
    assert any(name.endswith("tests/fixtures/evidence/v1/bundle.json") for name in names)
    assert any(
        name.endswith("tests/fixtures/evidence/v1/canonical-unsigned.hex")
        for name in names
    )


def test_canonicalization_boundary_translates_internal_codec_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle()

    def fail(_: object) -> bytes:
        raise evidence_module.CanonicalJsonError("fixture failure")

    monkeypatch.setattr(evidence_module, "rfc8785_json_bytes", fail)

    with pytest.raises(EvidenceBundleValidationError, match="not RFC 8785"):
        bundle.canonical_unsigned_bytes()
