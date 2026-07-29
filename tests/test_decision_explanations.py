from __future__ import annotations

import json
import subprocess
import sys
from base64 import b64encode
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_runtime_governance import (
    ActionContract,
    DecisionControl,
    DecisionExplanationAttachment,
    DecisionExplanationValidationError,
    EvidenceBundle,
    EvidenceExecution,
    ExecutionContext,
    ExecutionMode,
    InMemoryReceiptVerifier,
    OPADecision,
    OPAMiddleware,
    PolicyDriftDetector,
    PolicyMiddleware,
    ReceiptAttachment,
    ReceiptVerificationExpectation,
    ReceiptVerificationRequest,
    RiskTier,
    Rule,
    RuleMiddleware,
    SimplePolicy,
    ToolCall,
    YAMLPolicyLoader,
    compare_verified_decision_explanations,
    verify_decision_explanation,
    verify_decision_explanation_document,
)
from agent_runtime_governance.verify import verify_evidence_bundle_document

_IDENTITY_KEY = b"0123456789abcdef0123456789abcdef"
_POLICY_DIGEST = "a" * 64


def _action(
    *, policy_version: str = "policy-v1", policy_digest: str = _POLICY_DIGEST
):
    return ActionContract(
        contract_id="ops.decision-explanation",
        contract_version=1,
        tool_name="operate",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        effect_class="ops.change",
    ).bind(
        {"target": "production"},
        identity_issuer="issuer-v1",
        principal="principal-v1",
        tenant="tenant-v1",
        identity_digest_key=_IDENTITY_KEY,
        identity_digest_key_version="key-v1",
        policy_version=policy_version,
        policy_digest=policy_digest,
    )


def _context(action, *, input_text: str = "operate") -> ExecutionContext:
    return ExecutionContext.create(
        ToolCall(name="operate"),
        input_text=input_text,
        risk_tier=RiskTier.LOW,
    ).bind_action(action)


@pytest.mark.asyncio
async def test_python_policy_projects_a_canonical_privacy_safe_attachment() -> None:
    action = _action()
    middleware = PolicyMiddleware(
        SimplePolicy(
            approval_tools={"operate"},
            risk_overrides={"operate": RiskTier.CRITICAL},
        ),
        version="policy-v1",
        digest=_POLICY_DIGEST,
    )

    context = await middleware.process(_context(action, input_text="secret input"))
    attachment = DecisionExplanationAttachment.from_context(context)
    document = attachment.to_dict()

    assert attachment.final_decision == "allow"
    assert attachment.risk_tier == "CRITICAL"
    assert attachment.requires_approval is True
    assert [item["control_id"] for item in document["controls"]] == sorted(
        item["control_id"] for item in document["controls"]
    )
    assert "secret input" not in json.dumps(document, sort_keys=True)
    assert "production" not in json.dumps(document, sort_keys=True)

    report = verify_decision_explanation_document(
        document,
        expected_action_digest=action.action_digest,
        expected_policy_version="policy-v1",
        expected_policy_digest=_POLICY_DIGEST,
    )
    assert report["integrity"]["ok"] is True
    assert report["binding"]["ok"] is True


@pytest.mark.asyncio
async def test_rule_projection_excludes_rule_reason_and_proves_a_deny() -> None:
    action = _action()
    context = await RuleMiddleware(
        [Rule("block-delete", r"delete", "operator secret must not escape")]
    ).process(_context(action, input_text="delete the customer"))

    attachment = DecisionExplanationAttachment.from_context(context)
    document = attachment.to_dict()

    assert attachment.final_decision == "deny"
    assert document["controls"] == [
        {
            "control_id": document["controls"][0]["control_id"],
            "control_version": 1,
            "effect": "deny",
            "result": "matched",
            "reason_code": "rule_matched",
        }
    ]
    assert "operator secret" not in json.dumps(document, sort_keys=True)


@pytest.mark.asyncio
async def test_yaml_policy_uses_its_own_deterministic_control_namespace() -> None:
    document = YAMLPolicyLoader.loads(
        """
version: policy-v2
policies:
  - tool: operate
    effect: deny
"""
    )
    action = _action(policy_version=document.version, policy_digest=document.digest)

    context = await document.middleware().process(_context(action))
    attachment = DecisionExplanationAttachment.from_context(context)

    assert attachment.final_decision == "deny"
    assert attachment.controls[0].control_id.startswith("yaml-policy.")


class _OPAClient:
    def __init__(self, decision: OPADecision) -> None:
        self._decision = decision

    def evaluate(self, _context: ExecutionContext) -> OPADecision:
        return self._decision


@pytest.mark.asyncio
async def test_opa_requires_explicit_structured_controls_for_an_attachment() -> None:
    action = _action()
    structured = OPAMiddleware(
        _OPAClient(
            OPADecision(
                allow=True,
                reason="remote text is diagnostic only",
                controls=(
                    DecisionControl(
                        control_id="opa-policy.allow",
                        control_version=1,
                        effect="allow",
                        result="matched",
                        reason_code="opa_allow",
                    ),
                ),
            )
        ),
        policy_version="policy-v1",
        policy_digest=_POLICY_DIGEST,
    )
    context = await structured.process(_context(action))
    attachment = DecisionExplanationAttachment.from_context(context)
    assert attachment.controls[0].control_id == "opa-policy.allow"

    plain = OPAMiddleware(
        _OPAClient(OPADecision(allow=True, reason="remote secret")),
        policy_version="policy-v1",
        policy_digest=_POLICY_DIGEST,
    )
    context = await plain.process(_context(action))
    with pytest.raises(DecisionExplanationValidationError, match="controls"):
        DecisionExplanationAttachment.from_context(context)


@pytest.mark.asyncio
async def test_attachment_rejects_reordering_tampering_and_policy_substitution() -> None:
    action = _action()
    context = await PolicyMiddleware(
        SimplePolicy(approval_tools={"operate"}),
        version="policy-v1",
        digest=_POLICY_DIGEST,
    ).process(_context(action))
    attachment = DecisionExplanationAttachment.from_context(context)
    document = attachment.to_dict()

    reordered = {**document, "controls": list(reversed(document["controls"]))}
    with pytest.raises(DecisionExplanationValidationError, match="ordered"):
        DecisionExplanationAttachment.from_dict(reordered)

    unsafe = {
        **document,
        "controls": [
            {
                **document["controls"][0],
                "reason_code": "contains a secret",
            },
            *document["controls"][1:],
        ],
    }
    with pytest.raises(DecisionExplanationValidationError, match="reason_code"):
        DecisionExplanationAttachment.from_dict(unsafe)

    with pytest.raises(DecisionExplanationValidationError, match="fields"):
        DecisionControl.from_dict({**document["controls"][0], "raw": "secret"})

    report = verify_decision_explanation_document(
        document,
        expected_policy_digest="b" * 64,
    )
    assert report["binding"] == {
        "ok": False,
        "reasons": ["policy_digest_mismatch"],
        "state": "failed",
    }


@pytest.mark.asyncio
async def test_attachment_rejects_recorded_policy_identity_drift() -> None:
    context = await PolicyMiddleware(
        SimplePolicy(), version="policy-v2", digest="b" * 64
    ).process(_context(_action()))

    with pytest.raises(DecisionExplanationValidationError, match="policy identity"):
        DecisionExplanationAttachment.from_context(context)


@pytest.mark.asyncio
async def test_comparison_only_accepts_verified_same_action_attachments() -> None:
    action = _action()
    context = await PolicyMiddleware(
        SimplePolicy(), version="policy-v1", digest=_POLICY_DIGEST
    ).process(_context(action))
    baseline = DecisionExplanationAttachment.from_context(context)
    candidate = replace(baseline, risk_tier="HIGH")

    comparison = compare_verified_decision_explanations(
        verify_decision_explanation(baseline),
        verify_decision_explanation(candidate),
    )

    assert comparison.action_digest == action.action_digest
    assert [(item.field, item.baseline, item.candidate) for item in comparison.differences] == [
        ("risk_tier", "LOW", "HIGH")
    ]

    other = replace(baseline, action_digest="b" * 64)
    with pytest.raises(DecisionExplanationValidationError, match="action"):
        compare_verified_decision_explanations(
            verify_decision_explanation(baseline), verify_decision_explanation(other)
        )


@pytest.mark.asyncio
async def test_inspect_command_only_renders_a_verified_attachment(tmp_path: Path) -> None:
    action = _action()
    context = await PolicyMiddleware(
        SimplePolicy(), version="policy-v1", digest=_POLICY_DIGEST
    ).process(_context(action, input_text="secret input"))
    attachment = DecisionExplanationAttachment.from_context(context)
    path = tmp_path / "attachment.json"
    path.write_text(json.dumps(attachment.to_dict()), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_runtime_governance.inspect",
            str(path),
            "--expected-attachment-digest",
            attachment.attachment_digest,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "Decision explanation verification: passed" in completed.stdout
    assert f"Action digest: {action.action_digest}" in completed.stdout
    assert "secret input" not in completed.stdout


@pytest.mark.asyncio
async def test_attachment_binds_existing_evidence_and_receipt_verification() -> None:
    action = _action()
    context = await PolicyMiddleware(
        SimplePolicy(), version="policy-v1", digest=_POLICY_DIGEST
    ).process(_context(action))
    bundle = EvidenceBundle.from_bound_action(
        action,
        bundle_id="decision-explanation-bundle",
        created_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
        execution=EvidenceExecution(
            execution_record_id="decision-explanation-execution",
            status="succeeded",
            started_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
        ),
    )
    attachment = DecisionExplanationAttachment.from_context(
        context, evidence_bundle=bundle
    )
    receipt = ReceiptAttachment(
        bundle_digest=bundle.bundle_digest,
        value=b64encode(b"external-receipt-secret").decode("ascii"),
    )
    request = ReceiptVerificationRequest.from_bundle(bundle, receipt)
    verifier = InMemoryReceiptVerifier(
        (ReceiptVerificationExpectation.from_request(request, outcome="succeeded"),)
    )

    outcome = verify_evidence_bundle_document(
        bundle.to_dict(), receipt_verifier=verifier, receipt=receipt
    )
    explanation = verify_decision_explanation_document(
        attachment.to_dict(),
        expected_evidence_bundle_digest=bundle.bundle_digest,
    )

    assert attachment.evidence_bundle_digest == bundle.bundle_digest
    assert outcome["outcome_verified"]["state"] == "passed"
    assert explanation["binding"]["state"] == "passed"
    assert receipt.value not in json.dumps(attachment.to_dict(), sort_keys=True)


@settings(max_examples=25)
@given(st.lists(st.sampled_from(("risk-a", "risk-b", "risk-c")), unique=True))
def test_attachment_canonicalization_is_deterministic_and_order_sensitive(
    risk_controls: list[str],
) -> None:
    action = _action()
    controls = [
        DecisionControl(
            control_id="policy.allow",
            control_version=1,
            effect="allow",
            result="matched",
            reason_code="policy_allowed",
        ),
        *(
            DecisionControl(
                control_id=f"policy.{name}",
                control_version=1,
                effect="risk",
                result="matched",
                reason_code="risk_overridden",
            )
            for name in risk_controls
        ),
    ]
    attachment = DecisionExplanationAttachment(
        action_digest=action.action_digest,
        policy_version="policy-v1",
        policy_digest=_POLICY_DIGEST,
        final_decision="allow",
        risk_tier="LOW",
        requires_approval=False,
        controls=tuple(sorted(controls, key=lambda item: item.identity)),
    )

    assert DecisionExplanationAttachment.from_dict(
        attachment.to_dict()
    ).attachment_digest == attachment.attachment_digest
    if len(controls) > 1:
        reordered = {
            **attachment.to_dict(),
            "controls": list(reversed(attachment.to_dict()["controls"])),
        }
        with pytest.raises(DecisionExplanationValidationError, match="ordered"):
            DecisionExplanationAttachment.from_dict(reordered)


@pytest.mark.asyncio
async def test_comparison_has_no_runtime_or_tool_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = _action()
    context = await PolicyMiddleware(
        SimplePolicy(), version="policy-v1", digest=_POLICY_DIGEST
    ).process(_context(action))
    baseline = DecisionExplanationAttachment.from_context(context)
    candidate = replace(baseline, risk_tier="HIGH")

    async def unexpected_replay(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("attachment comparison must not replay a runtime")

    monkeypatch.setattr(PolicyDriftDetector, "compare", unexpected_replay)

    comparison = compare_verified_decision_explanations(
        verify_decision_explanation(baseline),
        verify_decision_explanation(candidate),
    )

    assert comparison.matches is False
