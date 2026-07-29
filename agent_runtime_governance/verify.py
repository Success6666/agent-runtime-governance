"""Offline, machine-readable verification for Governance Evidence Bundle v1.

The command deliberately performs no network access itself. It verifies the
portable bundle, optional detached signature inputs, caller-supplied binding
expectations, and explicitly selected external anchor or receipt providers.
Those providers receive only detached, bounded inputs and are never inferred
from bundle contents.
"""

from __future__ import annotations

import argparse
import contextlib
import inspect
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, NoReturn

from .decision_explanations import (
    DecisionExplanationAttachment,
    DecisionExplanationValidationError,
)
from .evidence import EvidenceBundle, EvidenceBundleValidationError
from .evidence_external import (
    ANCHOR_PROVIDER_ENTRY_POINT_GROUP,
    RECEIPT_VERIFIER_ENTRY_POINT_GROUP,
    AnchorProvider,
    AnchorVerificationRequest,
    AnchorVerificationResult,
    EvidenceExternalValidationError,
    ReceiptAttachment,
    ReceiptVerificationRequest,
    ReceiptVerificationResult,
    ReceiptVerifier,
)
from .evidence_signing import (
    EvidenceSignatureAttachment,
    EvidenceSignatureValidationError,
    EvidenceSignatureVerificationError,
    EvidenceSigningDependencyError,
    EvidenceTrustRoots,
    EvidenceTrustRootValidationError,
    verify_evidence_bundle_signature,
)

EXIT_SUCCESS = 0
EXIT_VERIFICATION_FAILURE = 1
EXIT_UNSUPPORTED = 2

_REPORT_SCHEMA_VERSION = "1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_EXTERNAL_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_ANCHOR_INPUT_REASONS = frozenset(
    {
        "anchor_provider_invalid",
        "anchor_provider_load_failed",
        "anchor_provider_unavailable",
        "anchor_sequence_invalid",
    }
)
_ANCHOR_FAILURE_REASONS = frozenset(
    {
        "anchor_sequence_deletion_detected",
        "anchor_sequence_mismatch",
        "anchor_sequence_reordered",
        "anchor_subject_missing",
    }
)
_ANCHOR_UNSUPPORTED_REASONS = frozenset(
    {"anchor_provider_unsupported", "anchor_sequence_unavailable"}
)
_RECEIPT_INPUT_REASONS = frozenset(
    {
        "receipt_attachment_invalid",
        "receipt_verifier_invalid",
        "receipt_verifier_load_failed",
        "receipt_verifier_unavailable",
    }
)
_RECEIPT_FAILURE_REASONS = frozenset({"receipt_not_found", "receipt_not_verified"})
_RECEIPT_UNSUPPORTED_REASONS = frozenset({"receipt_verifier_unsupported"})


class DecisionExplanationVerificationError(ValueError):
    """Raised when a decision attachment cannot enter read-only comparison."""


@dataclass(frozen=True, slots=True)
class VerifiedDecisionExplanation:
    """An attachment accepted by the existing offline verification surface."""

    attachment: DecisionExplanationAttachment
    report: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class DecisionExplanationDifference:
    """One stable, privacy-safe difference between verified attachments."""

    field: str
    baseline: Any
    candidate: Any


@dataclass(frozen=True, slots=True)
class DecisionExplanationComparison:
    """Read-only drift record for two verified attachments of one action."""

    action_digest: str
    differences: tuple[DecisionExplanationDifference, ...]

    @property
    def matches(self) -> bool:
        return not self.differences


class _CliUsageError(ValueError):
    """Raised instead of writing argparse diagnostics to the public protocol."""


class JsonInputError(ValueError):
    """Raised when a JSON input is not a strict JSON object."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _CliUsageError(message)


class _DiscardingTextStream:
    """A bounded sink used to preserve the verifier's JSON-only CLI protocol."""

    def write(self, value: str) -> int:
        return len(value)

    def flush(self) -> None:
        return None


@dataclass(frozen=True, slots=True)
class _PreparedAnchorProvider:
    provider_id: str
    protocol_version: str
    verify: Any

    def report_details(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "provider_protocol_version": self.protocol_version,
        }


@dataclass(frozen=True, slots=True)
class _PreparedReceiptVerifier:
    verifier_id: str
    protocol_version: str
    verify: Any

    def report_details(self) -> dict[str, str]:
        return {
            "verifier_id": self.verifier_id,
            "verifier_protocol_version": self.protocol_version,
        }


def verify_evidence_bundle_document(
    document: Mapping[str, Any],
    *,
    signature: EvidenceSignatureAttachment | None = None,
    trust_roots: EvidenceTrustRoots | None = None,
    input_reasons: Sequence[str] = (),
    authentication_requested: bool | None = None,
    anchor_provider: AnchorProvider | None = None,
    anchor_request: AnchorVerificationRequest | None = None,
    anchor_input_reasons: Sequence[str] = (),
    anchor_requested: bool | None = None,
    receipt_verifier: ReceiptVerifier | None = None,
    receipt: ReceiptAttachment | None = None,
    receipt_input_reasons: Sequence[str] = (),
    outcome_requested: bool | None = None,
    suppress_provider_output: bool = False,
    expected_bundle_digest: str | None = None,
    expected_tenant_digest: str | None = None,
    expected_policy_version: str | None = None,
    expected_policy_digest: str | None = None,
    expected_contract_id: str | None = None,
    expected_contract_version: int | None = None,
    expected_contract_digest: str | None = None,
    verification_time: datetime | None = None,
) -> dict[str, Any]:
    """Verify one decoded evidence document without network or host state.

    The result is directly JSON serializable. A false integrity result is a
    verification failure; an unsupported authenticity result means the
    optional Ed25519 verifier dependency is unavailable. Callers that parse a
    detached signature attachment before invoking this function can pass its
    failure reasons and requested state explicitly so a requested commitment
    never appears unanchored.
    """

    if authentication_requested is None:
        authentication_requested = (
            signature is not None or trust_roots is not None or bool(input_reasons)
        )
    if anchor_requested is None:
        anchor_requested = (
            anchor_provider is not None
            or anchor_request is not None
            or bool(anchor_input_reasons)
        )
    if outcome_requested is None:
        outcome_requested = (
            receipt_verifier is not None
            or receipt is not None
            or bool(receipt_input_reasons)
        )
    try:
        bundle = EvidenceBundle.from_dict(document)
    except (EvidenceBundleValidationError, TypeError, ValueError):
        return _report(
            integrity=_failed_level("bundle_invalid"),
            authenticity=(
                _not_evaluated_level("integrity_failed")
                if authentication_requested
                else _not_requested_level()
            ),
            outcome_verified=(
                _not_evaluated_level("integrity_failed")
                if outcome_requested
                else None
            ),
        )

    commitment = _commitment_level(
        bundle.bundle_digest,
        signature=signature,
        expected_bundle_digest=expected_bundle_digest,
        input_reasons=input_reasons,
    )
    anchor_continuity = _verify_anchor_continuity(
        bundle,
        provider=anchor_provider,
        request=anchor_request,
        input_reasons=anchor_input_reasons,
        requested=anchor_requested,
        suppress_provider_output=suppress_provider_output,
    )
    integrity_reasons = [
        *commitment["reasons"],
        *_binding_reasons(
            bundle,
            expected_tenant_digest=expected_tenant_digest,
            expected_policy_version=expected_policy_version,
            expected_policy_digest=expected_policy_digest,
            expected_contract_id=expected_contract_id,
            expected_contract_version=expected_contract_version,
            expected_contract_digest=expected_contract_digest,
        ),
    ]
    if anchor_continuity["state"] == "failed":
        integrity_reasons.extend(anchor_continuity["reasons"])
    integrity = _level(
        state="passed" if not integrity_reasons else "failed",
        ok=not integrity_reasons,
        reasons=integrity_reasons,
        bundle_digest=bundle.bundle_digest,
        commitment=commitment,
        audit_continuity=anchor_continuity,
    )

    authenticity = _verify_authenticity(
        bundle,
        signature=signature,
        trust_roots=trust_roots,
        requested=authentication_requested,
        verification_time=verification_time,
    )
    outcome_verified = _verify_outcome(
        bundle,
        verifier=receipt_verifier,
        receipt=receipt,
        input_reasons=receipt_input_reasons,
        requested=outcome_requested,
        suppress_provider_output=suppress_provider_output,
    )
    return _report(
        integrity=integrity,
        authenticity=authenticity,
        outcome_verified=outcome_verified,
    )


def verify_decision_explanation_document(
    document: Mapping[str, Any],
    *,
    expected_attachment_digest: str | None = None,
    expected_action_digest: str | None = None,
    expected_policy_version: str | None = None,
    expected_policy_digest: str | None = None,
    expected_evidence_bundle_digest: str | None = None,
) -> dict[str, Any]:
    """Verify one detached decision explanation without side effects.

    The attachment is intentionally separate from Evidence Bundle v1. This
    function shares the module and fail-closed report conventions used by the
    bundle verifier, but it performs no policy execution, receipt lookup, or
    network access.
    """

    try:
        attachment = DecisionExplanationAttachment.from_dict(document)
    except (DecisionExplanationValidationError, TypeError, ValueError):
        return _decision_explanation_report(
            integrity=_failed_level("attachment_invalid"),
            binding=_not_evaluated_level("integrity_failed"),
        )

    integrity_reasons: list[str] = []
    if expected_attachment_digest is not None:
        if not _SHA256_HEX.fullmatch(expected_attachment_digest):
            integrity_reasons.append("expected_attachment_digest_invalid")
        elif expected_attachment_digest != attachment.attachment_digest:
            integrity_reasons.append("attachment_digest_mismatch")
    integrity = _level(
        state="passed" if not integrity_reasons else "failed",
        ok=not integrity_reasons,
        reasons=integrity_reasons,
        attachment_digest=attachment.attachment_digest,
    )
    if integrity_reasons:
        return _decision_explanation_report(
            integrity=integrity,
            binding=_not_evaluated_level("integrity_failed"),
        )

    binding_reasons = _decision_explanation_binding_reasons(
        attachment,
        expected_action_digest=expected_action_digest,
        expected_policy_version=expected_policy_version,
        expected_policy_digest=expected_policy_digest,
        expected_evidence_bundle_digest=expected_evidence_bundle_digest,
    )
    return _decision_explanation_report(
        integrity=integrity,
        binding=_level(
            state="passed" if not binding_reasons else "failed",
            ok=not binding_reasons,
            reasons=binding_reasons,
        ),
    )


def verify_decision_explanation(
    attachment: DecisionExplanationAttachment,
    *,
    expected_attachment_digest: str | None = None,
    expected_action_digest: str | None = None,
    expected_policy_version: str | None = None,
    expected_policy_digest: str | None = None,
    expected_evidence_bundle_digest: str | None = None,
) -> VerifiedDecisionExplanation:
    """Return an attachment eligible for read-only comparison.

    Calling this function is the only supported path to
    :func:`compare_verified_decision_explanations`; comparison accepts no raw
    documents and never replays a runtime.
    """

    if not isinstance(attachment, DecisionExplanationAttachment):
        raise TypeError("attachment must be a DecisionExplanationAttachment")
    report = verify_decision_explanation_document(
        attachment.to_dict(),
        expected_attachment_digest=expected_attachment_digest,
        expected_action_digest=expected_action_digest,
        expected_policy_version=expected_policy_version,
        expected_policy_digest=expected_policy_digest,
        expected_evidence_bundle_digest=expected_evidence_bundle_digest,
    )
    if not report["integrity"]["ok"] or not report["binding"]["ok"]:
        raise DecisionExplanationVerificationError(
            "decision explanation verification failed"
        )
    return VerifiedDecisionExplanation(attachment=attachment, report=report)


def compare_verified_decision_explanations(
    baseline: VerifiedDecisionExplanation,
    candidate: VerifiedDecisionExplanation,
) -> DecisionExplanationComparison:
    """Compare verified explanations for the same action without execution."""

    if not isinstance(baseline, VerifiedDecisionExplanation) or not isinstance(
        candidate, VerifiedDecisionExplanation
    ):
        raise TypeError("comparison requires verified decision explanations")
    _require_verified_decision_explanation(baseline)
    _require_verified_decision_explanation(candidate)
    if baseline.attachment.action_digest != candidate.attachment.action_digest:
        raise DecisionExplanationValidationError(
            "decision explanations must bind the same action_digest"
        )

    differences: list[DecisionExplanationDifference] = []
    for field in (
        "evidence_bundle_digest",
        "policy_version",
        "policy_digest",
        "final_decision",
        "risk_tier",
        "requires_approval",
    ):
        baseline_value = getattr(baseline.attachment, field)
        candidate_value = getattr(candidate.attachment, field)
        if baseline_value != candidate_value:
            differences.append(
                DecisionExplanationDifference(field, baseline_value, candidate_value)
            )

    baseline_controls = {
        control.identity: control.to_dict() for control in baseline.attachment.controls
    }
    candidate_controls = {
        control.identity: control.to_dict() for control in candidate.attachment.controls
    }
    for identity in sorted(set(baseline_controls) | set(candidate_controls)):
        baseline_value = baseline_controls.get(identity)
        candidate_value = candidate_controls.get(identity)
        if baseline_value != candidate_value:
            control_id, control_version = identity
            differences.append(
                DecisionExplanationDifference(
                    f"controls/{control_id}@{control_version}",
                    baseline_value,
                    candidate_value,
                )
            )
    return DecisionExplanationComparison(
        action_digest=baseline.attachment.action_digest,
        differences=tuple(differences),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline verifier and write exactly one JSON report to stdout."""

    parser = _argument_parser()
    try:
        arguments = parser.parse_args(argv)
    except _CliUsageError:
        return _emit_and_exit(_report(integrity=_failed_level("cli_usage_invalid")))

    try:
        document = read_json_object(arguments.bundle, "bundle")
    except JsonInputError as exc:
        return _emit_and_exit(_report(integrity=_failed_level(str(exc))))

    signature, signature_reasons = _read_signature(arguments.signature)
    trust_roots, trust_root_reasons = _read_trust_roots(arguments.trust_roots)
    anchor_request, anchor_input_reasons = _read_anchor_request(
        arguments.anchor_sequence
    )
    receipt, receipt_input_reasons = _read_receipt(arguments.receipt)
    anchor_requested = (
        arguments.anchor_provider is not None or arguments.anchor_sequence is not None
    )
    outcome_requested = (
        arguments.require_outcome
        or arguments.receipt_verifier is not None
        or arguments.receipt is not None
    )
    try:
        verification_time = _parse_verification_time(arguments.at)
    except _CliUsageError:
        return _emit_and_exit(
            _report(integrity=_failed_level("verification_time_invalid"))
        )
    bundle_is_valid = _is_valid_bundle_document(document)
    anchor_provider: AnchorProvider | None = None
    if (
        bundle_is_valid
        and arguments.anchor_provider is not None
        and anchor_request is not None
        and not anchor_input_reasons
    ):
        anchor_provider, anchor_provider_reason = _load_anchor_provider(
            arguments.anchor_provider
        )
        if anchor_provider_reason is not None:
            anchor_input_reasons = [
                *anchor_input_reasons,
                anchor_provider_reason,
            ]
    receipt_verifier: ReceiptVerifier | None = None
    if (
        bundle_is_valid
        and arguments.receipt_verifier is not None
        and receipt is not None
        and not receipt_input_reasons
    ):
        receipt_verifier, receipt_provider_reason = _load_receipt_verifier(
            arguments.receipt_verifier
        )
        if receipt_provider_reason is not None:
            receipt_input_reasons = [
                *receipt_input_reasons,
                receipt_provider_reason,
            ]
    report = verify_evidence_bundle_document(
        document,
        signature=signature,
        trust_roots=trust_roots,
        input_reasons=signature_reasons,
        authentication_requested=(
            arguments.signature is not None or arguments.trust_roots is not None
        ),
        anchor_provider=anchor_provider,
        anchor_request=anchor_request,
        anchor_input_reasons=anchor_input_reasons,
        anchor_requested=anchor_requested,
        receipt_verifier=receipt_verifier,
        receipt=receipt,
        receipt_input_reasons=receipt_input_reasons,
        outcome_requested=outcome_requested,
        suppress_provider_output=True,
        expected_bundle_digest=arguments.expected_bundle_digest,
        expected_tenant_digest=arguments.expected_tenant_digest,
        expected_policy_version=arguments.expected_policy_version,
        expected_policy_digest=arguments.expected_policy_digest,
        expected_contract_id=arguments.expected_contract_id,
        expected_contract_version=arguments.expected_contract_version,
        expected_contract_digest=arguments.expected_contract_digest,
        verification_time=verification_time,
    )
    if signature_reasons or trust_root_reasons:
        report["authenticity"] = _failed_level(
            *signature_reasons,
            *trust_root_reasons,
        )
    return _emit_and_exit(
        report,
        require_anchor=anchor_requested,
        require_outcome=outcome_requested,
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="python -m agent_runtime_governance.verify",
        description="Verify a Governance Evidence Bundle without network access.",
    )
    parser.add_argument("bundle", metavar="BUNDLE", type=Path)
    parser.add_argument(
        "--signature",
        metavar="FILE",
        type=Path,
        help="detached EvidenceSignatureAttachment JSON file",
    )
    parser.add_argument(
        "--trust-roots",
        metavar="FILE",
        type=Path,
        help="EvidenceTrustRoots JSON file for detached signature verification",
    )
    parser.add_argument(
        "--anchor-provider",
        metavar="ENTRYPOINT",
        help=(
            "named anchor provider entry point; only this selected provider is loaded"
        ),
    )
    parser.add_argument(
        "--anchor-sequence",
        metavar="FILE",
        type=Path,
        help="detached AnchorVerificationRequest JSON file",
    )
    parser.add_argument(
        "--receipt-verifier",
        metavar="ENTRYPOINT",
        help=(
            "named receipt verifier entry point; only this selected verifier is loaded"
        ),
    )
    parser.add_argument(
        "--receipt",
        metavar="FILE",
        type=Path,
        help="detached ReceiptAttachment JSON file",
    )
    parser.add_argument(
        "--expected-bundle-digest",
        metavar="SHA256",
        help="require the canonical bundle digest to match this SHA-256 value",
    )
    parser.add_argument(
        "--expected-tenant-digest",
        metavar="SHA256",
        help="require the evidence tenant digest to match this SHA-256 value",
    )
    parser.add_argument(
        "--expected-policy-version",
        metavar="VERSION",
        help="require the evidence policy version to match this value",
    )
    parser.add_argument(
        "--expected-policy-digest",
        metavar="SHA256",
        help="require the evidence policy digest to match this SHA-256 value",
    )
    parser.add_argument(
        "--expected-contract-id",
        metavar="CONTRACT_ID",
        help="require the evidence contract identifier to match this value",
    )
    parser.add_argument(
        "--expected-contract-version",
        metavar="VERSION",
        type=int,
        help="require the evidence contract version to match this positive integer",
    )
    parser.add_argument(
        "--expected-contract-digest",
        metavar="SHA256",
        help="require the evidence contract digest to match this SHA-256 value",
    )
    parser.add_argument(
        "--require-outcome",
        action="store_true",
        help="require an external receipt verifier to establish the outcome",
    )
    parser.add_argument(
        "--at",
        metavar="RFC3339",
        help="evaluate trust-root validity at this RFC 3339 timestamp",
    )
    return parser


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    """Read one strict JSON object with duplicate-key and finite-number checks."""

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise JsonInputError(f"{label}_unreadable") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (json.JSONDecodeError, JsonInputError) as exc:
        raise JsonInputError(f"{label}_invalid_json") from exc
    if not isinstance(document, dict):
        raise JsonInputError(f"{label}_must_be_object")
    return document


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise JsonInputError("duplicate_json_key")
        document[key] = value
    return document


def _reject_nonfinite_constant(value: str) -> None:
    raise JsonInputError(f"nonfinite_json_constant_{value}")


def _read_signature(
    path: Path | None,
) -> tuple[EvidenceSignatureAttachment | None, list[str]]:
    if path is None:
        return None, []
    try:
        return EvidenceSignatureAttachment.from_dict(
            read_json_object(path, "signature")
        ), []
    except (
        EvidenceSignatureValidationError,
        JsonInputError,
        TypeError,
        ValueError,
    ):
        return None, ["signature_attachment_invalid"]


def _read_trust_roots(
    path: Path | None,
) -> tuple[EvidenceTrustRoots | None, list[str]]:
    if path is None:
        return None, []
    try:
        return EvidenceTrustRoots.from_dict(read_json_object(path, "trust_roots")), []
    except (
        EvidenceTrustRootValidationError,
        JsonInputError,
        TypeError,
        ValueError,
    ):
        return None, ["trust_roots_invalid"]


def _read_anchor_request(
    path: Path | None,
) -> tuple[AnchorVerificationRequest | None, list[str]]:
    if path is None:
        return None, []
    try:
        return AnchorVerificationRequest.from_dict(
            read_json_object(path, "anchor_sequence")
        ), []
    except (
        EvidenceExternalValidationError,
        JsonInputError,
        TypeError,
        ValueError,
    ):
        return None, ["anchor_sequence_invalid"]


def _read_receipt(
    path: Path | None,
) -> tuple[ReceiptAttachment | None, list[str]]:
    if path is None:
        return None, []
    try:
        return ReceiptAttachment.from_dict(read_json_object(path, "receipt")), []
    except (
        EvidenceExternalValidationError,
        JsonInputError,
        TypeError,
        ValueError,
    ):
        return None, ["receipt_attachment_invalid"]


def _is_valid_bundle_document(document: Mapping[str, Any]) -> bool:
    """Reject malformed bundles before any selected provider can be imported."""

    try:
        EvidenceBundle.from_dict(document)
    except (EvidenceBundleValidationError, TypeError, ValueError):
        return False
    return True


def _parse_verification_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    if not _RFC3339_TIMESTAMP.fullmatch(value):
        raise _CliUsageError("verification time must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _CliUsageError(
            "verification time must be an RFC 3339 timestamp"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _CliUsageError("verification time must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _commitment_level(
    bundle_digest: str,
    *,
    signature: EvidenceSignatureAttachment | None,
    expected_bundle_digest: str | None,
    input_reasons: Sequence[str] = (),
) -> dict[str, Any]:
    reasons = list(input_reasons)
    if signature is not None and signature.bundle_digest != bundle_digest:
        reasons.append("signature_bundle_digest_mismatch")
    if expected_bundle_digest is not None:
        if not _SHA256_HEX.fullmatch(expected_bundle_digest):
            reasons.append("expected_bundle_digest_invalid")
        elif expected_bundle_digest != bundle_digest:
            reasons.append("expected_bundle_digest_mismatch")
    if reasons:
        return _failed_level(*reasons)
    if signature is None and expected_bundle_digest is None:
        return _level(state="unanchored", ok=None, reasons=())
    return _passed_level()


def _binding_reasons(
    bundle: EvidenceBundle,
    *,
    expected_tenant_digest: str | None,
    expected_policy_version: str | None,
    expected_policy_digest: str | None,
    expected_contract_id: str | None,
    expected_contract_version: int | None,
    expected_contract_digest: str | None,
) -> list[str]:
    expected_digests = (
        ("tenant", expected_tenant_digest, bundle.identity.tenant_digest),
        ("policy", expected_policy_digest, bundle.policy.digest),
        ("contract", expected_contract_digest, bundle.action.contract_digest),
    )
    reasons: list[str] = []
    for label, expected_digest, actual_digest in expected_digests:
        if expected_digest is None:
            continue
        if not _SHA256_HEX.fullmatch(expected_digest):
            reasons.append(f"expected_{label}_digest_invalid")
        elif expected_digest != actual_digest:
            reasons.append(f"{label}_digest_mismatch")
    if (
        expected_policy_version is not None
        and expected_policy_version != bundle.policy.version
    ):
        reasons.append("policy_version_mismatch")
    if (
        expected_contract_id is not None
        and expected_contract_id != bundle.action.contract_id
    ):
        reasons.append("contract_id_mismatch")
    if expected_contract_version is not None:
        if expected_contract_version < 1:
            reasons.append("expected_contract_version_invalid")
        elif expected_contract_version != bundle.action.contract_version:
            reasons.append("contract_version_mismatch")
    return reasons


def _verify_authenticity(
    bundle: EvidenceBundle,
    *,
    signature: EvidenceSignatureAttachment | None,
    trust_roots: EvidenceTrustRoots | None,
    requested: bool,
    verification_time: datetime | None,
) -> dict[str, Any]:
    if not requested:
        return _not_requested_level()
    if signature is None:
        return _failed_level("signature_attachment_missing")
    if trust_roots is None:
        return _failed_level("trust_roots_missing")
    try:
        verify_evidence_bundle_signature(
            bundle,
            signature,
            trust_roots,
            now=verification_time,
        )
    except EvidenceSigningDependencyError:
        return _unsupported_level("ed25519_verifier_unavailable")
    except (
        EvidenceSignatureValidationError,
        EvidenceSignatureVerificationError,
        EvidenceTrustRootValidationError,
        TypeError,
        ValueError,
    ):
        return _failed_level("signature_not_verified")
    return _passed_level()


def _verify_anchor_continuity(
    bundle: EvidenceBundle,
    *,
    provider: AnchorProvider | None,
    request: AnchorVerificationRequest | None,
    input_reasons: Sequence[str],
    requested: bool,
    suppress_provider_output: bool,
) -> dict[str, Any]:
    reasons = _stable_reason_codes(
        input_reasons,
        allowed=_ANCHOR_INPUT_REASONS,
        fallback="anchor_input_invalid",
    )
    if reasons:
        if provider is None and reasons == ("anchor_provider_unavailable",):
            return _unsupported_level(*reasons)
        return _failed_level(*reasons)
    if provider is None:
        if requested:
            return _unsupported_level("anchor_provider_missing")
        return _unsupported_level("anchor_verifier_unsupported")
    if request is None:
        return _unsupported_level("anchor_sequence_missing")
    normalized_request = _normalize_anchor_request(request)
    if normalized_request is None:
        return _failed_level("anchor_request_invalid")
    if (
        normalized_request.subject_bundle_id != bundle.bundle_id
        or normalized_request.subject_bundle_digest != bundle.bundle_digest
    ):
        return _failed_level("anchor_subject_bundle_mismatch")
    if normalized_request.tenant_digest != bundle.identity.tenant_digest:
        return _failed_level("anchor_tenant_digest_mismatch")
    try:
        prepared = _call_provider(
            lambda: _prepare_anchor_provider(provider),
            suppress_output=suppress_provider_output,
        )
    except Exception:
        return _failed_level("anchor_provider_invalid")
    if prepared is None:
        return _failed_level("anchor_provider_invalid")
    details = prepared.report_details()
    try:
        result, async_result = _call_provider(
            lambda: _normalize_anchor_result(prepared.verify(normalized_request)),
            suppress_output=suppress_provider_output,
        )
    except Exception:
        return _failed_level("anchor_provider_failed", **details)
    if async_result:
        return _failed_level("anchor_provider_async_unsupported", **details)
    if result is None:
        return _failed_level("anchor_provider_invalid_result", **details)
    if result.state == "passed":
        return _passed_level(**details)
    if result.state == "unsupported":
        return _unsupported_level(_anchor_unsupported_reason(result.reason), **details)
    return _failed_level(_anchor_failure_reason(result.reason), **details)


def _verify_outcome(
    bundle: EvidenceBundle,
    *,
    verifier: ReceiptVerifier | None,
    receipt: ReceiptAttachment | None,
    input_reasons: Sequence[str],
    requested: bool,
    suppress_provider_output: bool,
) -> dict[str, Any]:
    reasons = _stable_reason_codes(
        input_reasons,
        allowed=_RECEIPT_INPUT_REASONS,
        fallback="receipt_input_invalid",
    )
    if reasons:
        if verifier is None and reasons == ("receipt_verifier_unavailable",):
            return _unsupported_level(*reasons)
        return _failed_level(*reasons)
    if verifier is None:
        if requested:
            return _unsupported_level("receipt_verifier_missing")
        return _unsupported_level("receipt_verifier_unsupported")
    if receipt is None:
        return _failed_level("receipt_attachment_missing")
    normalized_receipt = _normalize_receipt_attachment(receipt)
    if normalized_receipt is None:
        return _failed_level("receipt_attachment_invalid")
    if normalized_receipt.bundle_digest != bundle.bundle_digest:
        return _failed_level("receipt_bundle_digest_mismatch")
    try:
        request = ReceiptVerificationRequest.from_bundle(bundle, normalized_receipt)
    except (AttributeError, EvidenceExternalValidationError, TypeError, ValueError):
        return _failed_level("receipt_request_invalid")
    try:
        prepared = _call_provider(
            lambda: _prepare_receipt_verifier(verifier),
            suppress_output=suppress_provider_output,
        )
    except Exception:
        return _failed_level("receipt_verifier_invalid")
    if prepared is None:
        return _failed_level("receipt_verifier_invalid")
    details = prepared.report_details()
    try:
        result, async_result = _call_provider(
            lambda: _normalize_receipt_result(prepared.verify(request)),
            suppress_output=suppress_provider_output,
        )
    except Exception:
        return _failed_level("receipt_verifier_failed", **details)
    if async_result:
        return _failed_level("receipt_verifier_async_unsupported", **details)
    if result is None:
        return _failed_level("receipt_verifier_invalid_result", **details)
    if result.state == "passed":
        if (
            bundle.execution.status != "unknown"
            and result.outcome != bundle.execution.status
        ):
            return _failed_level("receipt_outcome_mismatch", **details)
        outcome_details: dict[str, Any] = {"outcome": result.outcome, **details}
        if bundle.execution.status == "unknown":
            outcome_details["recorded_execution_status"] = "unknown"
        return _passed_level(**outcome_details)
    if result.state == "unsupported":
        return _unsupported_level(_receipt_unsupported_reason(result.reason), **details)
    return _failed_level(_receipt_failure_reason(result.reason), **details)


def _normalize_receipt_attachment(
    receipt: object,
) -> ReceiptAttachment | None:
    """Re-parse an API input so malformed subclasses fail closed at the boundary."""

    if not isinstance(receipt, ReceiptAttachment):
        return None
    try:
        return ReceiptAttachment.from_dict(receipt.to_dict())
    except (AttributeError, EvidenceExternalValidationError, TypeError, ValueError):
        return None


def _load_anchor_provider(
    name: str,
) -> tuple[AnchorProvider | None, str | None]:
    provider, state = _load_named_provider(
        name,
        ANCHOR_PROVIDER_ENTRY_POINT_GROUP,
        _prepare_anchor_provider,
    )
    if state == "unavailable":
        return None, "anchor_provider_unavailable"
    if state == "load_failed":
        return None, "anchor_provider_load_failed"
    return provider, None


def _load_receipt_verifier(
    name: str,
) -> tuple[ReceiptVerifier | None, str | None]:
    verifier, state = _load_named_provider(
        name,
        RECEIPT_VERIFIER_ENTRY_POINT_GROUP,
        _prepare_receipt_verifier,
    )
    if state == "unavailable":
        return None, "receipt_verifier_unavailable"
    if state == "load_failed":
        return None, "receipt_verifier_load_failed"
    return verifier, None


def _load_named_provider(
    name: str,
    group: str,
    prepare_provider: Any,
) -> tuple[Any | None, str | None]:
    if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
        return None, "load_failed"
    try:
        discovered = metadata.entry_points()
        entries = (
            discovered.select(group=group)
            if hasattr(discovered, "select")
            else discovered.get(group, ())
        )
        matches = tuple(entry for entry in entries if entry.name == name)
    except Exception:
        return None, "load_failed"
    if len(matches) != 1:
        return None, "unavailable"
    try:
        loaded = _call_provider(matches[0].load, suppress_output=True)
        if inspect.isawaitable(loaded):
            _call_provider(lambda: _close_coroutine(loaded), suppress_output=True)
            return None, "load_failed"
        prepared = _call_provider(
            lambda: prepare_provider(loaded),
            suppress_output=True,
        )
        if isinstance(loaded, type):
            if not callable(loaded):
                return None, "load_failed"
            loaded = _call_provider(loaded, suppress_output=True)
            if inspect.isawaitable(loaded):
                _call_provider(lambda: _close_coroutine(loaded), suppress_output=True)
                return None, "load_failed"
            prepared = _call_provider(
                lambda: prepare_provider(loaded),
                suppress_output=True,
            )
        elif prepared is None:
            if not inspect.isroutine(loaded):
                return None, "load_failed"
            loaded = _call_provider(loaded, suppress_output=True)
            if inspect.isawaitable(loaded):
                _call_provider(lambda: _close_coroutine(loaded), suppress_output=True)
                return None, "load_failed"
            prepared = _call_provider(
                lambda: prepare_provider(loaded),
                suppress_output=True,
            )
    except Exception:
        return None, "load_failed"
    if prepared is None:
        return None, "load_failed"
    return loaded, None


def _prepare_anchor_provider(provider: object) -> _PreparedAnchorProvider | None:
    try:
        provider_id = getattr(provider, "provider_id")
        protocol_version = getattr(provider, "protocol_version")
        verify = getattr(provider, "verify_continuity")
    except Exception:
        return None
    if (
        not isinstance(provider_id, str)
        or not _EXTERNAL_IDENTIFIER.fullmatch(provider_id)
        or not isinstance(protocol_version, str)
        or not _EXTERNAL_IDENTIFIER.fullmatch(protocol_version)
        or not callable(verify)
    ):
        return None
    return _PreparedAnchorProvider(provider_id, protocol_version, verify)


def _prepare_receipt_verifier(verifier: object) -> _PreparedReceiptVerifier | None:
    try:
        verifier_id = getattr(verifier, "verifier_id")
        protocol_version = getattr(verifier, "protocol_version")
        verify = getattr(verifier, "verify")
    except Exception:
        return None
    if (
        not isinstance(verifier_id, str)
        or not _EXTERNAL_IDENTIFIER.fullmatch(verifier_id)
        or not isinstance(protocol_version, str)
        or not _EXTERNAL_IDENTIFIER.fullmatch(protocol_version)
        or not callable(verify)
    ):
        return None
    return _PreparedReceiptVerifier(verifier_id, protocol_version, verify)


def _normalize_anchor_request(
    request: object,
) -> AnchorVerificationRequest | None:
    if type(request) is not AnchorVerificationRequest:
        return None
    try:
        return AnchorVerificationRequest(
            sequence_id=request.sequence_id,
            entries=request.entries,
            subject_bundle_id=request.subject_bundle_id,
            subject_bundle_digest=request.subject_bundle_digest,
            tenant_digest=request.tenant_digest,
        )
    except (EvidenceExternalValidationError, TypeError, ValueError, AttributeError):
        return None


def _normalize_anchor_result(
    result: object,
) -> tuple[AnchorVerificationResult | None, bool]:
    if inspect.isawaitable(result):
        _close_coroutine(result)
        return None, True
    if type(result) is not AnchorVerificationResult:
        return None, False
    try:
        return AnchorVerificationResult(result.state, result.reason), False
    except (EvidenceExternalValidationError, TypeError, ValueError, AttributeError):
        return None, False


def _normalize_receipt_result(
    result: object,
) -> tuple[ReceiptVerificationResult | None, bool]:
    if inspect.isawaitable(result):
        _close_coroutine(result)
        return None, True
    if type(result) is not ReceiptVerificationResult:
        return None, False
    try:
        return ReceiptVerificationResult(result.state, result.outcome, result.reason), False
    except (EvidenceExternalValidationError, TypeError, ValueError, AttributeError):
        return None, False


def _close_coroutine(value: object) -> None:
    if inspect.iscoroutine(value):
        try:
            value.close()
        except Exception:
            return None


def _anchor_failure_reason(reason: str | None) -> str:
    if reason in _ANCHOR_FAILURE_REASONS:
        return reason
    return "anchor_provider_not_verified"


def _anchor_unsupported_reason(reason: str | None) -> str:
    if reason in _ANCHOR_UNSUPPORTED_REASONS:
        return reason
    return "anchor_provider_unsupported"


def _receipt_failure_reason(reason: str | None) -> str:
    if reason in _RECEIPT_FAILURE_REASONS:
        return reason
    return "receipt_not_verified"


def _receipt_unsupported_reason(reason: str | None) -> str:
    if reason in _RECEIPT_UNSUPPORTED_REASONS:
        return reason
    return "receipt_verifier_unsupported"


def _call_provider(
    callback: Any,
    *,
    suppress_output: bool,
) -> Any:
    if not suppress_output:
        return callback()
    sink = _DiscardingTextStream()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        return callback()


def _stable_reason_codes(
    reasons: Sequence[str],
    *,
    allowed: frozenset[str],
    fallback: str,
) -> tuple[str, ...]:
    return tuple(
        reason if isinstance(reason, str) and reason in allowed else fallback
        for reason in reasons
    )


def _decision_explanation_binding_reasons(
    attachment: DecisionExplanationAttachment,
    *,
    expected_action_digest: str | None,
    expected_policy_version: str | None,
    expected_policy_digest: str | None,
    expected_evidence_bundle_digest: str | None,
) -> list[str]:
    expected_digests = (
        ("action", expected_action_digest, attachment.action_digest),
        ("policy", expected_policy_digest, attachment.policy_digest),
        (
            "evidence_bundle",
            expected_evidence_bundle_digest,
            attachment.evidence_bundle_digest,
        ),
    )
    reasons: list[str] = []
    for label, expected_digest, actual_digest in expected_digests:
        if expected_digest is None:
            continue
        if not _SHA256_HEX.fullmatch(expected_digest):
            reasons.append(f"expected_{label}_digest_invalid")
        elif expected_digest != actual_digest:
            reasons.append(f"{label}_digest_mismatch")
    if (
        expected_policy_version is not None
        and expected_policy_version != attachment.policy_version
    ):
        reasons.append("policy_version_mismatch")
    return reasons


def _require_verified_decision_explanation(
    verified: VerifiedDecisionExplanation,
) -> None:
    try:
        integrity = verified.report["integrity"]
        binding = verified.report["binding"]
        integrity_ok = integrity["ok"]
        binding_ok = binding["ok"]
    except (KeyError, TypeError):
        raise DecisionExplanationVerificationError(
            "decision explanation verification report is invalid"
        ) from None
    if integrity_ok is not True or binding_ok is not True:
        raise DecisionExplanationVerificationError(
            "decision explanation verification did not pass"
        )


def _decision_explanation_report(
    *,
    integrity: dict[str, Any],
    binding: dict[str, Any],
) -> dict[str, Any]:
    return {
        "report_schema_version": _REPORT_SCHEMA_VERSION,
        "integrity": integrity,
        "binding": binding,
    }


def _report(
    *,
    integrity: dict[str, Any],
    authenticity: dict[str, Any] | None = None,
    outcome_verified: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "report_schema_version": _REPORT_SCHEMA_VERSION,
        "integrity": integrity,
        "authenticity": authenticity or _not_requested_level(),
        "outcome_verified": outcome_verified
        or _unsupported_level("receipt_verifier_unsupported"),
    }


def _level(
    *,
    state: str,
    ok: bool | None,
    reasons: Sequence[str],
    **details: Any,
) -> dict[str, Any]:
    return {
        "state": state,
        "ok": ok,
        "reasons": list(reasons),
        **details,
    }


def _passed_level(**details: Any) -> dict[str, Any]:
    return _level(state="passed", ok=True, reasons=(), **details)


def _failed_level(*reasons: str, **details: Any) -> dict[str, Any]:
    return _level(state="failed", ok=False, reasons=reasons, **details)


def _unsupported_level(*reasons: str, **details: Any) -> dict[str, Any]:
    return _level(state="unsupported", ok=False, reasons=reasons, **details)


def _not_requested_level() -> dict[str, Any]:
    return _level(state="not_requested", ok=None, reasons=())


def _not_evaluated_level(reason: str) -> dict[str, Any]:
    return _level(state="not_evaluated", ok=False, reasons=(reason,))


def _emit_and_exit(
    report: dict[str, Any],
    *,
    require_anchor: bool = False,
    require_outcome: bool = False,
) -> int:
    integrity = report["integrity"]
    authenticity = report["authenticity"]
    anchor = integrity.get("audit_continuity")
    outcome_verified = report["outcome_verified"]
    exit_code = EXIT_SUCCESS
    if (
        integrity["ok"] is False
        or authenticity["state"] == "failed"
        or (require_outcome and outcome_verified["state"] == "failed")
    ):
        exit_code = EXIT_VERIFICATION_FAILURE
    elif (
        authenticity["state"] == "unsupported"
        or (require_anchor and anchor is not None and anchor["state"] == "unsupported")
        or (require_outcome and outcome_verified["state"] == "unsupported")
    ):
        exit_code = EXIT_UNSUPPORTED
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
    try:
        print(encoded)
    except OSError:
        return EXIT_VERIFICATION_FAILURE
    return exit_code


def _run() -> int:
    try:
        return main()
    except Exception:
        return _emit_and_exit(
            _report(integrity=_failed_level("verifier_internal_error"))
        )


if __name__ == "__main__":
    raise SystemExit(_run())
