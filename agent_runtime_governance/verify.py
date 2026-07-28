"""Offline, machine-readable verification for Governance Evidence Bundle v1.

The command deliberately performs no network access.  It verifies the
portable bundle, an optional detached signature attachment, and caller-supplied
tenant, policy, and contract expectations.  Receipt verification is not part
of this v0.8 work package, so the outcome level remains explicitly
unsupported.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import EvidenceBundle, EvidenceBundleValidationError
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
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class _CliUsageError(ValueError):
    """Raised instead of writing argparse diagnostics to the public protocol."""


class _JsonInputError(ValueError):
    """Raised when a JSON input is not a strict JSON object."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _CliUsageError(message)


def verify_evidence_bundle_document(
    document: Mapping[str, Any],
    *,
    signature: EvidenceSignatureAttachment | None = None,
    trust_roots: EvidenceTrustRoots | None = None,
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

    The result is directly JSON serializable.  A false integrity result is a
    verification failure; an unsupported authenticity result means the
    optional Ed25519 verifier dependency is unavailable.
    """

    authentication_requested = signature is not None or trust_roots is not None
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
        )

    commitment = _commitment_level(
        bundle.bundle_digest,
        signature=signature,
        expected_bundle_digest=expected_bundle_digest,
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
    integrity = _level(
        state="passed" if not integrity_reasons else "failed",
        ok=not integrity_reasons,
        reasons=integrity_reasons,
        bundle_digest=bundle.bundle_digest,
        commitment=commitment,
        audit_continuity=_unsupported_level("anchor_verifier_unsupported"),
    )

    authenticity = _verify_authenticity(
        bundle,
        signature=signature,
        trust_roots=trust_roots,
        requested=authentication_requested,
        verification_time=verification_time,
    )
    return _report(integrity=integrity, authenticity=authenticity)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline verifier and write exactly one JSON report to stdout."""

    parser = _argument_parser()
    try:
        arguments = parser.parse_args(argv)
    except _CliUsageError:
        return _emit_and_exit(_report(integrity=_failed_level("cli_usage_invalid")))

    try:
        document = _read_json_object(arguments.bundle, "bundle")
    except _JsonInputError as exc:
        return _emit_and_exit(_report(integrity=_failed_level(str(exc))))

    signature, signature_reasons = _read_signature(arguments.signature)
    trust_roots, trust_root_reasons = _read_trust_roots(arguments.trust_roots)
    try:
        verification_time = _parse_verification_time(arguments.at)
    except _CliUsageError:
        return _emit_and_exit(
            _report(integrity=_failed_level("verification_time_invalid"))
        )
    report = verify_evidence_bundle_document(
        document,
        signature=signature,
        trust_roots=trust_roots,
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
    return _emit_and_exit(report, require_outcome=arguments.require_outcome)


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
        help="require external outcome verification (currently unsupported)",
    )
    parser.add_argument(
        "--at",
        metavar="RFC3339",
        help="evaluate trust-root validity at this RFC 3339 timestamp",
    )
    return parser


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise _JsonInputError(f"{label}_unreadable") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (json.JSONDecodeError, _JsonInputError) as exc:
        raise _JsonInputError(f"{label}_invalid_json") from exc
    if not isinstance(document, dict):
        raise _JsonInputError(f"{label}_must_be_object")
    return document


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise _JsonInputError("duplicate_json_key")
        document[key] = value
    return document


def _reject_nonfinite_constant(value: str) -> None:
    raise _JsonInputError(f"nonfinite_json_constant_{value}")


def _read_signature(
    path: Path | None,
) -> tuple[EvidenceSignatureAttachment | None, list[str]]:
    if path is None:
        return None, []
    try:
        return EvidenceSignatureAttachment.from_dict(
            _read_json_object(path, "signature")
        ), []
    except (
        EvidenceSignatureValidationError,
        _JsonInputError,
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
        return EvidenceTrustRoots.from_dict(_read_json_object(path, "trust_roots")), []
    except (
        EvidenceTrustRootValidationError,
        _JsonInputError,
        TypeError,
        ValueError,
    ):
        return None, ["trust_roots_invalid"]


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
) -> dict[str, Any]:
    reasons: list[str] = []
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


def _report(
    *,
    integrity: dict[str, Any],
    authenticity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "report_schema_version": _REPORT_SCHEMA_VERSION,
        "integrity": integrity,
        "authenticity": authenticity or _not_requested_level(),
        "outcome_verified": _unsupported_level("receipt_verifier_unsupported"),
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


def _emit_and_exit(report: dict[str, Any], *, require_outcome: bool = False) -> int:
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    integrity = report["integrity"]
    authenticity = report["authenticity"]
    if integrity["ok"] is False or authenticity["state"] == "failed":
        return EXIT_VERIFICATION_FAILURE
    if authenticity["state"] == "unsupported" or require_outcome:
        return EXIT_UNSUPPORTED
    return EXIT_SUCCESS


def _run() -> int:
    try:
        return main()
    except Exception:
        return _emit_and_exit(
            _report(integrity=_failed_level("verifier_internal_error"))
        )


if __name__ == "__main__":
    raise SystemExit(_run())
