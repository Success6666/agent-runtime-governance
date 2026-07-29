"""Human-readable rendering for verified decision-explanation attachments."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from .decision_explanations import (
    DecisionExplanationAttachment,
    DecisionExplanationValidationError,
)
from .verify import (
    EXIT_SUCCESS,
    EXIT_VERIFICATION_FAILURE,
    JsonInputError,
    VerifiedDecisionExplanation,
    read_json_object,
    verify_decision_explanation,
)

_EXIT_USAGE_ERROR = 2


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError(message)


def render_decision_explanation_report(
    verified: VerifiedDecisionExplanation,
) -> str:
    """Render only facts already accepted by the offline verifier."""

    attachment = verified.attachment
    report = verified.report
    lines = [
        f"Decision explanation verification: {report['integrity']['state']}",
        f"Binding: {report['binding']['state']}",
        f"Attachment digest: {attachment.attachment_digest}",
        f"Action digest: {attachment.action_digest}",
        f"Policy: {attachment.policy_version} ({attachment.policy_digest})",
        f"Decision: {attachment.final_decision}",
        f"Risk tier: {attachment.risk_tier}",
        f"Approval required: {str(attachment.requires_approval).lower()}",
        "Controls:",
    ]
    lines.extend(
        "  "
        + " ".join(
            (
                f"{control.control_id}@{control.control_version}",
                f"effect={control.effect}",
                f"result={control.result}",
                f"reason_code={control.reason_code}",
            )
        )
        for control in attachment.controls
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Verify and render a detached attachment without external side effects."""

    parser = _ArgumentParser(
        prog="python -m agent_runtime_governance.inspect",
        description="Inspect a verified policy-decision explanation attachment.",
    )
    parser.add_argument("attachment", metavar="ATTACHMENT", type=Path)
    parser.add_argument("--expected-attachment-digest", metavar="SHA256")
    parser.add_argument("--expected-action-digest", metavar="SHA256")
    parser.add_argument("--expected-policy-version", metavar="VERSION")
    parser.add_argument("--expected-policy-digest", metavar="SHA256")
    parser.add_argument("--expected-evidence-bundle-digest", metavar="SHA256")
    try:
        arguments = parser.parse_args(argv)
    except ValueError as exc:
        print(f"Invalid arguments: {exc}", file=sys.stderr)
        return _EXIT_USAGE_ERROR
    try:
        document = read_json_object(arguments.attachment, "attachment")
        attachment = DecisionExplanationAttachment.from_dict(document)
        verified = verify_decision_explanation(
            attachment,
            expected_attachment_digest=arguments.expected_attachment_digest,
            expected_action_digest=arguments.expected_action_digest,
            expected_policy_version=arguments.expected_policy_version,
            expected_policy_digest=arguments.expected_policy_digest,
            expected_evidence_bundle_digest=(
                arguments.expected_evidence_bundle_digest
            ),
        )
    except (
        DecisionExplanationValidationError,
        JsonInputError,
        TypeError,
        ValueError,
    ):
        print("Decision explanation verification: failed")
        return EXIT_VERIFICATION_FAILURE
    print(render_decision_explanation_report(verified))
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
