from __future__ import annotations

import base64
import json
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from agent_runtime_governance import (
    EVIDENCE_SIGNATURE_ATTACHMENT_SCHEMA_V1,
    EVIDENCE_TRUST_ROOTS_SCHEMA_V1,
    ActionContract,
    Ed25519EvidenceSigner,
    EvidenceBundle,
    EvidenceExecution,
    EvidenceSignatureAttachment,
    EvidenceSignatureValidationError,
    EvidenceSignatureVerificationError,
    EvidenceSigner,
    EvidenceTrustRoot,
    EvidenceTrustRoots,
    EvidenceTrustRootValidationError,
    ExecutionMode,
    sign_evidence_bundle,
    verify_evidence_bundle_signature,
)
from agent_runtime_governance._canonical import rfc8785_json_bytes

_IDENTITY_KEY = b"0123456789abcdef0123456789abcdef"
_SIGNING_KEY_ONE = b"\x01" * 32
_SIGNING_KEY_TWO = b"\x02" * 32


def _at(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 7, day, hour, tzinfo=timezone.utc)


def _bundle() -> EvidenceBundle:
    action = ActionContract(
        contract_id="ops.evidence.sign",
        contract_version=1,
        tool_name="sign_evidence",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}, "secret": {"type": "string"}},
            "required": ["target", "secret"],
            "additionalProperties": False,
        },
        effect_class="governance.export",
    ).bind(
        {"target": "external-ledger", "secret": "tool-parameter-secret-unique"},
        identity_issuer="issuer:privacy-secret",
        principal="principal:privacy-secret",
        tenant="tenant:privacy-secret",
        identity_digest_key=_IDENTITY_KEY,
        identity_digest_key_version="key-v1",
        policy_version="policy-v1",
        policy_digest="a" * 64,
    )
    return EvidenceBundle.from_bound_action(
        action,
        bundle_id="evidence-signature-bundle-1",
        created_at=_at(3),
        execution=EvidenceExecution(
            execution_record_id="evidence-signature-execution-1",
            status="succeeded",
            started_at=_at(2),
            finished_at=_at(2, 1),
        ),
    )


def _public_key(private_key: bytes) -> str:
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    encoded = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(encoded).decode("ascii")


def _root(
    key_id: str = "evidence-key-1",
    private_key: bytes = _SIGNING_KEY_ONE,
    *,
    not_before: datetime = _at(1),
    not_after: datetime = _at(10),
    revoked: bool = False,
) -> EvidenceTrustRoot:
    return EvidenceTrustRoot(
        key_id=key_id,
        algorithm="ed25519",
        public_key=_public_key(private_key),
        not_before=not_before,
        not_after=not_after,
        revoked=revoked,
    )


def _signed_attachment(
    bundle: EvidenceBundle | None = None,
    *,
    key_id: str = "evidence-key-1",
    private_key: bytes = _SIGNING_KEY_ONE,
) -> tuple[EvidenceBundle, EvidenceSignatureAttachment]:
    signed_bundle = bundle or _bundle()
    return signed_bundle, sign_evidence_bundle(
        signed_bundle,
        Ed25519EvidenceSigner.from_private_key_bytes(key_id, private_key),
    )


def test_ed25519_signature_verifies_without_mutating_v1_bundle() -> None:
    bundle = _bundle()
    signer = Ed25519EvidenceSigner.from_private_key_bytes(
        "evidence-key-1", _SIGNING_KEY_ONE
    )
    unsigned = bundle.canonical_unsigned_bytes()
    digest = bundle.bundle_digest

    assert isinstance(signer, EvidenceSigner)
    attachment = sign_evidence_bundle(bundle, signer)
    trust_roots = EvidenceTrustRoots(keys=(_root(),))

    verify_evidence_bundle_signature(bundle, attachment, trust_roots, now=_at(3))
    assert attachment.signing_bytes() == b"arg.evidence.signature.v1\0" + rfc8785_json_bytes(
        {
            "signature_schema_version": "1",
            "key_id": "evidence-key-1",
            "algorithm": "ed25519",
            "bundle_digest": digest,
        }
    )
    assert attachment.to_dict() == {
        "signature_schema_version": "1",
        "key_id": "evidence-key-1",
        "algorithm": "ed25519",
        "bundle_digest": digest,
        "value": attachment.value,
    }
    assert bundle.canonical_unsigned_bytes() == unsigned
    assert bundle.bundle_digest == digest
    assert bundle.to_dict()["signature"] is None


def test_rotated_trust_roots_verify_signatures_from_each_configured_key() -> None:
    bundle = _bundle()
    _, old_attachment = _signed_attachment(bundle, key_id="evidence-key-old")
    _, new_attachment = _signed_attachment(
        bundle,
        key_id="evidence-key-new",
        private_key=_SIGNING_KEY_TWO,
    )
    trust_roots = EvidenceTrustRoots(
        keys=(
            _root("evidence-key-old"),
            _root("evidence-key-new", _SIGNING_KEY_TWO),
        )
    )

    verify_evidence_bundle_signature(bundle, old_attachment, trust_roots, now=_at(3))
    verify_evidence_bundle_signature(bundle, new_attachment, trust_roots, now=_at(3))
    assert EvidenceTrustRoots.from_dict(trust_roots.to_dict()) == trust_roots


def test_verification_rejects_unknown_key() -> None:
    bundle, attachment = _signed_attachment()

    with pytest.raises(EvidenceSignatureVerificationError, match="not trusted"):
        verify_evidence_bundle_signature(
            bundle,
            attachment,
            EvidenceTrustRoots(keys=(_root("different-evidence-key"),)),
            now=_at(3),
        )


def test_verification_rejects_revoked_key() -> None:
    bundle, attachment = _signed_attachment()

    with pytest.raises(EvidenceSignatureVerificationError, match="revoked"):
        verify_evidence_bundle_signature(
            bundle,
            attachment,
            EvidenceTrustRoots(keys=(_root(revoked=True),)),
            now=_at(3),
        )


def test_verification_rejects_expired_key() -> None:
    bundle, attachment = _signed_attachment()

    with pytest.raises(EvidenceSignatureVerificationError, match="expired"):
        verify_evidence_bundle_signature(
            bundle,
            attachment,
            EvidenceTrustRoots(keys=(_root(not_after=_at(3)),)),
            now=_at(3),
        )


def test_verification_rejects_key_before_its_validity_window() -> None:
    bundle, attachment = _signed_attachment()

    with pytest.raises(EvidenceSignatureVerificationError, match="not yet valid"):
        verify_evidence_bundle_signature(
            bundle,
            attachment,
            EvidenceTrustRoots(keys=(_root(not_before=_at(4)),)),
            now=_at(3),
        )


def test_verification_rejects_tampered_signature_and_bundle_binding() -> None:
    bundle, attachment = _signed_attachment()
    trust_roots = EvidenceTrustRoots(
        keys=(
            _root(),
            _root("evidence-key-two", _SIGNING_KEY_ONE),
        )
    )
    tampered_signature = replace(
        attachment,
        value=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )

    with pytest.raises(EvidenceSignatureVerificationError, match="invalid"):
        verify_evidence_bundle_signature(bundle, tampered_signature, trust_roots, now=_at(3))
    with pytest.raises(EvidenceSignatureVerificationError, match="bundle_digest"):
        verify_evidence_bundle_signature(
            bundle,
            replace(attachment, bundle_digest="f" * 64),
            trust_roots,
            now=_at(3),
        )
    with pytest.raises(EvidenceSignatureVerificationError, match="invalid"):
        verify_evidence_bundle_signature(
            bundle,
            replace(attachment, key_id="evidence-key-two"),
            trust_roots,
            now=_at(3),
        )


def test_signature_and_trust_root_documents_fail_closed() -> None:
    bundle, attachment = _signed_attachment()
    root = _root()

    with pytest.raises(EvidenceSignatureValidationError, match="canonical base64"):
        EvidenceSignatureAttachment(
            key_id=attachment.key_id,
            algorithm="ed25519",
            bundle_digest=bundle.bundle_digest,
            value="not-base64",
        )
    with pytest.raises(EvidenceSignatureValidationError, match="only the ed25519"):
        EvidenceSignatureAttachment(
            key_id=attachment.key_id,
            algorithm="rsa",
            bundle_digest=bundle.bundle_digest,
            value=attachment.value,
        )
    with pytest.raises(EvidenceTrustRootValidationError, match="exactly 32 bytes"):
        EvidenceTrustRoot(
            key_id=root.key_id,
            algorithm=root.algorithm,
            public_key=base64.b64encode(b"short").decode("ascii"),
            not_before=root.not_before,
            not_after=root.not_after,
            revoked=False,
        )
    with pytest.raises(EvidenceTrustRootValidationError, match="only the ed25519"):
        EvidenceTrustRoot(
            key_id=root.key_id,
            algorithm="rsa",
            public_key=root.public_key,
            not_before=root.not_before,
            not_after=root.not_after,
            revoked=False,
        )
    with pytest.raises(EvidenceTrustRootValidationError, match="not_after"):
        _root(not_before=_at(3), not_after=_at(3))
    with pytest.raises(EvidenceTrustRootValidationError, match="repeat key_id"):
        EvidenceTrustRoots(keys=(root, root))
    with pytest.raises(EvidenceSignatureValidationError, match="private_key"):
        Ed25519EvidenceSigner.from_private_key_bytes("evidence-key-1", b"short")

    attachment_document = attachment.to_dict()
    attachment_document["unexpected"] = "not-allowed"
    with pytest.raises(EvidenceSignatureValidationError, match="Additional properties"):
        EvidenceSignatureAttachment.from_dict(attachment_document)

    roots_document = EvidenceTrustRoots(keys=(root,)).to_dict()
    roots_document["keys"][0]["revoked"] = 1
    with pytest.raises(EvidenceTrustRootValidationError, match="boolean"):
        EvidenceTrustRoots.from_dict(roots_document)
    roots_document["keys"][0]["revoked"] = False
    roots_document["keys"][0]["not_before"] = "2026-07-01 00:00:00Z"
    with pytest.raises(EvidenceTrustRootValidationError, match="date-time"):
        EvidenceTrustRoots.from_dict(roots_document)


def test_signature_and_trust_root_schemas_are_closed() -> None:
    bundle, attachment = _signed_attachment()
    root = _root()
    attachment_document = attachment.to_dict()
    roots_document = EvidenceTrustRoots(keys=(root,)).to_dict()
    attachment_validator = Draft202012Validator(EVIDENCE_SIGNATURE_ATTACHMENT_SCHEMA_V1)
    roots_validator = Draft202012Validator(
        EVIDENCE_TRUST_ROOTS_SCHEMA_V1,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )

    assert not list(attachment_validator.iter_errors(attachment_document))
    assert not list(roots_validator.iter_errors(roots_document))
    assert attachment_document["bundle_digest"] == bundle.bundle_digest
    attachment_document["parameters"] = {"secret": "tool-parameter-secret-unique"}
    assert any(
        error.validator == "additionalProperties"
        for error in attachment_validator.iter_errors(attachment_document)
    )
    roots_document["keys"][0]["identity"] = "principal:privacy-secret"
    assert any(
        error.validator == "additionalProperties"
        for error in roots_validator.iter_errors(roots_document)
    )


def test_signature_values_are_frozen_and_never_serialize_private_or_bundle_data() -> None:
    bundle, attachment = _signed_attachment()
    signer = Ed25519EvidenceSigner.from_private_key_bytes(
        "evidence-key-1", _SIGNING_KEY_ONE
    )
    encoded = json.dumps(attachment.to_dict(), sort_keys=True)

    with pytest.raises(FrozenInstanceError):
        attachment.key_id = "other"  # type: ignore[misc]
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        EvidenceSignatureAttachment(
            key_id="evidence-key-1",
            algorithm="ed25519",
            bundle_digest=bundle.bundle_digest,
            value=attachment.value,
            parameters={"secret": "tool-parameter-secret-unique"},  # type: ignore[call-arg]
        )
    for forbidden in (
        "tool-parameter-secret-unique",
        "issuer:privacy-secret",
        "principal:privacy-secret",
        "tenant:privacy-secret",
        _SIGNING_KEY_ONE.hex(),
        "private_key",
        "parameters",
        "receipt",
        "result",
    ):
        assert forbidden not in encoded
        assert forbidden not in repr(signer)


def test_core_import_and_optional_signing_fail_cleanly_without_cryptography() -> None:
    repository = Path(__file__).parents[1]
    script = "\n".join(
        (
            "import importlib.abc",
            "import sys",
            "class BlockCryptography(importlib.abc.MetaPathFinder):",
            "    def find_spec(self, fullname, path=None, target=None):",
            "        if fullname == 'cryptography' or fullname.startswith('cryptography.'):",
            "            raise ModuleNotFoundError('cryptography deliberately unavailable')",
            "        return None",
            "sys.meta_path.insert(0, BlockCryptography())",
            "import agent_runtime_governance as arg",
            "assert 'cryptography' not in sys.modules",
            "try:",
            "    arg.Ed25519EvidenceSigner.from_private_key_bytes('evidence-key-1', b'\\x01' * 32)",
            "except arg.EvidenceSigningDependencyError:",
            "    print('optional-dependency-blocked')",
            "else:",
            "    raise AssertionError('optional signing unexpectedly imported cryptography')",
        )
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "optional-dependency-blocked"
