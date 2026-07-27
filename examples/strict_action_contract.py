from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from agent_runtime_governance import (
    ActionContract,
    AuditMiddleware,
    ExecutionMode,
    InvocationOptions,
    JSONLAuditSink,
    PolicyMiddleware,
    ProductionProfile,
    ProviderDescriptor,
    ReconciliationFinding,
    ReconciliationState,
    Runtime,
    SimplePolicy,
    SQLiteIdempotencyStore,
    SQLiteReconciliationLedger,
    StaticIdentityProvider,
    VerifiedPrincipal,
)


def _secret(name: str) -> bytes:
    value = os.environ.get(name, "").encode("utf-8")
    if len(value) < 32:
        raise SystemExit(f"{name} must contain at least 32 bytes")
    return value


class EnvironmentKeyProvider:
    def get_key(self, *, tenant: str, version: str) -> bytes:
        master = _secret("ARG_IDENTITY_DIGEST_KEY")
        return hmac.new(
            master,
            f"agent-action-identity:{version}:{tenant}".encode("utf-8"),
            hashlib.sha256,
        ).digest()


def _load_policy() -> tuple[SimplePolicy, str, str]:
    policy_path = Path(__file__).with_name("policies") / "strict_action_contract.json"
    policy_bytes = policy_path.read_bytes()
    document = json.loads(policy_bytes)
    version = document["version"]
    required_permissions = {
        tool_name: frozenset(permissions)
        for tool_name, permissions in document["required_permissions"].items()
    }
    return (
        SimplePolicy(required_permissions=required_permissions),
        version,
        hashlib.sha256(policy_bytes).hexdigest(),
    )


async def _manual_review_probe(_context) -> ReconciliationFinding:
    """Fail closed when this compact example has no external receipt service."""

    return ReconciliationFinding(
        proposed_state=ReconciliationState.MANUAL_REVIEW,
        evidence_kind="probe",
        evidence={"source": "example-local-state", "conclusion": "manual_review"},
        observed_at=datetime.now(timezone.utc),
    )


def main() -> None:
    state_dir = Path(os.environ.get("ARG_STATE_DIR", ".arg-state")).resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    policy, policy_version, policy_digest = _load_policy()
    profile = ProductionProfile(
        identity_digest_key_provider=EnvironmentKeyProvider(),
        identity_digest_key_version="example-key-v1",
        policy_version=policy_version,
        policy_digest=policy_digest,
    )
    idempotency_path = state_dir / "idempotency.db"
    runtime = Runtime(
        [
            PolicyMiddleware(
                policy,
                version=policy_version,
                digest=policy_digest,
            ),
            AuditMiddleware(
                JSONLAuditSink(
                    state_dir / "audit.jsonl",
                    sign_key=_secret("ARG_AUDIT_HMAC_KEY"),
                ),
                fail_closed=True,
            )
        ],
        idempotency_store=SQLiteIdempotencyStore(idempotency_path),
        reconciliation_ledger=SQLiteReconciliationLedger(idempotency_path),
        identity_provider=StaticIdentityProvider(
            VerifiedPrincipal(
                issuer="example-trusted-gateway",
                subject="example-service-account",
                tenant="example-tenant",
                permissions=frozenset({"ops.write"}),
                source="static",
            )
        ),
        require_verified_identity=True,
        production_profile=profile,
    )
    contract = ActionContract(
        contract_id="examples.set-service-state",
        contract_version=1,
        tool_name="set_service_state",
        execution_mode=ExecutionMode.IDEMPOTENT,
        parameters_schema={
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
                },
                "enabled": {"type": "boolean"},
            },
            "required": ["service", "enabled"],
            "additionalProperties": False,
        },
        effect_class="service.configuration",
        receipt_schema={
            "type": "object",
            "properties": {
                "service": {"type": "string"},
                "enabled": {"type": "boolean"},
            },
            "required": ["service", "enabled"],
            "additionalProperties": False,
        },
    )

    @runtime.tool(
        name="set_service_state",
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=contract,
        reconciliation_provider=ProviderDescriptor(
            provider_id="example.local-manual-review",
            protocol_version="1",
            supported_evidence_kinds=("probe",),
            provider=_manual_review_probe,
        ),
    )
    def set_service_state(service: str, enabled: bool) -> dict[str, object]:
        target = (state_dir / f"{service}.state").resolve()
        target.relative_to(state_dir)
        target.write_text("enabled" if enabled else "disabled", encoding="utf-8")
        return {"service": service, "enabled": enabled}

    report = runtime.seal_production()
    if not report.ready:
        raise SystemExit("strict production readiness failed")
    result = runtime.invoke(
        "set_service_state",
        "worker",
        True,
        _governance=InvocationOptions(idempotency_key="example-change-1"),
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
