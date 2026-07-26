from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_runtime_governance import (
    ActionContract,
    ApprovalRequest,
    AuditMiddleware,
    ExecutionContext,
    ExecutionMode,
    JSONLAuditSink,
    ProductionProfile,
    RiskTier,
    Runtime,
    SQLiteIdempotencyStore,
    StaticIdentityProvider,
    VerifiedPrincipal,
)

FIXTURES = Path(__file__).parent / "fixtures" / "v0.5"


class KeyProvider:
    def get_key(self, *, tenant: str, version: str) -> bytes:
        return b"k" * 32


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_v05_context_without_bound_action_restores_deterministically() -> None:
    payload = _load("execution-context.json")
    restored = ExecutionContext.from_dict(payload)

    assert restored.bound_action is None
    assert restored.request_id == "legacy-context-1"
    assert restored.tool_call.args == ("node-a",)
    assert ExecutionContext.from_dict(restored.to_dict()) == restored


def test_v05_approval_without_action_digest_remains_readable() -> None:
    request = ApprovalRequest.from_dict(_load("approval-request.json"))

    assert request.action_digest is None
    assert request.request_id == "legacy-approval-1"
    assert ApprovalRequest.from_dict(request.to_dict()) == request


def test_v05_idempotency_fixture_survives_store_restart(tmp_path) -> None:
    fixture = _load("idempotency-entry.json")
    path = tmp_path / "idempotency.db"
    first = SQLiteIdempotencyStore(path)
    claim = first.acquire(
        fixture["namespace"], fixture["key"], fixture["fingerprint"]
    )
    first.complete(claim, fixture["result"])

    restarted = SQLiteIdempotencyStore(path)
    restored = restarted.acquire(
        fixture["namespace"], fixture["key"], fixture["fingerprint"]
    )
    assert restored.owner is False
    assert restored.future.result() == fixture["result"]


@pytest.mark.asyncio
async def test_v05_context_can_be_rebound_for_contracted_replay(tmp_path) -> None:
    principal = VerifiedPrincipal(
        issuer="trusted-gateway",
        subject="service-account",
        tenant="tenant-a",
        source="static",
    )
    profile = ProductionProfile(
        identity_digest_key_provider=KeyProvider(),
        identity_digest_key_version="key-v1",
        policy_version="policy-v1",
        policy_digest="a" * 64,
    )
    runtime = Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            )
        ],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=StaticIdentityProvider(principal),
        require_verified_identity=True,
        production_profile=profile,
    )
    contract = ActionContract(
        contract_id="ops.operate",
        contract_version=1,
        tool_name="operate",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        effect_class="service.change",
    )

    @runtime.tool(
        name="operate",
        risk=RiskTier.HIGH,
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract,
    )
    def operate(target: str) -> bool:
        return True

    runtime.seal_production()
    recorded = ExecutionContext.from_dict(_load("execution-context.json"))
    replayed = await runtime.areplay(recorded)

    assert replayed.request_id == recorded.request_id
    assert replayed.bound_action is not None
    assert replayed.bound_action.parameters["target"] == "node-a"
    assert replayed.bound_action.policy_version == "policy-v1"
