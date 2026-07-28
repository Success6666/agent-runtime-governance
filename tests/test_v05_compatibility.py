from __future__ import annotations

import json
import sqlite3
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
from agent_runtime_governance.approval_store import ApprovalStatus, SQLiteApprovalStore

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


def test_v05_approval_fixture_remains_readable_from_sqlite_store(tmp_path) -> None:
    fixture_text = (FIXTURES / "approval-request.json").read_text(encoding="utf-8")
    payload = json.loads(fixture_text)
    path = tmp_path / "approvals.db"
    store = SQLiteApprovalStore(path)

    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO approvals(
                request_id, request_json, decision_json, status, consumed_at,
                integrity_tag, reservation_token, reserved_until
            ) VALUES (?, ?, NULL, 'pending', NULL, NULL, NULL, NULL)
            """,
            (payload["request_id"], fixture_text),
        )
        connection.commit()

    restored = store.get(payload["request_id"])
    assert restored is not None
    assert restored.status is ApprovalStatus.PENDING
    assert restored.request.action_digest is None
    assert restored.request.to_dict() == {**payload, "action_digest": None}


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
async def test_v05_context_replay_is_analysis_only_and_preview_rebinds(tmp_path) -> None:
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
    assert replayed.bound_action is None
    assert replayed.metadata["replay_mode"] == "analysis"
    assert replayed.metadata["replay_authoritative"] is False
    assert "identity_verified" not in replayed.metadata
    assert "identity_issuer" not in replayed.metadata

    previewed = await runtime.apreview("operate", "node-a")
    assert previewed.bound_action is not None
    assert previewed.bound_action.parameters["target"] == "node-a"
    assert previewed.bound_action.policy_version == "policy-v1"
