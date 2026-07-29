from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncContextManager, AsyncIterator, Callable, Mapping

import pytest

from agent_runtime_governance import (
    ActionContract,
    AuditMiddleware,
    DecisionMiddleware,
    EvidenceBundle,
    EvidenceExecution,
    ExecutionMode,
    GovernanceDenied,
    HumanDecisionProvider,
    InvocationOptions,
    ProductionProfile,
    RiskTier,
    Rule,
    RuleMiddleware,
    Runtime,
    SQLiteApprovalStore,
    SQLiteAuditSink,
    StaticIdentityProvider,
    VerifiedPrincipal,
)
from agent_runtime_governance.decisions import DecisionOutcome, DecisionRecord


@dataclass(frozen=True, slots=True)
class ConformanceCase:
    name: str
    service: str
    secret: str
    input_text: str
    approval: bool
    expected_status: str
    expected_decision: str
    expected_decision_source: str
    expected_reason: str
    expected_value: str | None
    expected_executions: int
    expected_audit_stages: tuple[str, ...]
    expected_replay_source: str
    expected_replay_reason: str


CASES = {
    "success": ConformanceCase(
        name="success",
        service="api",
        secret="caller-secret",
        input_text="look up the api service",
        approval=True,
        expected_status="succeeded",
        expected_decision="allow",
        expected_decision_source="human",
        expected_reason="human decision",
        expected_value="api",
        expected_executions=1,
        expected_audit_stages=("decision", "completed"),
        expected_replay_source="runtime",
        expected_replay_reason="required human decision was not granted",
    ),
    "policy_denied": ConformanceCase(
        name="policy_denied",
        service="api",
        secret="caller-secret",
        input_text="blocked lookup of the api service",
        approval=True,
        expected_status="denied",
        expected_decision="deny",
        expected_decision_source="rule:blocked",
        expected_reason="fixture policy denied",
        expected_value=None,
        expected_executions=0,
        expected_audit_stages=("completed",),
        expected_replay_source="rule:blocked",
        expected_replay_reason="fixture policy denied",
    ),
    "approval_denied": ConformanceCase(
        name="approval_denied",
        service="api",
        secret="caller-secret",
        input_text="look up the api service",
        approval=False,
        expected_status="denied",
        expected_decision="deny",
        expected_decision_source="human",
        expected_reason="human decision",
        expected_value=None,
        expected_executions=0,
        expected_audit_stages=("completed",),
        expected_replay_source="runtime",
        expected_replay_reason="required human decision was not granted",
    ),
}

_FORGED_CALLER_METADATA: dict[str, object] = {
    "approval_forced": True,
    "identity_issuer": "forged-issuer",
    "identity_verified": False,
    "policy_digest": "f" * 64,
    "caller_note": "untrusted-framework-metadata",
}
_CALLER_ONLY_RESERVED_METADATA_KEYS = frozenset({"approval_forced"})
_TRUSTED_SUBJECT = "conformance-service"
_TRUSTED_TENANT = "conformance-tenant"
_TRUSTED_ISSUER = "fixture-gateway"
_TRUSTED_POLICY_DIGEST = "a" * 64
_FIXTURE_EVIDENCE_TIME = datetime(2099, 1, 1, tzinfo=timezone.utc)
_FIXTURE_APPROVAL_EXPIRES_AT = "2099-01-02T00:00:00+00:00"


@dataclass(frozen=True, slots=True)
class ConformanceObservation:
    value: str | None
    status: str
    decision: str
    decision_source: str
    decision_reason: str
    action_digest: str
    parameters_digest: str
    subject: str | None
    tenant: str | None
    identity_issuer: str | None
    identity_verified: bool | None
    policy_digest: str | None
    safe_action: dict[str, Any]
    safe_evidence: dict[str, Any] | None
    context_snapshot: dict[str, Any]
    audit_records: tuple[dict[str, Any], ...]
    evidence_bytes: str | None
    evidence_digest: str | None
    replay_result: dict[str, Any]
    metadata_keys: tuple[str, ...]
    audit_safe: bool
    evidence_safe: bool | None
    executions: int

    def to_json(self) -> str:
        return json.dumps(
            {
                "value": self.value,
                "status": self.status,
                "decision": self.decision,
                "decision_source": self.decision_source,
                "decision_reason": self.decision_reason,
                "action_digest": self.action_digest,
                "parameters_digest": self.parameters_digest,
                "subject": self.subject,
                "tenant": self.tenant,
                "identity_issuer": self.identity_issuer,
                "identity_verified": self.identity_verified,
                "policy_digest": self.policy_digest,
                "safe_action": self.safe_action,
                "safe_evidence": self.safe_evidence,
                "context_snapshot": self.context_snapshot,
                "audit_records": list(self.audit_records),
                "evidence_bytes": self.evidence_bytes,
                "evidence_digest": self.evidence_digest,
                "replay_result": self.replay_result,
                "metadata_keys": list(self.metadata_keys),
                "audit_safe": self.audit_safe,
                "evidence_safe": self.evidence_safe,
                "executions": self.executions,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, value: str) -> "ConformanceObservation":
        data = json.loads(value)
        return cls(
            value=data["value"],
            status=data["status"],
            decision=data["decision"],
            decision_source=data["decision_source"],
            decision_reason=data["decision_reason"],
            action_digest=data["action_digest"],
            parameters_digest=data["parameters_digest"],
            subject=data["subject"],
            tenant=data["tenant"],
            identity_issuer=data["identity_issuer"],
            identity_verified=data["identity_verified"],
            policy_digest=data["policy_digest"],
            safe_action=data["safe_action"],
            safe_evidence=data["safe_evidence"],
            context_snapshot=data["context_snapshot"],
            audit_records=tuple(data["audit_records"]),
            evidence_bytes=data["evidence_bytes"],
            evidence_digest=data["evidence_digest"],
            replay_result=data["replay_result"],
            metadata_keys=tuple(data["metadata_keys"]),
            audit_safe=data["audit_safe"],
            evidence_safe=data["evidence_safe"],
            executions=data["executions"],
        )


class _FixtureKeyProvider:
    def get_key(self, *, tenant: str, version: str) -> bytes:
        assert tenant == _TRUSTED_TENANT
        assert version == "fixture-key-v1"
        return b"k" * 32


class _FixtureDecisionMiddleware(DecisionMiddleware):
    """Keeps evidence bytes deterministic across equivalent entry points."""

    def _expires_at(self) -> str:
        return _FIXTURE_APPROVAL_EXPIRES_AT


def _fixture_decision_provider(case: ConformanceCase) -> HumanDecisionProvider:
    outcome = DecisionOutcome.ALLOW if case.approval else DecisionOutcome.DENY

    def decide(_context: Any, _request: Any) -> DecisionRecord:
        return DecisionRecord(
            outcome=outcome,
            reason="human decision",
            source="human",
            decision_id=f"conformance-{case.name}-decision",
            issued_at=_FIXTURE_EVIDENCE_TIME.isoformat(),
            expires_at=_FIXTURE_APPROVAL_EXPIRES_AT,
        )

    return HumanDecisionProvider(decide, approver="fixture-approver")


class ConformanceHarness:
    def __init__(
        self,
        runtime: Runtime,
        executions: list[tuple[str, str]],
        approval_store: SQLiteApprovalStore,
        audit_sink: SQLiteAuditSink,
    ) -> None:
        self._runtime = runtime
        self._executions = executions
        self._approval_store = approval_store
        self._audit_sink = audit_sink

    async def invoke(
        self,
        case: ConformanceCase,
        service: str,
        secret: str,
        caller_metadata: Mapping[str, object],
    ) -> ConformanceObservation:
        try:
            result = await self._runtime.arun(
                "conformance_lookup",
                service,
                secret,
                _governance=InvocationOptions(
                    input_text=case.input_text,
                    request_id=f"conformance-{case.name}",
                    user="forged-user",
                    tenant="forged-tenant",
                    permissions=frozenset({"forged:all"}),
                    identity_claims={"subject": "forged-user"},
                    metadata=dict(caller_metadata),
                ),
            )
            value = result.value
            context = result.context
        except GovernanceDenied as error:
            value = None
            context = error.context

        assert context.bound_action is not None
        assert context.decision is not None
        audit_events = self._audit_sink.read_verified()
        audit_safe = all(
            secret not in json.dumps(event, sort_keys=True) for event in audit_events
        )
        assert all(
            event["trace_id"] == context.trace_id
            and event["span_id"] == context.span_id
            and event["request_id"] == context.request_id
            for event in audit_events
        )
        safe_evidence, evidence_bytes, evidence_digest, evidence_safe = (
            self._safe_evidence(context, secret)
            if value is not None
            else (None, None, None, None)
        )
        executions_before_replay = len(self._executions)
        replayed = await self._runtime.areplay(context)
        assert len(self._executions) == executions_before_replay
        assert len(self._audit_sink.read_verified()) == len(audit_events)
        return ConformanceObservation(
            value=value,
            status=context.status.value,
            decision=context.decision.outcome.value,
            decision_source=context.decision.source,
            decision_reason=context.decision.reason,
            action_digest=context.bound_action.action_digest,
            parameters_digest=context.bound_action.parameters_digest,
            subject=context.user,
            tenant=context.tenant,
            identity_issuer=context.metadata.get("identity_issuer"),
            identity_verified=context.metadata.get("identity_verified"),
            policy_digest=context.metadata.get("policy_digest"),
            safe_action=context.bound_action.to_evidence_dict(),
            safe_evidence=safe_evidence,
            context_snapshot=_safe_context_snapshot(context),
            audit_records=tuple(_safe_audit_record(event) for event in audit_events),
            evidence_bytes=evidence_bytes,
            evidence_digest=evidence_digest,
            replay_result=_safe_context_snapshot(replayed),
            metadata_keys=tuple(sorted(context.metadata)),
            audit_safe=audit_safe,
            evidence_safe=evidence_safe,
            executions=len(self._executions),
        )

    def _safe_evidence(
        self, context, secret: str
    ) -> tuple[dict[str, Any], str, str, bool]:
        stored = self._approval_store.get(context.request_id)
        assert stored is not None
        assert stored.decision is not None
        assert context.bound_action is not None
        bundle = EvidenceBundle.from_bound_action(
            context.bound_action,
            bundle_id="conformance-success-evidence",
            created_at=_FIXTURE_EVIDENCE_TIME,
            approval_request=stored.request,
            decision=stored.decision,
            execution=EvidenceExecution(
                "conformance-success-execution",
                "succeeded",
                _FIXTURE_EVIDENCE_TIME,
                finished_at=_FIXTURE_EVIDENCE_TIME,
            ),
        )
        document = bundle.to_dict()
        projection = {
            "schema_version": document["schema_version"],
            "action": document["action"],
            "identity": document["identity"],
            "policy": document["policy"],
            "execution_status": document["execution"]["status"],
            "redactions": document["redactions"],
        }
        return (
            projection,
            bundle.canonical_unsigned_bytes().hex(),
            bundle.bundle_digest,
            secret not in json.dumps(document, sort_keys=True),
        )


def _safe_context_snapshot(context) -> dict[str, Any]:
    document = context.to_dict()
    if context.bound_action is not None:
        document["bound_action"] = context.bound_action.to_evidence_dict()
    return _safe_context_document(document)


def _safe_audit_record(record: Mapping[str, Any]) -> dict[str, Any]:
    context = record["context"]
    assert isinstance(context, Mapping)
    return {
        "sequence": record["sequence"],
        "schema_version": record["schema_version"],
        "stage": record["stage"],
        "request_id": record["request_id"],
        "tool_name": record["tool_name"],
        "contract_id": record["contract_id"],
        "contract_version": record["contract_version"],
        "action_digest": record["action_digest"],
        "risk_tier": record["risk_tier"],
        "risk_score": record["risk_score"],
        "status": record["status"],
        "decision": record["decision"],
        "reason": record["reason"],
        "context": _safe_context_document(context),
    }


def _safe_context_document(document: Mapping[str, Any]) -> dict[str, Any]:
    tool_call = document["tool_call"]
    assert isinstance(tool_call, Mapping)
    history = document["history"]
    assert isinstance(history, list)
    metadata = document["metadata"]
    assert isinstance(metadata, Mapping)
    return {
        "request_id": document["request_id"],
        "subject": document["user"],
        "tenant": document["tenant"],
        "tool_name": tool_call["name"],
        "execution_mode": document["execution_mode"],
        "bound_action": document["bound_action"],
        "risk_tier": document["risk_tier"],
        "risk_score": document["risk_score"],
        "requires_approval": document["requires_approval"],
        "approval_granted": document["approval_granted"],
        "approval_request_id": document["approval_request_id"],
        "approval_decision_present": document["approval_decision_id"] is not None,
        "status": document["status"],
        "decision": _safe_decision_snapshot(document["decision"]),
        "history": [_safe_history_entry(entry) for entry in history],
        "metadata_keys": sorted(metadata),
        "trusted_metadata": {
            key: metadata[key]
            for key in (
                "identity_issuer",
                "identity_verified",
                "policy_digest",
                "policy_version",
            )
            if key in metadata
        },
        "replay_mode": metadata.get("replay_mode"),
        "replay_authoritative": metadata.get("replay_authoritative"),
        "result_present": document["result"] is not None,
        "error_present": document["error"] is not None,
    }


def _safe_history_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    data = entry["data"]
    assert isinstance(data, Mapping)
    return {
        "middleware": entry["middleware"],
        "outcome": entry["outcome"],
        "reason": entry["reason"],
        "data": {
            key: data[key]
            for key in (
                "stage",
                "critical",
                "request_id",
                "arguments_digest",
                "policy_version",
                "policy_digest",
                "action_digest",
                "approver",
            )
            if key in data
        },
    }


def _safe_decision_snapshot(
    decision: DecisionRecord | Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if decision is None:
        return None
    document = decision.to_dict() if isinstance(decision, DecisionRecord) else decision
    return {
        key: document[key]
        for key in (
            "outcome",
            "reason",
            "source",
            "request_id",
            "approver",
            "tool_name",
            "arguments_digest",
            "risk_tier",
            "policy_version",
            "policy_digest",
            "subject",
            "tenant",
            "identity_issuer",
            "action_digest",
        )
    }


@asynccontextmanager
async def _new_harness(
    directory: Path,
    case: ConformanceCase,
) -> AsyncIterator[ConformanceHarness]:
    directory.mkdir()
    executions: list[tuple[str, str]] = []
    approval_store = SQLiteApprovalStore(
        directory / "approvals.db", sign_key=b"p" * 32
    )
    audit_sink = SQLiteAuditSink(directory / "audit.db", sign_key=b"a" * 32)
    runtime = Runtime(
        [
            RuleMiddleware(
                [Rule("blocked", r"\bblocked\b", "fixture policy denied")]
            ),
            _FixtureDecisionMiddleware(
                _fixture_decision_provider(case),
                store=approval_store,
            ),
            AuditMiddleware(
                audit_sink, fail_closed=True
            ),
        ],
        identity_provider=StaticIdentityProvider(
            VerifiedPrincipal(
                issuer=_TRUSTED_ISSUER,
                subject=_TRUSTED_SUBJECT,
                tenant=_TRUSTED_TENANT,
                permissions=frozenset({"tool:invoke"}),
                source="fixture",
                verified_at="2026-01-01T00:00:00+00:00",
            )
        ),
        require_verified_identity=True,
        production_profile=ProductionProfile(
            identity_digest_key_provider=_FixtureKeyProvider(),
            identity_digest_key_version="fixture-key-v1",
            policy_version="fixture-policy-v1",
            policy_digest=_TRUSTED_POLICY_DIGEST,
        ),
    )
    contract = ActionContract(
        contract_id="conformance.lookup",
        contract_version=1,
        tool_name="conformance_lookup",
        execution_mode=ExecutionMode.READ_ONLY,
        parameters_schema={
            "type": "object",
            "properties": {
                "service": {"type": "string"},
                "secret": {"type": "string"},
            },
            "required": ["service", "secret"],
            "additionalProperties": False,
        },
        effect_class="service.lookup",
    )

    @runtime.tool(
        name="conformance_lookup",
        risk=RiskTier.HIGH,
        requires_approval=True,
        execution_mode=ExecutionMode.READ_ONLY,
        action_contract=contract,
    )
    async def conformance_lookup(service: str, secret: str) -> str:
        executions.append((service, secret))
        return service

    assert runtime.seal_production().ready
    try:
        yield ConformanceHarness(runtime, executions, approval_store, audit_sink)
    finally:
        await runtime.aclose()


def _assert_protected_semantics(
    case: ConformanceCase,
    observation: ConformanceObservation,
) -> None:
    assert observation.value == case.expected_value
    assert observation.status == case.expected_status
    assert observation.decision == case.expected_decision
    assert observation.decision_source == case.expected_decision_source
    assert observation.decision_reason == case.expected_reason
    assert observation.executions == case.expected_executions
    assert observation.subject == _TRUSTED_SUBJECT
    assert observation.tenant == _TRUSTED_TENANT
    assert observation.identity_issuer == _TRUSTED_ISSUER
    assert observation.identity_verified is True
    assert observation.policy_digest == _TRUSTED_POLICY_DIGEST
    assert observation.action_digest == observation.safe_action["action_digest"]
    assert observation.parameters_digest == observation.safe_action["parameters_digest"]
    assert "parameters" not in observation.safe_action
    assert "caller-secret" not in json.dumps(observation.safe_action, sort_keys=True)
    assert observation.audit_safe is True
    assert observation.context_snapshot["status"] == case.expected_status
    assert observation.context_snapshot["bound_action"] == observation.safe_action
    assert observation.context_snapshot["subject"] == _TRUSTED_SUBJECT
    assert observation.context_snapshot["tenant"] == _TRUSTED_TENANT
    assert observation.context_snapshot["trusted_metadata"] == {
        "identity_issuer": _TRUSTED_ISSUER,
        "identity_verified": True,
        "policy_digest": _TRUSTED_POLICY_DIGEST,
        "policy_version": "fixture-policy-v1",
    }
    assert observation.audit_records
    assert [record["stage"] for record in observation.audit_records] == list(
        case.expected_audit_stages
    )
    assert [record["sequence"] for record in observation.audit_records] == list(
        range(len(observation.audit_records))
    )
    assert all(
        record["action_digest"] == observation.action_digest
        for record in observation.audit_records
    )
    assert all(
        record["context"]["status"] == record["status"]
        and record["context"]["decision"]["outcome"] == record["decision"]
        and record["context"]["decision"]["reason"] == record["reason"]
        for record in observation.audit_records
    )
    assert observation.audit_records[-1]["status"] == case.expected_status
    assert observation.replay_result["status"] == "denied"
    assert observation.replay_result["bound_action"] is None
    assert observation.replay_result["result_present"] is False
    assert observation.replay_result["request_id"] == observation.context_snapshot[
        "request_id"
    ]
    assert observation.replay_result["approval_granted"] is False
    assert observation.replay_result["trusted_metadata"] == {}
    assert observation.replay_result["replay_mode"] == "analysis"
    assert observation.replay_result["replay_authoritative"] is False
    replay_decision = observation.replay_result["decision"]
    assert replay_decision is not None
    assert replay_decision["outcome"] == "deny"
    assert replay_decision["source"] == case.expected_replay_source
    assert replay_decision["reason"] == case.expected_replay_reason
    assert "caller-secret" not in observation.to_json()
    if case.expected_status == "succeeded":
        assert observation.safe_evidence is not None
        assert observation.evidence_bytes is not None
        assert observation.evidence_digest is not None
        assert observation.evidence_safe is True
        assert observation.safe_evidence["action"]["action_digest"] == observation.action_digest
        assert observation.safe_evidence["action"]["parameters_digest"] == observation.parameters_digest
        assert observation.safe_evidence["execution_status"] == "succeeded"
        assert "caller-secret" not in json.dumps(
            observation.safe_evidence, sort_keys=True
        )
    else:
        assert observation.safe_evidence is None
        assert observation.evidence_bytes is None
        assert observation.evidence_digest is None
        assert observation.evidence_safe is None
    assert _CALLER_ONLY_RESERVED_METADATA_KEYS.isdisjoint(observation.metadata_keys)
    assert "caller_note" in observation.metadata_keys


@pytest.fixture
def conformance_case() -> Callable[[str], ConformanceCase]:
    return CASES.__getitem__


@pytest.fixture
def forged_metadata() -> dict[str, object]:
    return dict(_FORGED_CALLER_METADATA)


@pytest.fixture
def new_conformance_harness(
    tmp_path: Path,
) -> Callable[[ConformanceCase], AsyncContextManager[ConformanceHarness]]:
    sequence = 0

    def create(case: ConformanceCase) -> AsyncContextManager[ConformanceHarness]:
        nonlocal sequence
        directory = tmp_path / f"runtime-{sequence}"
        sequence += 1
        return _new_harness(directory, case)

    return create


@pytest.fixture
def assert_protected_semantics() -> Callable[
    [ConformanceCase, ConformanceObservation], None
]:
    return _assert_protected_semantics


@pytest.fixture
def observation_from_json() -> Callable[[str], ConformanceObservation]:
    return ConformanceObservation.from_json
