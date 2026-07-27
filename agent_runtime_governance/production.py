from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from ._serialization import thaw as _thaw
from .action_contracts import ActionContract
from .context import ExecutionMode
from .middleware.audit import AuditMiddleware
from .middleware.decision import DecisionMiddleware
from .pipeline import Pipeline
from .reconciliation import SQLiteReconciliationLedger
from .registry import SQLiteIdempotencyStore, ToolSpec

_KEY_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_POLICY_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class IdentityDigestKeyProvider(Protocol):
    """Resolve tenant-scoped action identity keys without exposing them in reports."""

    def get_key(self, *, tenant: str, version: str) -> bytes: ...


class PreconditionDigestProvider(Protocol):
    """Resolve the current digest for contract-declared external preconditions."""

    def get_digest(
        self,
        *,
        contract: ActionContract,
        parameters: Mapping[str, Any],
        principal: str,
        tenant: str,
    ) -> str: ...


class ProductionReadinessState(str, Enum):
    READY = "ready"
    MIGRATION_ONLY = "migration_only"
    INVALID = "invalid"


class ProductionReadinessReason(str, Enum):
    CONTRACT_REQUIRED = "contract.required"
    CONTRACT_TOOL_MISMATCH = "contract.tool_mismatch"
    CONTRACT_EXECUTION_MODE_MISMATCH = "contract.execution_mode_mismatch"
    CONTRACT_PARAMETERS_SCHEMA_MISMATCH = "contract.parameters_schema_mismatch"
    CONTRACT_RECEIPT_SCHEMA_MISMATCH = "contract.receipt_schema_mismatch"
    CONTRACT_PARAMETER_LIMIT_MISMATCH = "contract.parameter_limit_mismatch"
    IDENTITY_DIGEST_KEY_PROVIDER_REQUIRED = "identity_digest.key_provider_required"
    IDENTITY_DIGEST_KEY_VERSION_REQUIRED = "identity_digest.key_version_required"
    POLICY_IDENTITY_REQUIRED = "policy.identity_required"
    POLICY_MIDDLEWARE_IDENTITY_REQUIRED = "policy.middleware_identity_required"
    POLICY_IDENTITY_MISMATCH = "policy.identity_mismatch"
    POLICY_FAIL_CLOSED_REQUIRED = "policy.fail_closed_required"
    PRECONDITION_PROVIDER_REQUIRED = "precondition.provider_required"
    IDENTITY_PROVIDER_REQUIRED = "identity.provider_required"
    IDENTITY_PROVIDER_NOT_TRUSTED = "identity.provider_not_trusted"
    VERIFIED_IDENTITY_REQUIRED = "identity.verification_required"
    IDENTITY_REPLAY_DURABLE_REQUIRED = "identity.replay_store_durable_required"
    IDEMPOTENCY_DURABLE_REQUIRED = "idempotency.durable_store_required"
    RECONCILIATION_DURABLE_REQUIRED = "reconciliation.durable_ledger_required"
    RECONCILIATION_ATOMIC_LEDGER_REQUIRED = "reconciliation.atomic_ledger_required"
    RECONCILIATION_COLOCATED_REQUIRED = "reconciliation.colocated_ledger_required"
    RECONCILIATION_PROVIDER_REQUIRED = "reconciliation.provider_required"
    APPROVAL_MIDDLEWARE_REQUIRED = "approval.middleware_required"
    APPROVAL_STORE_DURABLE_REQUIRED = "approval.durable_store_required"
    APPROVAL_INTEGRITY_REQUIRED = "approval.integrity_protection_required"
    AUDIT_MIDDLEWARE_REQUIRED = "audit.middleware_required"
    AUDIT_SINK_DURABLE_REQUIRED = "audit.durable_sink_required"
    AUDIT_INTEGRITY_REQUIRED = "audit.integrity_protection_required"
    AUDIT_FAIL_CLOSED_REQUIRED = "audit.fail_closed_required"


@dataclass(frozen=True, slots=True)
class ToolProductionReadiness:
    tool_name: str
    execution_mode: ExecutionMode
    state: ProductionReadinessState
    reasons: tuple[ProductionReadinessReason, ...] = ()
    contract_id: str | None = None
    contract_version: int | None = None
    contract_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "execution_mode": self.execution_mode.value,
            "state": self.state.value,
            "reasons": [reason.value for reason in self.reasons],
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "contract_digest": self.contract_digest,
        }


@dataclass(frozen=True, slots=True)
class ProductionReadinessReport:
    profile_version: int
    tools: tuple[ToolProductionReadiness, ...]
    runtime_reasons: tuple[ProductionReadinessReason, ...] = ()

    @property
    def ready(self) -> bool:
        return not self.runtime_reasons and all(
            tool.state is ProductionReadinessState.READY for tool in self.tools
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_version": self.profile_version,
            "ready": self.ready,
            "runtime_reasons": [reason.value for reason in self.runtime_reasons],
            "tools": [tool.to_dict() for tool in self.tools],
        }


@dataclass(frozen=True, slots=True, repr=False)
class ProductionProfile:
    """Versioned fail-closed startup requirements for governed tools."""

    identity_digest_key_provider: IdentityDigestKeyProvider | None = field(
        default=None, repr=False, compare=False
    )
    identity_digest_key_version: str | None = None
    policy_version: str | None = None
    policy_digest: str | None = None
    precondition_digest_provider: PreconditionDigestProvider | None = field(
        default=None, repr=False, compare=False
    )
    version: int = 1

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise TypeError("production profile version must be an integer")
        if self.version != 1:
            raise ValueError("unsupported production profile version")
        provider = self.identity_digest_key_provider
        if provider is not None and not callable(getattr(provider, "get_key", None)):
            raise TypeError(
                "identity_digest_key_provider must define get_key(tenant, version)"
            )
        key_version = self.identity_digest_key_version
        if key_version is not None and (
            type(key_version) is not str or not _KEY_VERSION.fullmatch(key_version)
        ):
            raise ValueError("identity_digest_key_version is invalid")
        if (self.policy_version is None) != (self.policy_digest is None):
            raise ValueError(
                "policy_version and policy_digest must be configured together"
            )
        if self.policy_version is not None and not _POLICY_VERSION.fullmatch(
            self.policy_version
        ):
            raise ValueError("policy_version is invalid")
        if self.policy_digest is not None and not _SHA256.fullmatch(
            self.policy_digest
        ):
            raise ValueError("policy_digest must be a SHA-256 hex digest")
        precondition_provider = self.precondition_digest_provider
        if precondition_provider is not None and not callable(
            getattr(precondition_provider, "get_digest", None)
        ):
            raise TypeError(
                "precondition_digest_provider must define get_digest(...)"
            )

    def inventory(
        self, tools: Iterable[ToolSpec[Any, Any]]
    ) -> ProductionReadinessReport:
        entries = tuple(
            self._tool_readiness(spec)
            for spec in sorted(tools, key=lambda item: item.name)
        )
        return ProductionReadinessReport(profile_version=self.version, tools=entries)

    def evaluate(
        self,
        tools: Iterable[ToolSpec[Any, Any]],
        *,
        pipeline: Pipeline,
        idempotency_store: Any,
        reconciliation_ledger: Any,
        identity_provider: Any,
        require_verified_identity: bool,
    ) -> ProductionReadinessReport:
        tool_items = tuple(tools)
        inventory = self.inventory(tool_items)
        entries = inventory.tools
        side_effecting = any(
            tool.execution_mode is not ExecutionMode.READ_ONLY for tool in entries
        )
        approval_required = any(spec.requires_approval for spec in tool_items)
        idempotent_tools = tuple(
            spec
            for spec in tool_items
            if spec.execution_mode is ExecutionMode.IDEMPOTENT
        )
        reasons: list[ProductionReadinessReason] = []

        if entries:
            if identity_provider is None:
                reasons.append(ProductionReadinessReason.IDENTITY_PROVIDER_REQUIRED)
            elif not _capability(identity_provider, "production_trusted"):
                reasons.append(
                    ProductionReadinessReason.IDENTITY_PROVIDER_NOT_TRUSTED
                )
            if not require_verified_identity:
                reasons.append(ProductionReadinessReason.VERIFIED_IDENTITY_REQUIRED)
            if hasattr(identity_provider, "replay_store") and not _capability(
                identity_provider.replay_store, "production_durable"
            ):
                reasons.append(
                    ProductionReadinessReason.IDENTITY_REPLAY_DURABLE_REQUIRED
                )
            if side_effecting and not _capability(
                idempotency_store, "production_durable"
            ):
                reasons.append(
                    ProductionReadinessReason.IDEMPOTENCY_DURABLE_REQUIRED
                )
            self._reconciliation_reasons(
                idempotent_tools,
                idempotency_store,
                reconciliation_ledger,
                reasons,
            )
            self._audit_reasons(pipeline, reasons)
            if any(tool.contract_id is not None for tool in entries):
                self._policy_reasons(pipeline, reasons)

        if approval_required:
            self._approval_reasons(pipeline, reasons)

        return ProductionReadinessReport(
            profile_version=self.version,
            tools=entries,
            runtime_reasons=tuple(dict.fromkeys(reasons)),
        )

    def _tool_readiness(self, spec: ToolSpec[Any, Any]) -> ToolProductionReadiness:
        contract = spec.action_contract
        if contract is None:
            state = (
                ProductionReadinessState.READY
                if spec.execution_mode is ExecutionMode.READ_ONLY
                else ProductionReadinessState.MIGRATION_ONLY
            )
            reasons = (
                ()
                if state is ProductionReadinessState.READY
                else (ProductionReadinessReason.CONTRACT_REQUIRED,)
            )
            return ToolProductionReadiness(
                tool_name=spec.name,
                execution_mode=spec.execution_mode,
                state=state,
                reasons=reasons,
            )

        reasons = self._contract_reasons(spec, contract)
        return ToolProductionReadiness(
            tool_name=spec.name,
            execution_mode=spec.execution_mode,
            state=(
                ProductionReadinessState.READY
                if not reasons
                else ProductionReadinessState.INVALID
            ),
            reasons=reasons,
            contract_id=contract.contract_id,
            contract_version=contract.contract_version,
            contract_digest=contract.contract_digest,
        )

    def _contract_reasons(
        self,
        spec: ToolSpec[Any, Any],
        contract: ActionContract,
    ) -> tuple[ProductionReadinessReason, ...]:
        reasons: list[ProductionReadinessReason] = []
        if contract.tool_name != spec.name:
            reasons.append(ProductionReadinessReason.CONTRACT_TOOL_MISMATCH)
        if contract.execution_mode is not spec.execution_mode:
            reasons.append(ProductionReadinessReason.CONTRACT_EXECUTION_MODE_MISMATCH)
        if spec.parameters_schema is not None and not _schemas_equal(
            spec.parameters_schema, contract.parameters_schema
        ):
            reasons.append(
                ProductionReadinessReason.CONTRACT_PARAMETERS_SCHEMA_MISMATCH
            )
        if (
            spec.max_parameters_bytes is not None
            and spec.max_parameters_bytes != contract.max_parameters_bytes
        ):
            reasons.append(ProductionReadinessReason.CONTRACT_PARAMETER_LIMIT_MISMATCH)
        if spec.result_schema is not None and not _schemas_equal(
            spec.result_schema, contract.receipt_schema
        ):
            reasons.append(
                ProductionReadinessReason.CONTRACT_RECEIPT_SCHEMA_MISMATCH
            )
        if self.identity_digest_key_provider is None:
            reasons.append(
                ProductionReadinessReason.IDENTITY_DIGEST_KEY_PROVIDER_REQUIRED
            )
        if self.identity_digest_key_version is None:
            reasons.append(
                ProductionReadinessReason.IDENTITY_DIGEST_KEY_VERSION_REQUIRED
            )
        if self.policy_version is None or self.policy_digest is None:
            reasons.append(ProductionReadinessReason.POLICY_IDENTITY_REQUIRED)
        if (
            contract.precondition_requirements
            and self.precondition_digest_provider is None
        ):
            reasons.append(ProductionReadinessReason.PRECONDITION_PROVIDER_REQUIRED)
        return tuple(reasons)

    def _policy_reasons(
        self,
        pipeline: Pipeline,
        reasons: list[ProductionReadinessReason],
    ) -> None:
        for middleware in pipeline:
            if not getattr(
                middleware, "requires_action_policy_identity", False
            ):
                continue
            if getattr(
                middleware, "requires_fail_closed_in_production", False
            ) and not getattr(middleware, "fail_closed", False):
                reasons.append(
                    ProductionReadinessReason.POLICY_FAIL_CLOSED_REQUIRED
                )
            identity = getattr(middleware, "action_policy_identity", None)
            configured = identity() if callable(identity) else None
            if configured is None:
                reasons.append(
                    ProductionReadinessReason.POLICY_MIDDLEWARE_IDENTITY_REQUIRED
                )
                continue
            version, digest = configured
            # The profile is the action identity source of truth. A policy
            # middleware may only advertise that exact deployment identity.
            if version != self.policy_version or digest != self.policy_digest:
                reasons.append(
                    ProductionReadinessReason.POLICY_IDENTITY_MISMATCH
                )

    @staticmethod
    def _approval_reasons(
        pipeline: Pipeline, reasons: list[ProductionReadinessReason]
    ) -> None:
        middleware = next(
            (item for item in pipeline if isinstance(item, DecisionMiddleware)), None
        )
        if middleware is None:
            reasons.append(ProductionReadinessReason.APPROVAL_MIDDLEWARE_REQUIRED)
            return
        if middleware.store is None or not _capability(
            middleware.store, "production_durable"
        ):
            reasons.append(ProductionReadinessReason.APPROVAL_STORE_DURABLE_REQUIRED)
        elif not _capability(
            middleware.store, "production_integrity_protected"
        ):
            reasons.append(ProductionReadinessReason.APPROVAL_INTEGRITY_REQUIRED)

    @staticmethod
    def _reconciliation_reasons(
        tools: tuple[ToolSpec[Any, Any], ...],
        idempotency_store: Any,
        reconciliation_ledger: Any,
        reasons: list[ProductionReadinessReason],
    ) -> None:
        if not tools:
            return
        if not _capability(reconciliation_ledger, "production_durable"):
            reasons.append(ProductionReadinessReason.RECONCILIATION_DURABLE_REQUIRED)
        elif not isinstance(
            reconciliation_ledger, SQLiteReconciliationLedger
        ) or not isinstance(idempotency_store, SQLiteIdempotencyStore):
            reasons.append(
                ProductionReadinessReason.RECONCILIATION_ATOMIC_LEDGER_REQUIRED
            )
        elif not _same_sqlite_database(idempotency_store, reconciliation_ledger):
            reasons.append(
                ProductionReadinessReason.RECONCILIATION_COLOCATED_REQUIRED
            )
        if any(spec.reconciliation_provider is None for spec in tools):
            reasons.append(ProductionReadinessReason.RECONCILIATION_PROVIDER_REQUIRED)

    @staticmethod
    def _audit_reasons(
        pipeline: Pipeline, reasons: list[ProductionReadinessReason]
    ) -> None:
        middleware = next(
            (item for item in pipeline if isinstance(item, AuditMiddleware)), None
        )
        if middleware is None:
            reasons.append(ProductionReadinessReason.AUDIT_MIDDLEWARE_REQUIRED)
            return
        if not _capability(middleware.sink, "production_durable"):
            reasons.append(ProductionReadinessReason.AUDIT_SINK_DURABLE_REQUIRED)
        elif not _capability(
            middleware.sink, "production_integrity_protected"
        ):
            reasons.append(ProductionReadinessReason.AUDIT_INTEGRITY_REQUIRED)
        if not middleware.fail_closed:
            reasons.append(ProductionReadinessReason.AUDIT_FAIL_CLOSED_REQUIRED)


class ProductionReadinessError(RuntimeError):
    def __init__(self, report: ProductionReadinessReport) -> None:
        self.report = report
        reasons = sorted(
            {reason.value for tool in report.tools for reason in tool.reasons}
            | {reason.value for reason in report.runtime_reasons}
        )
        detail = ", ".join(reasons) if reasons else "runtime is not sealed"
        super().__init__(f"strict production readiness failed: {detail}")


def _schemas_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return _thaw(left) == _thaw(right)


def _capability(value: Any, name: str) -> bool:
    return getattr(value, name, False) is True


def _same_sqlite_database(
    idempotency_store: SQLiteIdempotencyStore,
    reconciliation_ledger: SQLiteReconciliationLedger,
) -> bool:
    return Path(idempotency_store.path).resolve() == Path(reconciliation_ledger.path).resolve()
