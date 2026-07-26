from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Protocol

from ._serialization import thaw as _thaw
from .action_contracts import ActionContract
from .context import ExecutionMode
from .registry import ToolSpec

_KEY_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class IdentityDigestKeyProvider(Protocol):
    """Resolve tenant-scoped action identity keys without exposing them in reports."""

    def get_key(self, *, tenant: str, version: str) -> bytes: ...


class ProductionReadinessState(str, Enum):
    READY = "ready"
    MIGRATION_ONLY = "migration_only"
    INVALID = "invalid"


class ProductionReadinessReason(str, Enum):
    CONTRACT_REQUIRED = "contract.required"
    CONTRACT_TOOL_MISMATCH = "contract.tool_mismatch"
    CONTRACT_EXECUTION_MODE_MISMATCH = "contract.execution_mode_mismatch"
    CONTRACT_PARAMETERS_SCHEMA_MISMATCH = "contract.parameters_schema_mismatch"
    CONTRACT_PARAMETER_LIMIT_MISMATCH = "contract.parameter_limit_mismatch"
    IDENTITY_DIGEST_KEY_PROVIDER_REQUIRED = "identity_digest.key_provider_required"
    IDENTITY_DIGEST_KEY_VERSION_REQUIRED = "identity_digest.key_version_required"


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

    def inventory(
        self, tools: Iterable[ToolSpec[Any, Any]]
    ) -> ProductionReadinessReport:
        entries = tuple(
            self._tool_readiness(spec)
            for spec in sorted(tools, key=lambda item: item.name)
        )
        return ProductionReadinessReport(profile_version=self.version, tools=entries)

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
        if self.identity_digest_key_provider is None:
            reasons.append(
                ProductionReadinessReason.IDENTITY_DIGEST_KEY_PROVIDER_REQUIRED
            )
        if self.identity_digest_key_version is None:
            reasons.append(
                ProductionReadinessReason.IDENTITY_DIGEST_KEY_VERSION_REQUIRED
            )
        return tuple(reasons)


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
