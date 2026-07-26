from __future__ import annotations

import pytest

from agent_runtime_governance import (
    ActionContract,
    ExecutionMode,
    ProductionProfile,
    ProductionReadinessReason,
    ProductionReadinessState,
    Runtime,
)


class KeyProvider:
    def get_key(self, *, tenant: str, version: str) -> bytes:
        return b"k" * 32


def contract(
    *,
    tool_name: str = "operate",
    execution_mode: ExecutionMode = ExecutionMode.MUTATING,
    schema: dict | None = None,
    max_parameters_bytes: int = 4096,
) -> ActionContract:
    return ActionContract(
        contract_id="ops.operate",
        contract_version=1,
        tool_name=tool_name,
        execution_mode=execution_mode,
        parameters_schema=schema
        or {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        effect_class="service.change",
        max_parameters_bytes=max_parameters_bytes,
    )


def strict_profile() -> ProductionProfile:
    return ProductionProfile(
        identity_digest_key_provider=KeyProvider(),
        identity_digest_key_version="2026-07",
    )


def test_inventory_is_sorted_and_contains_no_secret_material() -> None:
    runtime = Runtime()

    @runtime.tool(
        name="z_write",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={"type": "object"},
        max_parameters_bytes=4096,
        action_contract=contract(tool_name="z_write", schema={"type": "object"}),
    )
    def write() -> bool:
        return True

    @runtime.tool(name="a_read", execution_mode=ExecutionMode.READ_ONLY)
    def read() -> bool:
        return True

    report = strict_profile().inventory(runtime.registry.list())

    assert report.ready is True
    assert [tool.tool_name for tool in report.tools] == ["a_read", "z_write"]
    serialized = report.to_dict()
    assert serialized["ready"] is True
    assert "kkkk" not in repr(serialized)


def test_side_effecting_tool_without_contract_is_migration_only() -> None:
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.IDEMPOTENT)
    def operate() -> bool:
        return True

    entry = strict_profile().inventory(runtime.registry.list()).tools[0]

    assert entry.state is ProductionReadinessState.MIGRATION_ONLY
    assert entry.reasons == (ProductionReadinessReason.CONTRACT_REQUIRED,)


def test_read_only_tool_has_an_explicit_contract_exception() -> None:
    runtime = Runtime()

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def inspect() -> bool:
        return True

    entry = strict_profile().inventory(runtime.registry.list()).tools[0]

    assert entry.state is ProductionReadinessState.READY
    assert entry.reasons == ()


@pytest.mark.parametrize(
    ("tool_name", "execution_mode", "schema", "limit", "reason"),
    [
        (
            "other",
            ExecutionMode.MUTATING,
            {"type": "object"},
            4096,
            ProductionReadinessReason.CONTRACT_TOOL_MISMATCH,
        ),
        (
            "operate",
            ExecutionMode.READ_ONLY,
            {"type": "object"},
            4096,
            ProductionReadinessReason.CONTRACT_EXECUTION_MODE_MISMATCH,
        ),
        (
            "operate",
            ExecutionMode.MUTATING,
            {"type": "object", "additionalProperties": False},
            4096,
            ProductionReadinessReason.CONTRACT_PARAMETERS_SCHEMA_MISMATCH,
        ),
        (
            "operate",
            ExecutionMode.MUTATING,
            {"type": "object"},
            8192,
            ProductionReadinessReason.CONTRACT_PARAMETER_LIMIT_MISMATCH,
        ),
    ],
)
def test_inventory_reports_contract_conflicts(
    tool_name: str,
    execution_mode: ExecutionMode,
    schema: dict,
    limit: int,
    reason: ProductionReadinessReason,
) -> None:
    runtime = Runtime()

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={"type": "object"},
        max_parameters_bytes=4096,
        action_contract=contract(
            tool_name=tool_name,
            execution_mode=execution_mode,
            schema=schema,
            max_parameters_bytes=limit,
        ),
    )
    def operate() -> bool:
        return True

    entry = strict_profile().inventory(runtime.registry.list()).tools[0]

    assert entry.state is ProductionReadinessState.INVALID
    assert reason in entry.reasons


def test_contracted_tool_requires_key_provider_and_public_version() -> None:
    runtime = Runtime()

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    entry = ProductionProfile().inventory(runtime.registry.list()).tools[0]

    assert entry.state is ProductionReadinessState.INVALID
    assert entry.reasons == (
        ProductionReadinessReason.IDENTITY_DIGEST_KEY_PROVIDER_REQUIRED,
        ProductionReadinessReason.IDENTITY_DIGEST_KEY_VERSION_REQUIRED,
    )


def test_profile_rejects_invalid_key_configuration() -> None:
    with pytest.raises(TypeError, match="get_key"):
        ProductionProfile(identity_digest_key_provider=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="key_version"):
        ProductionProfile(identity_digest_key_version="bad version")
    with pytest.raises(ValueError, match="unsupported"):
        ProductionProfile(version=2)
