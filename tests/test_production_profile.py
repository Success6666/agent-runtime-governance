from __future__ import annotations

import pytest

from agent_runtime_governance import (
    ActionContract,
    AuditMiddleware,
    ExecutionMode,
    InMemoryAuditSink,
    InMemoryIdempotencyStore,
    InvocationOptions,
    JSONLAuditSink,
    ProductionProfile,
    ProductionReadinessError,
    ProductionReadinessReason,
    ProductionReadinessState,
    RegistryError,
    Runtime,
    RuntimeBuilder,
    SQLiteIdempotencyStore,
    StaticIdentityProvider,
    VerifiedPrincipal,
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


def test_strict_runtime_rejects_traffic_until_sealed(tmp_path) -> None:
    calls: list[str] = []
    runtime = Runtime(
        [AuditMiddleware(JSONLAuditSink(tmp_path / "audit.jsonl"), fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        calls.append(target)
        return True

    with pytest.raises(ProductionReadinessError, match="not sealed") as caught:
        runtime.invoke("operate", "node-a")

    assert caught.value.report.ready is True
    assert calls == []
    report = runtime.seal_production()
    assert report.ready is True
    assert runtime.production_sealed is True
    assert runtime.production_report == report
    assert operate("node-a", _governance=InvocationOptions()) is True
    assert calls == ["node-a"]


def test_failed_seal_reports_all_runtime_requirements() -> None:
    runtime = Runtime(
        idempotency_store=InMemoryIdempotencyStore(),
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    with pytest.raises(ProductionReadinessError) as caught:
        runtime.seal_production()

    assert caught.value.report.runtime_reasons == (
        ProductionReadinessReason.IDENTITY_PROVIDER_REQUIRED,
        ProductionReadinessReason.VERIFIED_IDENTITY_REQUIRED,
        ProductionReadinessReason.IDEMPOTENCY_DURABLE_REQUIRED,
        ProductionReadinessReason.AUDIT_MIDDLEWARE_REQUIRED,
    )
    assert runtime.production_sealed is False
    assert runtime.registry.is_sealed is False


def test_sealed_registry_rejects_late_registration(tmp_path) -> None:
    runtime = _ready_runtime(tmp_path)

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    runtime.seal_production()

    with pytest.raises(RegistryError, match="registry is sealed"):

        @runtime.tool(name="late", execution_mode=ExecutionMode.READ_ONLY)
        def late() -> bool:
            return True


def test_non_strict_runtime_remains_compatible() -> None:
    runtime = Runtime()

    @runtime.tool()
    def operate() -> str:
        return "ok"

    assert operate() == "ok"
    report = runtime.production_readiness(strict_profile())
    assert report.ready is False
    assert report.tools[0].state is ProductionReadinessState.MIGRATION_ONLY


def test_builder_propagates_strict_profile(tmp_path) -> None:
    profile = strict_profile()
    runtime = (
        RuntimeBuilder(
            idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
            identity_provider=StaticIdentityProvider(_principal()),
            require_verified_identity=True,
        )
        .with_production_profile(profile)
        .add_middleware(
            AuditMiddleware(JSONLAuditSink(tmp_path / "audit.jsonl"), fail_closed=True)
        )
        .build()
    )

    assert runtime.production_profile is profile
    assert runtime.production_sealed is False


def test_in_memory_audit_is_rejected_even_when_fail_closed() -> None:
    runtime = Runtime(
        [AuditMiddleware(InMemoryAuditSink(), fail_closed=True)],
        idempotency_store=object(),  # type: ignore[arg-type]
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    report = runtime.production_readiness()
    assert report.runtime_reasons == (
        ProductionReadinessReason.AUDIT_SINK_DURABLE_REQUIRED,
    )


def _principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="trusted-gateway",
        subject="service-account",
        tenant="tenant-a",
        source="static",
    )


def _ready_runtime(tmp_path) -> Runtime:
    return Runtime(
        [AuditMiddleware(JSONLAuditSink(tmp_path / "audit.jsonl"), fail_closed=True)],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )
