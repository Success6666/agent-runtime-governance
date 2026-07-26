from __future__ import annotations

import threading

import pytest

from agent_runtime_governance import (
    ActionContract,
    AuditMiddleware,
    DecisionMiddleware,
    ExecutionContext,
    ExecutionMode,
    HMACClaimsIdentityProvider,
    HookRegistry,
    InMemoryApprovalStore,
    InMemoryAuditSink,
    InMemoryIdempotencyStore,
    InvocationOptions,
    JSONLAuditSink,
    ProductionProfile,
    ProductionReadinessError,
    ProductionReadinessReason,
    ProductionReadinessState,
    RegistryError,
    RiskTier,
    Runtime,
    RuntimeBuilder,
    SQLiteApprovalStore,
    SQLiteIdempotencyStore,
    SQLiteIdentityReplayStore,
    StaticIdentityProvider,
    ToolCall,
    ToolSpec,
    VerifiedPrincipal,
)
from agent_runtime_governance.registry import ToolRegistry


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
        policy_version="policy-v1",
        policy_digest="a" * 64,
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


def test_read_only_contract_exception_does_not_bypass_identity_or_audit() -> None:
    runtime = Runtime(production_profile=strict_profile())

    @runtime.tool(execution_mode=ExecutionMode.READ_ONLY)
    def inspect() -> bool:
        return True

    report = runtime.production_readiness()

    assert report.tools[0].state is ProductionReadinessState.READY
    assert report.runtime_reasons == (
        ProductionReadinessReason.IDENTITY_PROVIDER_REQUIRED,
        ProductionReadinessReason.VERIFIED_IDENTITY_REQUIRED,
        ProductionReadinessReason.AUDIT_MIDDLEWARE_REQUIRED,
    )


def test_empty_registry_can_be_sealed_without_unused_components() -> None:
    runtime = Runtime(production_profile=strict_profile())

    report = runtime.seal_production()

    assert report.ready is True
    assert report.tools == ()
    assert runtime.registry.is_sealed is True


def test_inventory_includes_direct_registry_entries() -> None:
    runtime = Runtime()
    runtime.registry.register(
        ToolSpec(
            name="direct_read",
            function=lambda: True,
            risk=RiskTier.LOW,
            requires_approval=False,
            description="",
            execution_mode=ExecutionMode.READ_ONLY,
        )
    )

    report = strict_profile().inventory(runtime.registry.list())

    assert report.ready is True
    assert report.tools[0].tool_name == "direct_read"


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
        ProductionReadinessReason.POLICY_IDENTITY_REQUIRED,
    )


def test_profile_rejects_invalid_key_configuration() -> None:
    with pytest.raises(TypeError, match="get_key"):
        ProductionProfile(identity_digest_key_provider=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="key_version"):
        ProductionProfile(identity_digest_key_version="bad version")
    with pytest.raises(ValueError, match="unsupported"):
        ProductionProfile(version=2)
    with pytest.raises(TypeError, match="integer"):
        ProductionProfile(version=True)


def test_strict_runtime_rejects_traffic_until_sealed(tmp_path) -> None:
    calls: list[str] = []
    runtime = Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            )
        ],
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


def test_registry_snapshot_validation_and_seal_are_atomic() -> None:
    runtime = Runtime()
    validation_started = threading.Event()
    release_validation = threading.Event()
    registration_errors: list[BaseException] = []

    def validate(specs):
        assert specs == ()
        validation_started.set()
        assert release_validation.wait(timeout=2)
        return "sealed"

    seal_thread = threading.Thread(target=lambda: runtime.registry._seal_with(validate))
    seal_thread.start()
    assert validation_started.wait(timeout=2)

    def register_late() -> None:
        try:
            runtime.registry.register(
                ToolSpec(
                    name="late",
                    function=lambda: True,
                    risk=RiskTier.LOW,
                    requires_approval=False,
                    description="",
                    execution_mode=ExecutionMode.READ_ONLY,
                )
            )
        except BaseException as exc:
            registration_errors.append(exc)

    register_thread = threading.Thread(target=register_late)
    register_thread.start()
    release_validation.set()
    seal_thread.join(timeout=2)
    register_thread.join(timeout=2)

    assert not seal_thread.is_alive()
    assert not register_thread.is_alive()
    assert len(registration_errors) == 1
    assert isinstance(registration_errors[0], RegistryError)
    assert runtime.registry.list() == ()


def test_concurrent_production_sealing_is_idempotent(monkeypatch) -> None:
    runtime = Runtime(production_profile=strict_profile())
    registry_sealed = threading.Event()
    release_first_caller = threading.Event()
    second_caller_started = threading.Event()
    reports = []
    errors: list[BaseException] = []
    original_seal_with = ToolRegistry._seal_with
    seal_calls = 0

    def delayed_return(self, validator):
        nonlocal seal_calls
        seal_calls += 1
        report = original_seal_with(self, validator)
        registry_sealed.set()
        assert release_first_caller.wait(timeout=2)
        return report

    monkeypatch.setattr(ToolRegistry, "_seal_with", delayed_return)

    def seal(*, started: threading.Event | None = None) -> None:
        if started is not None:
            started.set()
        try:
            reports.append(runtime.seal_production())
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=seal)
    first.start()
    assert registry_sealed.wait(timeout=2)

    second = threading.Thread(target=seal, kwargs={"started": second_caller_started})
    second.start()
    assert second_caller_started.wait(timeout=2)
    release_first_caller.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert len(reports) == 2
    assert reports[0] is reports[1]
    assert seal_calls == 1


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
    class DurableStore:
        production_durable = True

    runtime = Runtime(
        [AuditMiddleware(InMemoryAuditSink(), fail_closed=True)],
        idempotency_store=DurableStore(),  # type: ignore[arg-type]
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


def test_unsigned_audit_sink_is_rejected(tmp_path) -> None:
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
        return bool(target)

    assert runtime.production_readiness().runtime_reasons == (
        ProductionReadinessReason.AUDIT_INTEGRITY_REQUIRED,
    )


@pytest.mark.parametrize(
    ("middleware", "reason"),
    [
        (None, ProductionReadinessReason.APPROVAL_MIDDLEWARE_REQUIRED),
        (
            DecisionMiddleware(store=InMemoryApprovalStore()),
            ProductionReadinessReason.APPROVAL_STORE_DURABLE_REQUIRED,
        ),
    ],
)
def test_approval_requires_durable_middleware(tmp_path, middleware, reason) -> None:
    middlewares = [
        AuditMiddleware(
            JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
            fail_closed=True,
        )
    ]
    if middleware is not None:
        middlewares.insert(0, middleware)
    runtime = Runtime(
        middlewares,
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        requires_approval=True,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    assert reason in runtime.production_readiness().runtime_reasons


def test_unsigned_durable_approval_store_is_rejected(tmp_path) -> None:
    runtime = Runtime(
        [
            DecisionMiddleware(store=SQLiteApprovalStore(tmp_path / "approvals.db")),
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            ),
        ],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        requires_approval=True,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    assert runtime.production_readiness().runtime_reasons == (
        ProductionReadinessReason.APPROVAL_INTEGRITY_REQUIRED,
    )


def test_signed_durable_approval_store_is_ready(tmp_path) -> None:
    runtime = Runtime(
        [
            DecisionMiddleware(
                store=SQLiteApprovalStore(
                    tmp_path / "approvals.db", sign_key=b"p" * 32
                )
            ),
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            ),
        ],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        requires_approval=True,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    assert runtime.seal_production().ready is True


def test_non_fail_closed_audit_is_rejected(tmp_path) -> None:
    runtime = Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=False,
            )
        ],
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
        return bool(target)

    assert runtime.production_readiness().runtime_reasons == (
        ProductionReadinessReason.AUDIT_FAIL_CLOSED_REQUIRED,
    )


def test_hmac_identity_requires_durable_replay_store(tmp_path) -> None:
    provider = HMACClaimsIdentityProvider(
        b"i" * 32,
        expected_issuer="gateway",
        expected_audience="runtime",
    )
    runtime = Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            )
        ],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=provider,
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    assert runtime.production_readiness().runtime_reasons == (
        ProductionReadinessReason.IDENTITY_REPLAY_DURABLE_REQUIRED,
    )

    provider.replay_store = SQLiteIdentityReplayStore(tmp_path / "replay.db")
    assert runtime.production_readiness().runtime_reasons == ()


def test_unmarked_identity_provider_is_not_trusted(tmp_path) -> None:
    class UnmarkedProvider:
        def verify(self, claims=None):
            return _principal()

    runtime = Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            )
        ],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=UnmarkedProvider(),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    assert runtime.production_readiness().runtime_reasons == (
        ProductionReadinessReason.IDENTITY_PROVIDER_NOT_TRUSTED,
    )


def test_sealed_runtime_rejects_component_reassignment(tmp_path) -> None:
    runtime = _ready_runtime(tmp_path)

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    runtime.seal_production()
    original_pipeline = runtime.pipeline
    original_hooks = runtime.hooks
    original_registry = runtime.registry
    original_store = runtime.idempotency_store
    original_provider = runtime.identity_provider
    original_profile = runtime.production_profile

    with pytest.raises(RuntimeError, match="sealed for production"):
        runtime.pipeline = []
    with pytest.raises(RuntimeError, match="sealed for production"):
        runtime.hooks = HookRegistry()
    with pytest.raises(RuntimeError, match="sealed for production"):
        runtime.registry = ToolRegistry()
    with pytest.raises(RuntimeError, match="sealed for production"):
        runtime.idempotency_store = InMemoryIdempotencyStore()
    with pytest.raises(RuntimeError, match="sealed for production"):
        runtime.identity_provider = None
    with pytest.raises(RuntimeError, match="sealed for production"):
        runtime.require_verified_identity = False
    with pytest.raises(RuntimeError, match="sealed for production"):
        runtime.production_profile = None

    assert runtime.pipeline is original_pipeline
    assert runtime.hooks is original_hooks
    assert runtime.registry is original_registry
    assert runtime.idempotency_store is original_store
    assert runtime.identity_provider is original_provider
    assert runtime.require_verified_identity is True
    assert runtime.production_profile is original_profile
    assert runtime.production_sealed is True


def test_unsealed_strict_runtime_allows_component_configuration(tmp_path) -> None:
    runtime = _ready_runtime(tmp_path)

    runtime.identity_provider = StaticIdentityProvider(_principal())
    runtime.require_verified_identity = True
    runtime.idempotency_store = SQLiteIdempotencyStore(
        tmp_path / "idempotency-2.db"
    )

    report = runtime.seal_production()
    assert report.ready is True


def test_assigning_production_profile_re_arms_fail_closed_gate() -> None:
    runtime = Runtime()

    @runtime.tool()
    def operate() -> bool:
        return True

    runtime.production_profile = strict_profile()

    assert runtime.production_sealed is False
    with pytest.raises(ProductionReadinessError):
        runtime.invoke("operate")


async def test_strict_runtime_rejects_preview_until_sealed(tmp_path) -> None:
    runtime = _ready_runtime(tmp_path)

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    with pytest.raises(ProductionReadinessError, match="not sealed"):
        await runtime.apreview("operate", "node-a")

    runtime.seal_production()
    context = await runtime.apreview(
        "operate", "node-a", _governance=InvocationOptions()
    )
    assert context.denied is False


async def test_strict_runtime_rejects_replay_until_sealed(tmp_path) -> None:
    runtime = _ready_runtime(tmp_path)

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    recorded = ExecutionContext.create(ToolCall("operate", ("node-a",)))

    with pytest.raises(ProductionReadinessError, match="not sealed"):
        await runtime.areplay(recorded)

    runtime.seal_production()
    replayed = await runtime.areplay(recorded)
    assert replayed.trace_id == recorded.trace_id


def test_identity_replay_durability_applies_to_third_party_providers(
    tmp_path,
) -> None:
    class ThirdPartyProvider:
        production_trusted = True

        def __init__(self) -> None:
            self.replay_store = object()

        def verify(self, claims=None):
            return _principal()

    provider = ThirdPartyProvider()
    runtime = Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            )
        ],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=provider,
        require_verified_identity=True,
        production_profile=strict_profile(),
    )

    @runtime.tool(
        execution_mode=ExecutionMode.MUTATING,
        action_contract=contract(),
    )
    def operate(target: str) -> bool:
        return bool(target)

    assert runtime.production_readiness().runtime_reasons == (
        ProductionReadinessReason.IDENTITY_REPLAY_DURABLE_REQUIRED,
    )

    provider.replay_store = SQLiteIdentityReplayStore(tmp_path / "replay.db")
    assert runtime.production_readiness().runtime_reasons == ()


def _principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="trusted-gateway",
        subject="service-account",
        tenant="tenant-a",
        source="static",
    )


def _ready_runtime(tmp_path) -> Runtime:
    return Runtime(
        [
            AuditMiddleware(
                JSONLAuditSink(tmp_path / "audit.jsonl", sign_key=b"a" * 32),
                fail_closed=True,
            )
        ],
        idempotency_store=SQLiteIdempotencyStore(tmp_path / "idempotency.db"),
        identity_provider=StaticIdentityProvider(_principal()),
        require_verified_identity=True,
        production_profile=strict_profile(),
    )
