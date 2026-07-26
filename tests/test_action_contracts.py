from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError
from datetime import datetime
from enum import Enum
from pathlib import Path

import pytest

import agent_runtime_governance.action_contracts as action_contracts
from agent_runtime_governance import ActionContract, BoundAction, ExecutionMode
from agent_runtime_governance.contracts import canonical_json_bytes
from agent_runtime_governance.errors import ContractValidationError

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_SAFE_INTEGER = (1 << 53) - 1
_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "action-contracts" / "v1"


def _contract(**overrides: object) -> ActionContract:
    values: dict[str, object] = {
        "contract_id": "ops.file.delete",
        "contract_version": 1,
        "tool_name": "delete_file",
        "execution_mode": ExecutionMode.MUTATING,
        "parameters_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "count": {"type": "integer", "minimum": 1},
            },
            "required": ["target", "count"],
            "additionalProperties": False,
        },
        "effect_class": "filesystem.delete",
        "precondition_requirements": (),
        "receipt_schema": {
            "type": "object",
            "properties": {"receipt_id": {"type": "string"}},
            "required": ["receipt_id"],
        },
        "max_parameters_bytes": 1024,
    }
    values.update(overrides)
    return ActionContract(**values)  # type: ignore[arg-type]


def _bound(contract: ActionContract | None = None, **overrides: object) -> BoundAction:
    values: dict[str, object] = {
        "parameters": {"target": "/srv/data", "count": 1},
        "identity_issuer": "issuer:local",
        "principal": "user:operator",
        "tenant": "tenant:acme",
        "policy_version": "policy-v1",
        "policy_digest": _DIGEST_A,
        "precondition_digest": None,
    }
    values.update(overrides)
    selected = contract or _contract()
    parameters = values.pop("parameters")
    return selected.bind(parameters, **values)  # type: ignore[arg-type]


def test_contract_has_stable_rfc8785_fixture() -> None:
    contract = _contract()
    expected = bytes.fromhex(
        (_FIXTURE_DIR / "contract.hex").read_text(encoding="ascii").strip()
    )
    assert contract.canonical_bytes() == expected
    assert contract.contract_digest == json.loads(
        (_FIXTURE_DIR / "digests.json").read_text(encoding="utf-8")
    )["contract_digest"]


def test_bound_action_has_stable_digest_fixture() -> None:
    bound = _bound()
    expected = json.loads(
        (_FIXTURE_DIR / "digests.json").read_text(encoding="utf-8")
    )
    assert bound.parameters_digest == expected["parameters_digest"]
    assert bound.action_digest == expected["action_digest"]


def test_mapping_insertion_order_does_not_change_digests() -> None:
    schema_one = {
        "type": "object",
        "properties": {"beta": {"type": "integer"}, "alpha": {"type": "string"}},
    }
    schema_two = {
        "properties": {"alpha": {"type": "string"}, "beta": {"type": "integer"}},
        "type": "object",
    }
    first_contract = _contract(parameters_schema=schema_one, receipt_schema=None)
    second_contract = _contract(parameters_schema=schema_two, receipt_schema=None)
    assert first_contract.contract_digest == second_contract.contract_digest

    first = first_contract.bind(
        {"beta": 2, "alpha": "one"},
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    second = second_contract.bind(
        {"alpha": "one", "beta": 2},
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    assert first.parameters_digest == second.parameters_digest
    assert first.action_digest == second.action_digest


def test_contract_and_bound_action_detach_nested_inputs() -> None:
    schema = {
        "type": "object",
        "properties": {"items": {"type": "array", "items": {"type": "string"}}},
    }
    parameters = {"items": ["one"]}
    contract = _contract(parameters_schema=schema, receipt_schema=None)
    bound = contract.bind(
        parameters,
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    contract_digest = contract.contract_digest
    parameters_digest = bound.parameters_digest

    schema["properties"]["items"]["items"]["type"] = "integer"
    parameters["items"].append("two")

    assert contract.contract_digest == contract_digest
    assert contract.to_dict()["contract"]["parameters_schema"]["properties"][
        "items"
    ]["items"] == {"type": "string"}
    assert bound.parameters_digest == parameters_digest
    assert bound.to_dict()["parameters"] == {"items": ["one"]}


def test_public_values_and_nested_members_are_immutable() -> None:
    contract = _contract()
    bound = _bound(contract)

    with pytest.raises(FrozenInstanceError):
        contract.tool_name = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        contract.parameters_schema["type"] = "array"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        bound.tenant_digest = _DIGEST_B  # type: ignore[misc]
    with pytest.raises(TypeError):
        bound.parameters["target"] = "/tmp"  # type: ignore[index]
    assert "parameters_schema" not in repr(contract)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("contract_id", "ops.file.remove"),
        ("contract_version", 2),
        ("tool_name", "remove_file"),
        ("execution_mode", ExecutionMode.IDEMPOTENT),
        ("parameters_schema", {"type": "object"}),
        ("effect_class", "filesystem.remove"),
        ("precondition_requirements", ("etag",)),
        ("receipt_schema", None),
        ("max_parameters_bytes", 2048),
    ],
)
def test_every_contract_field_changes_contract_digest(field: str, value: object) -> None:
    assert _contract(**{field: value}).contract_digest != _contract().contract_digest


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("parameters", {"target": "/srv/other", "count": 1}),
        ("identity_issuer", "issuer:other"),
        ("principal", "user:reviewer"),
        ("tenant", "tenant:other"),
        ("policy_version", "policy-v2"),
        ("policy_digest", _DIGEST_B),
        ("precondition_digest", _DIGEST_B),
    ],
)
def test_every_binding_field_changes_action_digest(field: str, value: object) -> None:
    assert _bound(**{field: value}).action_digest != _bound().action_digest


def test_same_subject_from_different_issuer_changes_action_digest() -> None:
    assert (
        _bound(identity_issuer="issuer:primary").action_digest
        != _bound(identity_issuer="issuer:secondary").action_digest
    )


def test_contract_change_changes_bound_action_digest() -> None:
    assert _bound(_contract(contract_version=2)).action_digest != _bound().action_digest


def test_parameters_must_match_declared_schema() -> None:
    with pytest.raises(ContractValidationError, match=r"count.*minimum"):
        _bound(parameters={"target": "/srv/data", "count": 0})


def test_schema_errors_do_not_echo_rejected_secret_values() -> None:
    secret = "TOP-SECRET-TOKEN"
    with pytest.raises(ContractValidationError) as exc_info:
        _bound(parameters={"target": "/srv/data", "count": secret})
    message = str(exc_info.value)
    assert secret not in message
    assert "failed JSON Schema constraint" in message


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (math.nan, "non-finite"),
        (math.inf, "non-finite"),
        (-math.inf, "non-finite"),
        (-0.0, "negative zero"),
        (_SAFE_INTEGER + 1, "safe range"),
        (-_SAFE_INTEGER - 1, "safe range"),
        (object(), "unsupported value type"),
    ],
)
def test_ambiguous_or_unsupported_parameter_values_are_rejected(
    value: object, message: str
) -> None:
    contract = _contract(
        parameters_schema={"type": "object"},
        receipt_schema=None,
    )
    with pytest.raises(ContractValidationError, match=message):
        contract.bind(
            {"value": value},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


def test_non_string_mapping_key_is_rejected() -> None:
    contract = _contract(parameters_schema={}, receipt_schema=None)
    with pytest.raises(ContractValidationError, match="object keys must be strings"):
        contract.bind(
            {1: "value"},  # type: ignore[dict-item]
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


def test_cyclic_parameter_value_is_rejected_explicitly() -> None:
    recursive: dict[str, object] = {}
    recursive["self"] = recursive
    contract = _contract(parameters_schema={}, receipt_schema=None)
    with pytest.raises(ContractValidationError, match="cyclic values"):
        contract.bind(
            recursive,
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


def test_lone_unicode_surrogate_is_rejected() -> None:
    contract = _contract(parameters_schema={}, receipt_schema=None)
    with pytest.raises(ContractValidationError, match="Unicode scalar"):
        contract.bind(
            {"value": "\ud800"},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


def test_parameter_payload_limit_uses_canonical_parameter_bytes() -> None:
    contract = _contract(
        parameters_schema={},
        receipt_schema=None,
        max_parameters_bytes=12,
    )
    with pytest.raises(ContractValidationError, match="exceeds 12 bytes"):
        contract.bind(
            {"value": "long"},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


def test_required_precondition_cannot_be_omitted() -> None:
    contract = _contract(precondition_requirements=("resource.etag",))
    with pytest.raises(ValueError, match="precondition_digest is required"):
        _bound(contract)
    assert _bound(contract, precondition_digest=_DIGEST_A).precondition_digest == _DIGEST_A


@pytest.mark.parametrize(
    "values",
    [
        {"policy_version": "policy-v1", "policy_digest": None},
        {"policy_version": None, "policy_digest": _DIGEST_A},
        {"policy_version": "policy-v1", "policy_digest": "invalid"},
        {"precondition_digest": "A" * 64},
    ],
)
def test_digest_metadata_is_structurally_validated(values: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _bound(**values)


def test_serialized_values_are_json_compatible_and_detached() -> None:
    bound = _bound()
    serialized = bound.to_dict()
    assert json.loads(json.dumps(serialized)) == serialized

    serialized["parameters"]["target"] = "changed"
    serialized["contract"]["contract"]["parameters_schema"]["type"] = "array"
    assert bound.parameters["target"] == "/srv/data"
    assert bound.contract.parameters_schema["type"] == "object"


def test_serialized_values_round_trip_with_digest_verification() -> None:
    contract = _contract()
    bound = _bound(contract)

    restored_contract = ActionContract.from_dict(contract.to_dict())
    restored_bound = BoundAction.from_dict(bound.to_dict())

    assert restored_contract == contract
    assert restored_bound == bound
    assert restored_bound.canonical_bytes() == bound.canonical_bytes()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("version", 2, "unsupported version"),
        ("version", True, "unsupported version"),
        ("domain", "other.domain", "unsupported domain"),
        ("contract_digest", _DIGEST_B, "contract digest mismatch"),
    ],
)
def test_contract_deserialization_rejects_untrusted_envelope(
    field: str, value: object, message: str
) -> None:
    serialized = _contract().to_dict()
    serialized[field] = value
    with pytest.raises(ContractValidationError, match=message):
        ActionContract.from_dict(serialized)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("parameters_digest", _DIGEST_B, "parameters digest mismatch"),
        ("action_digest", _DIGEST_B, "action digest mismatch"),
        ("principal_digest", _DIGEST_B, "action digest mismatch"),
    ],
)
def test_bound_action_deserialization_detects_tampering(
    field: str, value: object, message: str
) -> None:
    serialized = _bound().to_dict()
    serialized[field] = value
    with pytest.raises(ContractValidationError, match=message):
        BoundAction.from_dict(serialized)


def test_serialized_envelopes_reject_missing_and_extra_fields() -> None:
    missing = _bound().to_dict()
    missing.pop("action_digest")
    with pytest.raises(ContractValidationError, match="missing"):
        BoundAction.from_dict(missing)

    extra = _contract().to_dict()
    extra["future"] = True
    with pytest.raises(ContractValidationError, match="unexpected"):
        ActionContract.from_dict(extra)


def test_identity_values_are_opaque_and_not_retained() -> None:
    principal = "用户+ops@example.com"
    tenant = "https://issuer.example/tenant?id=北"
    bound = _contract().bind(
        {"target": "/srv/data", "count": 1},
        identity_issuer="issuer:local",
        principal=principal,
        tenant=tenant,
    )

    serialized = json.dumps(bound.to_dict(), ensure_ascii=False)
    assert principal not in serialized
    assert tenant not in serialized
    assert principal not in repr(bound)
    assert tenant not in repr(bound)


def test_evidence_representation_excludes_raw_parameters() -> None:
    secret = "TOP-SECRET"
    bound = _bound(parameters={"target": secret, "count": 1})
    evidence = json.dumps(bound.to_evidence_dict())

    assert secret not in evidence
    assert secret not in repr(bound)
    assert "parameters" not in bound.to_evidence_dict()


def test_digest_backed_values_are_hashable() -> None:
    contract = _contract()
    bound = _bound(contract)
    assert {contract} == {ActionContract.from_dict(contract.to_dict())}
    assert {bound} == {BoundAction.from_dict(bound.to_dict())}


class _Code(str, Enum):
    VALUE = "value"


@pytest.mark.parametrize(
    "value",
    [
        _Code.VALUE,
        ("tuple",),
        {"set"},
        b"bytes",
        Path("/tmp/value"),
        datetime(2026, 1, 1),
    ],
)
def test_non_json_native_values_are_not_coerced(value: object) -> None:
    contract = _contract(parameters_schema={}, receipt_schema=None)
    with pytest.raises(ContractValidationError, match="unsupported value type"):
        contract.bind(
            {"value": value},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


class _StringSubclass(str):
    pass


class _IntegerSubclass(int):
    pass


@pytest.mark.parametrize("value", [_StringSubclass("value"), _IntegerSubclass(1)])
def test_json_primitive_subclasses_are_not_coerced(value: object) -> None:
    contract = _contract(parameters_schema={}, receipt_schema=None)
    with pytest.raises(ContractValidationError, match="unsupported value type"):
        contract.bind(
            {"value": value},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


class _DuplicateKeyMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        if key == "value":
            return 2
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        yield "value"

    def __len__(self) -> int:
        return 1

    def items(self):
        return [("value", 1), ("value", 2)]


def test_custom_mapping_cannot_supply_duplicate_keys() -> None:
    contract = _contract(parameters_schema={}, receipt_schema=None)
    with pytest.raises(ContractValidationError, match="duplicate object keys"):
        contract.bind(
            _DuplicateKeyMapping(),
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


def test_unicode_is_not_silently_normalized() -> None:
    composed = _bound(parameters={"target": "\u00e9", "count": 1})
    decomposed = _bound(parameters={"target": "e\u0301", "count": 1})
    assert composed.parameters_digest != decomposed.parameters_digest


def test_parameter_limit_accepts_exact_canonical_size() -> None:
    contract = _contract(
        parameters_schema={},
        receipt_schema=None,
        max_parameters_bytes=13,
    )
    assert contract.bind(
        {"value": "x"},
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )


def test_excessive_nesting_is_rejected() -> None:
    nested: object = "leaf"
    for _ in range(102):
        nested = [nested]
    contract = _contract(parameters_schema={}, receipt_schema=None)
    with pytest.raises(ContractValidationError, match="maximum nesting depth"):
        contract.bind(
            {"value": nested},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


@pytest.mark.parametrize(
    ("overrides", "error", "message"),
    [
        ({"contract_id": "bad value"}, ValueError, "contract_id"),
        ({"contract_version": 0}, ValueError, "positive integer"),
        ({"contract_version": True}, ValueError, "positive integer"),
        ({"tool_name": "9invalid"}, ValueError, "tool_name"),
        ({"execution_mode": "mutating"}, TypeError, "ExecutionMode"),
        ({"effect_class": "bad value"}, ValueError, "effect_class"),
        ({"max_parameters_bytes": 0}, ValueError, "positive integer"),
        ({"max_parameters_bytes": True}, ValueError, "positive integer"),
        ({"precondition_requirements": ["etag"]}, TypeError, "must be a tuple"),
        (
            {"precondition_requirements": ("etag", "etag")},
            ValueError,
            "duplicates",
        ),
        (
            {"precondition_requirements": ("bad value",)},
            ValueError,
            "stable",
        ),
    ],
)
def test_invalid_contract_configuration_fails_early(
    overrides: dict[str, object], error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        _contract(**overrides)


def test_contract_schemas_must_be_valid_json_schema_objects() -> None:
    with pytest.raises(ContractValidationError, match="must be an object"):
        _contract(parameters_schema=[])
    with pytest.raises(ContractValidationError, match="invalid parameters_schema"):
        _contract(parameters_schema={"type": "not-a-json-type"})


def test_contract_payload_limit_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(action_contracts, "_MAX_CONTRACT_BYTES", 32)
    with pytest.raises(ContractValidationError, match="exceeds 32 bytes"):
        _contract()


def test_bound_action_requires_a_contract_and_parameter_object() -> None:
    with pytest.raises(TypeError, match="contract must be"):
        BoundAction(  # type: ignore[arg-type]
            "not-a-contract",
            {},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )
    with pytest.raises(ContractValidationError, match="must be an object"):
        _contract().bind(  # type: ignore[arg-type]
            [],
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("principal", "", "non-empty"),
        ("tenant", "\ud800", "Unicode scalar"),
        ("principal", "x" * 1025, "1024 UTF-8 bytes"),
    ],
)
def test_identity_input_boundaries(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _bound(**{field: value})


def test_serialized_contract_validates_field_types_and_digest_shape() -> None:
    wrong_requirements = _contract().to_dict()
    wrong_requirements["contract"]["precondition_requirements"] = "etag"
    with pytest.raises(ContractValidationError, match="must be an array"):
        ActionContract.from_dict(wrong_requirements)

    invalid_schema = _contract().to_dict()
    invalid_schema["contract"]["parameters_schema"] = {
        "type": "not-a-json-type"
    }
    with pytest.raises(ContractValidationError, match="invalid parameters_schema"):
        ActionContract.from_dict(invalid_schema)

    invalid_digest = _contract().to_dict()
    invalid_digest["contract_digest"] = "invalid"
    with pytest.raises(ContractValidationError, match="SHA-256"):
        ActionContract.from_dict(invalid_digest)


def test_serialized_bound_action_validates_all_binding_metadata() -> None:
    invalid_digest = _bound().to_dict()
    invalid_digest["principal_digest"] = "invalid"
    with pytest.raises(ContractValidationError, match="SHA-256"):
        BoundAction.from_dict(invalid_digest)

    invalid_policy = _bound().to_dict()
    invalid_policy["policy_digest"] = None
    with pytest.raises(ContractValidationError, match="provided together"):
        BoundAction.from_dict(invalid_policy)

    required = _bound(
        _contract(precondition_requirements=("resource.etag",)),
        precondition_digest=_DIGEST_A,
    ).to_dict()
    required["precondition_digest"] = None
    with pytest.raises(ContractValidationError, match="required by action contract"):
        BoundAction.from_dict(required)

    wrong_contract_digest = _bound().to_dict()
    wrong_contract_digest["contract_digest"] = _DIGEST_B
    with pytest.raises(ContractValidationError, match="contract digest mismatch"):
        BoundAction.from_dict(wrong_contract_digest)


def test_serialized_object_boundaries_are_strict() -> None:
    with pytest.raises(ContractValidationError, match="must be an object"):
        ActionContract.from_dict([])  # type: ignore[arg-type]
    with pytest.raises(ContractValidationError, match="keys must be strings"):
        ActionContract.from_dict({1: "value"})  # type: ignore[dict-item]


def test_canonical_node_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(action_contracts, "_MAX_CANONICAL_NODES", 2)
    with pytest.raises(ContractValidationError, match="value count"):
        _contract(parameters_schema={}, receipt_schema=None).bind(
            {"first": 1, "second": 2},
            identity_issuer="issuer:local",
            principal="user:operator",
            tenant="tenant:acme",
        )


def test_canonicalizer_errors_are_translated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_: object) -> bytes:
        raise action_contracts.rfc8785.CanonicalizationError("invalid canonical value")

    monkeypatch.setattr(action_contracts.rfc8785, "dumps", fail)
    with pytest.raises(ContractValidationError, match="invalid canonical value"):
        _contract()


def test_jcs_number_equivalence_is_explicit() -> None:
    contract = _contract(parameters_schema={}, receipt_schema=None)
    integer = contract.bind(
        {"value": 1},
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    floating = contract.bind(
        {"value": 1.0},
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    assert integer.parameters_digest == floating.parameters_digest


def test_safe_integer_boundaries_are_accepted() -> None:
    contract = _contract(parameters_schema={}, receipt_schema=None)
    bound = contract.bind(
        {"minimum": -_SAFE_INTEGER, "maximum": _SAFE_INTEGER},
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    assert bound.parameters["minimum"] == -_SAFE_INTEGER
    assert bound.parameters["maximum"] == _SAFE_INTEGER


def test_v05_legacy_canonicalization_fixture_is_unchanged() -> None:
    encoded = canonical_json_bytes(
        {
            "tool": "delete_file",
            "parameters": {"count": 1, "target": "/srv/data"},
        },
        label="legacy action",
    )
    assert encoded == (
        b'{"parameters":{"count":1,"target":"/srv/data"},'
        b'"tool":"delete_file"}'
    )
    assert hashlib.sha256(encoded).hexdigest() == (
        "7c73281f77d007309fee3b03485215a2f8ea9fb3305581e498f15a08a13bb55e"
    )


def test_digests_are_identical_in_a_fresh_python_process(tmp_path) -> None:
    local = _bound()
    script = tmp_path / "fixture.py"
    script.write_text(
        """
import json
from agent_runtime_governance import ActionContract, ExecutionMode

contract = ActionContract(
    contract_id="ops.file.delete",
    contract_version=1,
    tool_name="delete_file",
    execution_mode=ExecutionMode.MUTATING,
    parameters_schema={
        "required": ["target", "count"],
        "properties": {
            "count": {"minimum": 1, "type": "integer"},
            "target": {"type": "string"},
        },
        "additionalProperties": False,
        "type": "object",
    },
    effect_class="filesystem.delete",
    receipt_schema={
        "required": ["receipt_id"],
        "properties": {"receipt_id": {"type": "string"}},
        "type": "object",
    },
    max_parameters_bytes=1024,
)
bound = contract.bind(
    {"count": 1, "target": "/srv/data"},
    identity_issuer="issuer:local",
    principal="user:operator",
    tenant="tenant:acme",
    policy_version="policy-v1",
    policy_digest="a" * 64,
)
print(json.dumps({
    "contract": contract.contract_digest,
    "parameters": bound.parameters_digest,
    "action": bound.action_digest,
    "bytes": contract.canonical_bytes().decode("utf-8"),
}, sort_keys=True))
""".strip(),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    remote = json.loads(completed.stdout)

    assert remote == {
        "action": local.action_digest,
        "bytes": local.contract.canonical_bytes().decode("utf-8"),
        "contract": local.contract_digest,
        "parameters": local.parameters_digest,
    }
