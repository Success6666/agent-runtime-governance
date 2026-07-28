from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator

from ._canonical import CanonicalJsonError, rfc8785_json_bytes
from ._serialization import freeze_mapping as _freeze_mapping
from ._serialization import thaw as _thaw
from .context import ExecutionMode
from .contracts import validate_schema
from .errors import ContractValidationError, RegistryError

_ACTION_CONTRACT_DOMAIN = "arg.action-contract"
_ACTION_PARAMETERS_DOMAIN = "arg.action-parameters"
_BOUND_ACTION_DOMAIN = "arg.bound-action"
_PRINCIPAL_DOMAIN = "arg.principal"
_TENANT_DOMAIN = "arg.tenant"
_IDENTITY_HMAC_ALGORITHM = "hmac-sha256"
_ENVELOPE_VERSION = 1
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_NESTING_DEPTH = 100
_MAX_CANONICAL_NODES = 100_000
_MAX_CONTRACT_BYTES = 1_048_576
_DEFAULT_MAX_PARAMETERS_BYTES = 1_048_576
_STABLE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_TOOL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_KEY_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MIN_IDENTITY_DIGEST_KEY_BYTES = 32
_MAX_IDENTITY_DIGEST_KEY_BYTES = 4096


@dataclass(frozen=True, slots=True, repr=False)
class ActionContract:
    """Versioned contract for one governed tool action."""

    contract_id: str
    contract_version: int
    tool_name: str
    execution_mode: ExecutionMode
    parameters_schema: Mapping[str, Any] = field(repr=False)
    effect_class: str
    precondition_requirements: tuple[str, ...] = ()
    receipt_schema: Mapping[str, Any] | None = field(default=None, repr=False)
    max_parameters_bytes: int = _DEFAULT_MAX_PARAMETERS_BYTES
    contract_digest: str = field(init=False)
    _parameters_validator: Draft202012Validator = field(
        init=False, repr=False, compare=False, hash=False
    )

    def __post_init__(self) -> None:
        _require_identifier("contract_id", self.contract_id)
        if (
            isinstance(self.contract_version, bool)
            or not isinstance(self.contract_version, int)
            or self.contract_version < 1
        ):
            raise ValueError("contract_version must be a positive integer")
        if type(self.tool_name) is not str or not _TOOL_IDENTIFIER.fullmatch(
            self.tool_name
        ):
            raise ValueError("tool_name must be a stable 1-128 character identifier")
        if not isinstance(self.execution_mode, ExecutionMode):
            raise TypeError("execution_mode must be an ExecutionMode")
        _require_identifier("effect_class", self.effect_class)
        requirements = _normalize_requirements(self.precondition_requirements)
        if (
            isinstance(self.max_parameters_bytes, bool)
            or not isinstance(self.max_parameters_bytes, int)
            or self.max_parameters_bytes < 1
        ):
            raise ValueError("max_parameters_bytes must be a positive integer")

        parameters_schema = _normalize_schema(
            self.parameters_schema, label="parameters_schema"
        )
        receipt_schema = (
            None
            if self.receipt_schema is None
            else _normalize_schema(self.receipt_schema, label="receipt_schema")
        )
        object.__setattr__(
            self, "parameters_schema", _freeze_mapping(parameters_schema)
        )
        object.__setattr__(
            self,
            "_parameters_validator",
            Draft202012Validator(_thaw(parameters_schema)),
        )
        object.__setattr__(self, "precondition_requirements", requirements)
        if receipt_schema is not None:
            object.__setattr__(self, "receipt_schema", _freeze_mapping(receipt_schema))

        encoded = _canonical_bytes(self._digest_payload(), label="action contract")
        if len(encoded) > _MAX_CONTRACT_BYTES:
            raise ContractValidationError(
                "action contract",
                f"canonical payload exceeds {_MAX_CONTRACT_BYTES} bytes",
            )
        object.__setattr__(self, "contract_digest", _sha256(encoded))

    def __repr__(self) -> str:
        return (
            f"ActionContract(contract_id={self.contract_id!r}, "
            f"contract_version={self.contract_version!r}, "
            f"tool_name={self.tool_name!r}, "
            f"contract_digest={self.contract_digest!r})"
        )

    def __hash__(self) -> int:
        return hash(self.contract_digest)

    def bind(
        self,
        parameters: Mapping[str, Any],
        *,
        identity_issuer: str,
        principal: str,
        tenant: str,
        identity_digest_key: bytes,
        identity_digest_key_version: str,
        policy_version: str | None = None,
        policy_digest: str | None = None,
        precondition_digest: str | None = None,
    ) -> BoundAction:
        """Bind parameters and identity using an ephemeral keyed digest secret.

        ``identity_digest_key`` must be deployment- or tenant-scoped secret
        material. The key is consumed only while binding and is never retained
        by the resulting value. ``identity_digest_key_version`` is public
        rotation metadata and becomes part of the action identity.
        """
        return BoundAction(
            self,
            parameters,
            identity_issuer=identity_issuer,
            principal=principal,
            tenant=tenant,
            identity_digest_key=identity_digest_key,
            identity_digest_key_version=identity_digest_key_version,
            policy_version=policy_version,
            policy_digest=policy_digest,
            precondition_digest=precondition_digest,
        )

    def canonical_bytes(self) -> bytes:
        """Return the exact versioned bytes covered by ``contract_digest``."""
        return _canonical_bytes(self._digest_payload(), label="action contract")

    def to_dict(self) -> dict[str, Any]:
        """Return the complete versioned contract persistence form."""
        return {
            "domain": _ACTION_CONTRACT_DOMAIN,
            "version": _ENVELOPE_VERSION,
            "contract": self._contract_fields(),
            "contract_digest": self.contract_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ActionContract:
        """Restore and verify a versioned serialized contract."""
        data = _require_mapping(value, label="serialized action contract")
        _require_exact_keys(
            data,
            {"domain", "version", "contract", "contract_digest"},
            label="serialized action contract",
        )
        _require_envelope(
            data,
            domain=_ACTION_CONTRACT_DOMAIN,
            label="serialized action contract",
        )
        fields = _require_mapping(
            data["contract"], label="serialized action contract fields"
        )
        _require_exact_keys(
            fields,
            {
                "contract_id",
                "contract_version",
                "tool_name",
                "execution_mode",
                "parameters_schema",
                "effect_class",
                "precondition_requirements",
                "receipt_schema",
                "max_parameters_bytes",
            },
            label="serialized action contract fields",
        )
        try:
            execution_mode = ExecutionMode(fields["execution_mode"])
            requirements_value = fields["precondition_requirements"]
            if not isinstance(requirements_value, list):
                raise TypeError("precondition_requirements must be an array")
            contract = cls(
                contract_id=fields["contract_id"],
                contract_version=fields["contract_version"],
                tool_name=fields["tool_name"],
                execution_mode=execution_mode,
                parameters_schema=fields["parameters_schema"],
                effect_class=fields["effect_class"],
                precondition_requirements=tuple(requirements_value),
                receipt_schema=fields["receipt_schema"],
                max_parameters_bytes=fields["max_parameters_bytes"],
            )
        except ContractValidationError:
            raise
        except (TypeError, ValueError) as exc:
            raise ContractValidationError(
                "serialized action contract", str(exc)
            ) from exc
        digest = data["contract_digest"]
        try:
            _require_digest("contract_digest", digest, optional=False)
        except (TypeError, ValueError) as exc:
            raise ContractValidationError(
                "serialized action contract", str(exc)
            ) from exc
        if digest != contract.contract_digest:
            raise ContractValidationError(
                "serialized action contract", "contract digest mismatch"
            )
        return contract

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "domain": _ACTION_CONTRACT_DOMAIN,
            "version": _ENVELOPE_VERSION,
            "contract": self._contract_fields(),
        }

    def _contract_fields(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "tool_name": self.tool_name,
            "execution_mode": self.execution_mode.value,
            "parameters_schema": _thaw(self.parameters_schema),
            "effect_class": self.effect_class,
            "precondition_requirements": list(self.precondition_requirements),
            "receipt_schema": (
                None if self.receipt_schema is None else _thaw(self.receipt_schema)
            ),
            "max_parameters_bytes": self.max_parameters_bytes,
        }


@dataclass(frozen=True, slots=True, init=False, repr=False)
class BoundAction:
    """Immutable, privacy-minimized identity for one governed action."""

    contract: ActionContract
    parameters: Mapping[str, Any] = field(repr=False)
    principal_digest: str
    tenant_digest: str
    identity_digest_key_version: str
    policy_version: str | None
    policy_digest: str | None
    precondition_digest: str | None
    contract_digest: str
    parameters_digest: str
    action_digest: str

    def __init__(
        self,
        contract: ActionContract,
        parameters: Mapping[str, Any],
        *,
        identity_issuer: str,
        principal: str,
        tenant: str,
        identity_digest_key: bytes,
        identity_digest_key_version: str,
        policy_version: str | None = None,
        policy_digest: str | None = None,
        precondition_digest: str | None = None,
    ) -> None:
        if not isinstance(contract, ActionContract):
            raise TypeError("contract must be an ActionContract")
        _require_identity_value("identity_issuer", identity_issuer)
        _require_identity_value("principal", principal)
        _require_identity_value("tenant", tenant)
        key = _require_identity_digest_key(identity_digest_key)
        key_version = _require_identity_digest_key_version(identity_digest_key_version)
        _validate_policy(policy_version, policy_digest)
        _require_digest("precondition_digest", precondition_digest, optional=True)
        if contract.precondition_requirements and precondition_digest is None:
            raise ValueError("precondition_digest is required by this action contract")
        normalized, parameters_digest = _prepare_parameters(contract, parameters)
        _initialize_bound_action(
            self,
            contract=contract,
            normalized=normalized,
            principal_digest=_principal_digest(
                identity_issuer,
                principal,
                key=key,
                key_version=key_version,
            ),
            tenant_digest=_identifier_digest(
                _TENANT_DOMAIN,
                tenant,
                key=key,
                key_version=key_version,
            ),
            identity_digest_key_version=key_version,
            policy_version=policy_version,
            policy_digest=policy_digest,
            precondition_digest=precondition_digest,
            parameters_digest=parameters_digest,
        )

    def __repr__(self) -> str:
        return (
            f"BoundAction(contract_id={self.contract.contract_id!r}, "
            f"contract_version={self.contract.contract_version!r}, "
            f"action_digest={self.action_digest!r})"
        )

    def __hash__(self) -> int:
        return hash(self.action_digest)

    def canonical_bytes(self) -> bytes:
        """Return the exact versioned bytes covered by ``action_digest``."""
        return _canonical_bytes(self._digest_payload(), label="bound action")

    def to_dict(self) -> dict[str, Any]:
        """Return the full persistence form without raw identity or HMAC key.

        This includes the isolated parameter snapshot for controlled replay and
        migration readers. Audit records, logs, and externally shared evidence
        must use :meth:`to_evidence_dict` instead.
        """
        return {
            "domain": _BOUND_ACTION_DOMAIN,
            "version": _ENVELOPE_VERSION,
            "contract": self.contract.to_dict(),
            "parameters": _thaw(self.parameters),
            "principal_digest": self.principal_digest,
            "tenant_digest": self.tenant_digest,
            "identity_digest_key_version": self.identity_digest_key_version,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "precondition_digest": self.precondition_digest,
            "contract_digest": self.contract_digest,
            "parameters_digest": self.parameters_digest,
            "action_digest": self.action_digest,
        }

    def to_evidence_dict(self) -> dict[str, Any]:
        """Return an evidence-safe representation without raw parameters."""
        return {
            "domain": _BOUND_ACTION_DOMAIN,
            "version": _ENVELOPE_VERSION,
            "contract_id": self.contract.contract_id,
            "contract_version": self.contract.contract_version,
            "tool_name": self.contract.tool_name,
            "contract_digest": self.contract_digest,
            "parameters_digest": self.parameters_digest,
            "principal_digest": self.principal_digest,
            "tenant_digest": self.tenant_digest,
            "identity_digest_key_version": self.identity_digest_key_version,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "precondition_digest": self.precondition_digest,
            "action_digest": self.action_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> BoundAction:
        """Restore a serialized action and verify every derived digest."""
        data = _require_mapping(value, label="serialized bound action")
        _require_exact_keys(
            data,
            {
                "domain",
                "version",
                "contract",
                "parameters",
                "principal_digest",
                "tenant_digest",
                "identity_digest_key_version",
                "policy_version",
                "policy_digest",
                "precondition_digest",
                "contract_digest",
                "parameters_digest",
                "action_digest",
            },
            label="serialized bound action",
        )
        _require_envelope(
            data,
            domain=_BOUND_ACTION_DOMAIN,
            label="serialized bound action",
        )
        contract = ActionContract.from_dict(
            _require_mapping(data["contract"], label="serialized bound action contract")
        )
        try:
            for name in (
                "principal_digest",
                "tenant_digest",
                "policy_digest",
                "precondition_digest",
                "contract_digest",
                "parameters_digest",
                "action_digest",
            ):
                _require_digest(
                    name,
                    data[name],
                    optional=name in {"policy_digest", "precondition_digest"},
                )
            _require_identity_digest_key_version(data["identity_digest_key_version"])
            _validate_policy(data["policy_version"], data["policy_digest"])
        except (TypeError, ValueError) as exc:
            raise ContractValidationError("serialized bound action", str(exc)) from exc
        if contract.precondition_requirements and data["precondition_digest"] is None:
            raise ContractValidationError(
                "serialized bound action",
                "precondition digest required by action contract",
            )
        if data["contract_digest"] != contract.contract_digest:
            raise ContractValidationError(
                "serialized bound action", "contract digest mismatch"
            )
        normalized, parameters_digest = _prepare_parameters(
            contract,
            _require_mapping(data["parameters"], label="serialized parameters"),
        )
        if data["parameters_digest"] != parameters_digest:
            raise ContractValidationError(
                "serialized bound action", "parameters digest mismatch"
            )
        instance = object.__new__(cls)
        _initialize_bound_action(
            instance,
            contract=contract,
            normalized=normalized,
            principal_digest=data["principal_digest"],
            tenant_digest=data["tenant_digest"],
            identity_digest_key_version=data["identity_digest_key_version"],
            policy_version=data["policy_version"],
            policy_digest=data["policy_digest"],
            precondition_digest=data["precondition_digest"],
            parameters_digest=parameters_digest,
        )
        if data["action_digest"] != instance.action_digest:
            raise ContractValidationError(
                "serialized bound action", "action digest mismatch"
            )
        return instance

    def _digest_payload(self) -> dict[str, Any]:
        return _action_digest_payload(
            contract_digest=self.contract_digest,
            parameters_digest=self.parameters_digest,
            principal_digest=self.principal_digest,
            tenant_digest=self.tenant_digest,
            identity_digest_key_version=self.identity_digest_key_version,
            policy_version=self.policy_version,
            policy_digest=self.policy_digest,
            precondition_digest=self.precondition_digest,
        )


def _prepare_parameters(
    contract: ActionContract, parameters: Mapping[str, Any]
) -> tuple[dict[str, Any], str]:
    if not isinstance(parameters, Mapping):
        raise ContractValidationError("parameters", "must be an object")
    strict = _normalize_action_json(parameters, label="parameters")
    validated = _validate_parameters(strict, contract._parameters_validator)
    parameter_bytes = _canonical_bytes(validated, label="parameters")
    if len(parameter_bytes) > contract.max_parameters_bytes:
        raise ContractValidationError(
            "parameters",
            f"canonical payload exceeds {contract.max_parameters_bytes} bytes",
        )
    envelope = {
        "domain": _ACTION_PARAMETERS_DOMAIN,
        "version": _ENVELOPE_VERSION,
        "parameters": validated,
    }
    return validated, _sha256(_canonical_bytes(envelope, label="action parameters"))


def _initialize_bound_action(
    instance: BoundAction,
    *,
    contract: ActionContract,
    normalized: dict[str, Any],
    principal_digest: str,
    tenant_digest: str,
    identity_digest_key_version: str,
    policy_version: str | None,
    policy_digest: str | None,
    precondition_digest: str | None,
    parameters_digest: str,
) -> None:
    payload = _action_digest_payload(
        contract_digest=contract.contract_digest,
        parameters_digest=parameters_digest,
        principal_digest=principal_digest,
        tenant_digest=tenant_digest,
        identity_digest_key_version=identity_digest_key_version,
        policy_version=policy_version,
        policy_digest=policy_digest,
        precondition_digest=precondition_digest,
    )
    object.__setattr__(instance, "contract", contract)
    object.__setattr__(instance, "parameters", _freeze_mapping(normalized))
    object.__setattr__(instance, "principal_digest", principal_digest)
    object.__setattr__(instance, "tenant_digest", tenant_digest)
    object.__setattr__(
        instance, "identity_digest_key_version", identity_digest_key_version
    )
    object.__setattr__(instance, "policy_version", policy_version)
    object.__setattr__(instance, "policy_digest", policy_digest)
    object.__setattr__(instance, "precondition_digest", precondition_digest)
    object.__setattr__(instance, "contract_digest", contract.contract_digest)
    object.__setattr__(instance, "parameters_digest", parameters_digest)
    object.__setattr__(
        instance,
        "action_digest",
        _sha256(_canonical_bytes(payload, label="bound action")),
    )


def _action_digest_payload(
    *,
    contract_digest: str,
    parameters_digest: str,
    principal_digest: str,
    tenant_digest: str,
    identity_digest_key_version: str,
    policy_version: str | None,
    policy_digest: str | None,
    precondition_digest: str | None,
) -> dict[str, Any]:
    return {
        "domain": _BOUND_ACTION_DOMAIN,
        "version": _ENVELOPE_VERSION,
        "contract_digest": contract_digest,
        "parameters_digest": parameters_digest,
        "principal_digest": principal_digest,
        "tenant_digest": tenant_digest,
        "identity_digest_key_version": identity_digest_key_version,
        "policy": {"version": policy_version, "digest": policy_digest},
        "precondition_digest": precondition_digest,
    }


def _principal_digest(
    issuer: str, subject: str, *, key: bytes, key_version: str
) -> str:
    domain = _identity_digest_domain(_PRINCIPAL_DOMAIN, key_version)
    return _hmac_sha256(
        key,
        _canonical_bytes(
            {
                "domain": domain,
                "version": _ENVELOPE_VERSION,
                "issuer": issuer,
                "subject": subject,
            },
            label=domain,
        ),
    )


def _identifier_digest(domain: str, value: str, *, key: bytes, key_version: str) -> str:
    scoped_domain = _identity_digest_domain(domain, key_version)
    return _hmac_sha256(
        key,
        _canonical_bytes(
            {
                "domain": scoped_domain,
                "version": _ENVELOPE_VERSION,
                "identifier": value,
            },
            label=scoped_domain,
        ),
    )


def _validate_parameters(
    value: dict[str, Any], validator: Draft202012Validator
) -> dict[str, Any]:
    error = min(
        validator.iter_errors(value),
        key=lambda error: (
            "/".join(str(item) for item in error.absolute_path),
            str(error.validator or "unknown"),
        ),
        default=None,
    )
    if error is not None:
        path = "/".join(str(item) for item in error.absolute_path) or "$"
        keyword = error.validator if isinstance(error.validator, str) else "unknown"
        raise ContractValidationError(
            "parameters",
            f"{path}: failed JSON Schema constraint {keyword!r}",
        )
    return value


def _normalize_schema(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractValidationError(label, "must be an object")
    normalized = _normalize_action_json(value, label=label)
    try:
        validate_schema(normalized, label=label)
    except RegistryError as exc:
        raise ContractValidationError(label, str(exc)) from exc
    return normalized


def _normalize_requirements(value: Any) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise TypeError("precondition_requirements must be a tuple")
    for item in value:
        _require_identifier("precondition requirement", item)
    if len(set(value)) != len(value):
        raise ValueError("precondition_requirements cannot contain duplicates")
    return tuple(sorted(value))


def _normalize_action_json(value: Any, *, label: str) -> Any:
    budget = [_MAX_CANONICAL_NODES]
    return _normalize_value(value, path=label, depth=0, active=set(), budget=budget)


def _normalize_value(
    value: Any,
    *,
    path: str,
    depth: int,
    active: set[int],
    budget: list[int],
) -> Any:
    if depth > _MAX_NESTING_DEPTH:
        raise ContractValidationError(path, "maximum nesting depth exceeded")
    budget[0] -= 1
    if budget[0] < 0:
        raise ContractValidationError(path, "maximum canonical value count exceeded")
    if isinstance(value, Enum):
        raise ContractValidationError(
            path,
            f"unsupported value type {type(value).__module__}.{type(value).__qualname__}",
        )
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ContractValidationError(
                path, "strings must contain valid Unicode scalar values"
            ) from exc
        return value
    if type(value) is int:
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise ContractValidationError(
                path, "integer exceeds the interoperable IEEE-754 safe range"
            )
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ContractValidationError(path, "non-finite numbers are not valid JSON")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise ContractValidationError(
                path, "negative zero is ambiguous in RFC 8785"
            )
        return value
    if isinstance(value, Mapping):
        return _normalize_container(
            value,
            path=path,
            depth=depth,
            active=active,
            budget=budget,
            mapping=True,
        )
    if isinstance(value, list):
        return _normalize_container(
            value,
            path=path,
            depth=depth,
            active=active,
            budget=budget,
            mapping=False,
        )
    raise ContractValidationError(
        path,
        f"unsupported value type {type(value).__module__}.{type(value).__qualname__}",
    )


def _normalize_container(
    value: Any,
    *,
    path: str,
    depth: int,
    active: set[int],
    budget: list[int],
    mapping: bool,
) -> Any:
    identity = id(value)
    if identity in active:
        raise ContractValidationError(path, "cyclic values are not valid JSON")
    active.add(identity)
    try:
        if mapping:
            result: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise ContractValidationError(path, "object keys must be strings")
                if key in result:
                    raise ContractValidationError(
                        path, "duplicate object keys are invalid"
                    )
                _normalize_value(
                    key,
                    path=path,
                    depth=depth + 1,
                    active=active,
                    budget=budget,
                )
                result[key] = _normalize_value(
                    item,
                    path=f"{path}.{key}",
                    depth=depth + 1,
                    active=active,
                    budget=budget,
                )
            return result
        return [
            _normalize_value(
                item,
                path=f"{path}[{index}]",
                depth=depth + 1,
                active=active,
                budget=budget,
            )
            for index, item in enumerate(value)
        ]
    finally:
        active.remove(identity)


def _canonical_bytes(value: Any, *, label: str) -> bytes:
    try:
        return rfc8785_json_bytes(value, encoder=rfc8785.dumps)
    except CanonicalJsonError as exc:
        raise ContractValidationError(label, str(exc)) from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hmac_sha256(key: bytes, value: bytes) -> str:
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def _identity_digest_domain(domain: str, key_version: str) -> str:
    return f"{domain}.{_IDENTITY_HMAC_ALGORITHM}.{key_version}"


def _require_identity_digest_key(value: Any) -> bytes:
    if type(value) is not bytes:
        raise TypeError("identity_digest_key must be bytes")
    if (
        not _MIN_IDENTITY_DIGEST_KEY_BYTES
        <= len(value)
        <= _MAX_IDENTITY_DIGEST_KEY_BYTES
    ):
        raise ValueError(
            "identity_digest_key must contain 32-4096 bytes of secret material"
        )
    return value


def _require_identity_digest_key_version(value: Any) -> str:
    if type(value) is not str or not _KEY_VERSION.fullmatch(value):
        raise ValueError(
            "identity_digest_key_version must be a stable 1-64 character identifier"
        )
    return value


def _require_identifier(label: str, value: Any) -> None:
    if type(value) is not str or not _STABLE_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a stable 1-256 character identifier")


def _require_identity_value(label: str, value: Any) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must contain valid Unicode scalar values") from exc
    if len(encoded) > 1024:
        raise ValueError(f"{label} must not exceed 1024 UTF-8 bytes")


def _require_digest(label: str, value: Any, *, optional: bool) -> None:
    if value is None and optional:
        return
    if type(value) is not str or not _SHA256_HEX.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")


def _validate_policy(version: Any, digest: Any) -> None:
    if (version is None) != (digest is None):
        raise ValueError("policy_version and policy_digest must be provided together")
    if version is not None:
        _require_identifier("policy_version", version)
        _require_digest("policy_digest", digest, optional=False)


def _require_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractValidationError(label, "must be an object")
    if any(type(key) is not str for key in value):
        raise ContractValidationError(label, "object keys must be strings")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], *, label: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ContractValidationError(
            label,
            f"invalid fields; missing={missing!r}, unexpected={unexpected!r}",
        )


def _require_envelope(value: Mapping[str, Any], *, domain: str, label: str) -> None:
    if type(value["domain"]) is not str or value["domain"] != domain:
        raise ContractValidationError(label, f"unsupported domain {value['domain']!r}")
    if type(value["version"]) is not int or value["version"] != _ENVELOPE_VERSION:
        raise ContractValidationError(
            label, f"unsupported version {value['version']!r}"
        )
