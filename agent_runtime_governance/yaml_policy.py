from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .context import RiskTier
from .policy import PolicyMiddleware, SimplePolicy


class PolicyValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    version: str
    digest: str
    policy: SimplePolicy

    def middleware(self) -> PolicyMiddleware:
        return PolicyMiddleware(
            self.policy, version=self.version, digest=self.digest
        )


class YAMLPolicyLoader:
    ROOT_KEYS = frozenset({"version", "policies"})
    POLICY_KEYS = frozenset(
        {
            "tool",
            "effect",
            "approval",
            "admin_only",
            "required_permissions",
            "risk",
        }
    )

    @classmethod
    def load(cls, source: str | Path) -> PolicyDocument:
        path = Path(source)
        return cls.loads(path.read_text(encoding="utf-8"))

    @classmethod
    def loads(cls, text: str) -> PolicyDocument:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "install agent-runtime-governance[yaml] to load YAML policies"
            ) from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyValidationError(f"invalid YAML: {exc}") from exc
        return cls._parse(data)

    @classmethod
    def _parse(cls, data: Any) -> PolicyDocument:
        root = cls._mapping(data, "policy document")
        cls._reject_unknown(root, cls.ROOT_KEYS, "policy document")
        version = root.get("version")
        if isinstance(version, bool) or not isinstance(version, str | int) or not str(version).strip():
            raise PolicyValidationError("version must be a non-empty string or integer")
        entries = root.get("policies")
        if not isinstance(entries, list):
            raise PolicyValidationError("policies must be a list")

        denied: set[str] = set()
        approvals: set[str] = set()
        admin_only: set[str] = set()
        required: dict[str, frozenset[str]] = {}
        risks: dict[str, RiskTier] = {}
        seen: set[str] = set()
        canonical_entries: list[dict[str, Any]] = []

        for index, value in enumerate(entries):
            entry = cls._mapping(value, f"policies[{index}]")
            cls._reject_unknown(entry, cls.POLICY_KEYS, f"policies[{index}]")
            tool = entry.get("tool")
            if not isinstance(tool, str) or not tool.strip():
                raise PolicyValidationError(f"policies[{index}].tool must be non-empty")
            if tool in seen:
                raise PolicyValidationError(f"duplicate policy for tool {tool!r}")
            seen.add(tool)

            effect = entry.get("effect", "allow")
            if effect not in {"allow", "deny"}:
                raise PolicyValidationError(f"invalid effect for tool {tool!r}")
            approval = entry.get("approval", "none")
            if approval not in {"none", "required"}:
                raise PolicyValidationError(f"invalid approval for tool {tool!r}")
            is_admin_only = entry.get("admin_only", False)
            if not isinstance(is_admin_only, bool):
                raise PolicyValidationError(f"admin_only for {tool!r} must be boolean")
            permissions_value = entry.get("required_permissions", [])
            if not isinstance(permissions_value, list) or not all(
                isinstance(item, str) and item for item in permissions_value
            ):
                raise PolicyValidationError(
                    f"required_permissions for {tool!r} must be a string list"
                )
            risk_value = entry.get("risk")
            if risk_value is not None:
                try:
                    risks[tool] = RiskTier[str(risk_value).upper()]
                except KeyError as exc:
                    raise PolicyValidationError(f"invalid risk for tool {tool!r}") from exc

            if effect == "deny":
                denied.add(tool)
            if approval == "required":
                approvals.add(tool)
            if is_admin_only:
                admin_only.add(tool)
            if permissions_value:
                required[tool] = frozenset(permissions_value)
            canonical_entries.append(
                {
                    "tool": tool,
                    "effect": effect,
                    "approval": approval,
                    "admin_only": is_admin_only,
                    "required_permissions": sorted(permissions_value),
                    "risk": risks[tool].name if tool in risks else None,
                }
            )

        canonical = {
            "version": str(version),
            "policies": sorted(canonical_entries, key=lambda item: item["tool"]),
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return PolicyDocument(
            version=str(version),
            digest=digest,
            policy=SimplePolicy(
                denied_tools=frozenset(denied),
                approval_tools=frozenset(approvals),
                admin_only=frozenset(admin_only),
                required_permissions=required,
                risk_overrides=risks,
            ),
        )

    @staticmethod
    def _mapping(value: Any, location: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise PolicyValidationError(f"{location} must be a mapping")
        return value

    @staticmethod
    def _reject_unknown(
        value: Mapping[str, Any], allowed: frozenset[str], location: str
    ) -> None:
        unknown = sorted(set(value).difference(allowed))
        if unknown:
            raise PolicyValidationError(
                f"unknown keys in {location}: {', '.join(unknown)}"
            )
