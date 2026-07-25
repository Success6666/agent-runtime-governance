from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from .context import ExecutionContext
from .errors import AuditIntegrityError


DEFAULT_SENSITIVE_KEYS = frozenset(
    {"password", "passwd", "secret", "token", "api_key", "authorization", "cookie"}
)


class AuditSink(Protocol):
    def write(self, event: Mapping[str, Any]) -> None: ...


class InMemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def write(self, event: Mapping[str, Any]) -> None:
        with self._lock:
            self.events.append(dict(event))


class JSONLAuditSink:
    """Append-only JSONL sink with optional HMAC signatures."""

    def __init__(
        self,
        path: str | Path,
        *,
        sign_key: bytes | str | None = None,
        sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = sign_key.encode() if isinstance(sign_key, str) else sign_key
        self._sensitive_keys = frozenset(key.lower() for key in sensitive_keys)
        self._lock = threading.Lock()

    def write(self, event: Mapping[str, Any]) -> None:
        payload = _redact(dict(event), self._sensitive_keys)
        if self._key:
            payload["signature"] = sign_event(payload, self._key)
        line = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line + "\n")

    def read_verified(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if not self.path.exists():
            return events
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                event = json.loads(line)
                signature = event.pop("signature", None)
                if self._key:
                    expected = sign_event(event, self._key)
                    if not signature or not hmac.compare_digest(signature, expected):
                        raise AuditIntegrityError(
                            f"invalid audit signature on line {line_number}"
                        )
                    event["signature"] = signature
                events.append(event)
        return events


def context_event(context: ExecutionContext, *, stage: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "trace_id": context.trace_id,
        "span_id": context.span_id,
        "request_id": context.request_id,
        "tool_name": context.tool_call.name,
        "risk_tier": context.risk_tier.name,
        "risk_score": context.risk_score,
        "status": context.status.value,
        "decision": context.decision.outcome.value if context.decision else None,
        "reason": context.decision.reason if context.decision else None,
        "context": context.to_dict(),
    }


def sign_event(event: Mapping[str, Any], key: bytes) -> str:
    message = json.dumps(
        event, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _redact(value: Any, sensitive_keys: frozenset[str]) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            result[str(key)] = (
                "[REDACTED]"
                if normalized in sensitive_keys
                else _redact(item, sensitive_keys)
            )
        return result
    if isinstance(value, list | tuple):
        return [_redact(item, sensitive_keys) for item in value]
    return value

