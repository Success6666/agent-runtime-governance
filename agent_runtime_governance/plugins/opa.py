from __future__ import annotations

import asyncio
import json
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from ..context import ExecutionContext, HistoryEntry
from ..decisions import DecisionOutcome, DecisionRecord
from ..middleware.base import GatingMiddleware
from ..resilience import CircuitBreaker
from .core import RuntimeBuilder


@dataclass(frozen=True, slots=True)
class OPADecision:
    allow: bool
    reason: str


class OPAClient:
    def __init__(
        self,
        endpoint: str,
        policy_path: str,
        *,
        timeout_seconds: float = 3.0,
        transport: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None,
        headers: Mapping[str, str] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        max_request_bytes: int = 64 * 1024,
        max_response_bytes: int = 256 * 1024,
        failure_threshold: int = 0,
        recovery_timeout: float = 30.0,
        allow_insecure_http: bool = False,
    ) -> None:
        parsed = urlsplit(endpoint)
        is_local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError(
                "OPA endpoint must be an absolute HTTP or HTTPS URL"
            )
        if parsed.scheme == "http" and not is_local and not allow_insecure_http:
            raise ValueError(
                "OPA endpoint must use HTTPS; non-local HTTP requires "
                "allow_insecure_http=True"
            )
        if parsed.username or parsed.password:
            raise ValueError("OPA endpoint must not contain embedded credentials")
        if parsed.query:
            raise ValueError("OPA endpoint must not contain a query string")
        if parsed.fragment:
            raise ValueError("OPA endpoint must not contain a fragment")
        normalized_path = policy_path.strip("/")
        if (
            not normalized_path
            or ".." in normalized_path.split("/")
            or not re.fullmatch(r"[A-Za-z0-9_/-]+", normalized_path)
        ):
            raise ValueError("invalid OPA policy path")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 0 and 30")
        if max_request_bytes <= 0 or max_response_bytes <= 0:
            raise ValueError("request and response byte limits must be positive")
        self.url = f"{endpoint.rstrip('/')}/v1/data/{normalized_path}"
        self.timeout_seconds = timeout_seconds
        self.transport = transport
        self.headers = _safe_headers(headers or {})
        self.ssl_context = ssl_context
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        self._circuit_breaker = CircuitBreaker(
            failure_threshold, recovery_seconds=recovery_timeout
        )

    def evaluate(self, context: ExecutionContext) -> OPADecision:
        payload = {
            "input": {
                "trace_id": context.trace_id,
                "tool": context.tool_call.name,
                "risk_tier": context.risk_tier.name,
                "risk_score": context.risk_score,
                "user": context.user,
                "tenant": context.tenant,
                "permissions": sorted(context.permissions),
                "requires_approval": context.requires_approval,
            }
        }
        encoded = _encode_json(payload, self.max_request_bytes)
        def request() -> Mapping[str, Any]:
            response = self.transport(payload) if self.transport else self._post(encoded)
            return response

        response = self._circuit_breaker.call(request)
        result = response.get("result")
        if isinstance(result, bool):
            return OPADecision(result, "OPA boolean decision")
        if isinstance(result, Mapping) and isinstance(result.get("allow"), bool):
            return OPADecision(
                bool(result["allow"]),
                str(result.get("reason", "OPA structured decision")),
            )
        raise ValueError("OPA response must contain result bool or result.allow bool")

    def _post(self, encoded: bytes) -> Mapping[str, Any]:
        request = Request(
            self.url,
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "agent-runtime-governance/0.5",
                **self.headers,
            },
            method="POST",
        )
        opener = build_opener(
            _RejectRedirects(),
            HTTPSHandler(context=self.ssl_context),
        )
        with opener.open(request, timeout=self.timeout_seconds) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"OPA returned HTTP {response.status}")
            body = response.read(self.max_response_bytes + 1)
            if len(body) > self.max_response_bytes:
                raise RuntimeError("OPA response exceeded byte limit")
            return json.loads(body.decode("utf-8"))


class OPAMiddleware(GatingMiddleware):
    name = "opa"
    priority = 30
    replayable = False
    requires_action_policy_identity = True
    requires_fail_closed_in_production = True

    def __init__(
        self,
        client: OPAClient,
        *,
        fail_closed: bool = True,
        policy_version: str | None = None,
        policy_digest: str | None = None,
    ) -> None:
        if (policy_version is None) != (policy_digest is None):
            raise ValueError(
                "OPA policy_version and policy_digest must be provided together"
            )
        if policy_version is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}", policy_version
        ):
            raise ValueError("OPA policy_version is invalid")
        if policy_digest is not None and not re.fullmatch(
            r"[0-9a-f]{64}", policy_digest
        ):
            raise ValueError("OPA policy_digest must be a SHA-256 hex digest")
        self.client = client
        self.fail_closed = fail_closed
        self.policy_version = policy_version
        self.policy_digest = policy_digest

    def action_policy_identity(self) -> tuple[str, str] | None:
        if self.policy_version is None or self.policy_digest is None:
            return None
        return self.policy_version, self.policy_digest

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        try:
            decision = await asyncio.to_thread(self.client.evaluate, context)
        except Exception as exc:
            if self.fail_closed:
                raise
            return context.append_history(
                HistoryEntry(
                    self.name,
                    "error",
                    f"OPA unavailable, fail open: {type(exc).__name__}",
                )
            )
        if not decision.allow:
            return context.with_decision(
                DecisionRecord(DecisionOutcome.DENY, decision.reason, self.name)
            ).append_history(
                HistoryEntry(self.name, "deny", decision.reason)
            )
        return context.append_history(
            HistoryEntry(self.name, "allow", decision.reason)
        )


class OPAPlugin:
    name = "opa"
    version = "1"

    def __init__(
        self,
        client: OPAClient,
        *,
        fail_closed: bool = True,
        policy_version: str | None = None,
        policy_digest: str | None = None,
    ) -> None:
        self.client = client
        self.fail_closed = fail_closed
        self.policy_version = policy_version
        self.policy_digest = policy_digest

    def register(self, builder: RuntimeBuilder) -> None:
        builder.add_middleware(
            OPAMiddleware(
                self.client,
                fail_closed=self.fail_closed,
                policy_version=self.policy_version,
                policy_digest=self.policy_digest,
            )
        )
        builder.add_service("opa", self.client)


def _encode_json(payload: Mapping[str, Any], max_bytes: int) -> bytes:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError("OPA request exceeded byte limit")
    return encoded


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in headers.items():
        if not key or any(ch in key for ch in "\r\n:"):
            raise ValueError("invalid header name")
        if any(ch in value for ch in "\r\n"):
            raise ValueError("invalid header value")
        safe[str(key)] = str(value)
    return safe


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None
