from __future__ import annotations

import inspect
import json
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Awaitable, Protocol
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .._internal.runtime.blocking import invoke_extension
from .._internal.runtime.extensions import is_native_async_callable
from ..context import ExecutionContext, HistoryEntry
from ..decision_explanations import (
    DecisionControl,
    DecisionExplanationValidationError,
    decision_controls_history_data,
    unavailable_decision_controls_history_data,
)
from ..decisions import DecisionOutcome, DecisionRecord
from ..middleware.base import GatingMiddleware
from ..resilience import CircuitBreaker
from .core import RuntimeBuilder


@dataclass(frozen=True, slots=True)
class OPADecision:
    allow: bool
    reason: str
    controls: tuple[DecisionControl, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self.allow) is not bool:
            raise TypeError("OPA allow must be a boolean")
        if not isinstance(self.reason, str):
            raise TypeError("OPA reason must be a string")
        controls = tuple(self.controls)
        if any(not isinstance(item, DecisionControl) for item in controls):
            raise TypeError("OPA controls must contain DecisionControl values")
        identities = tuple(item.identity for item in controls)
        if len(set(identities)) != len(identities) or identities != tuple(
            sorted(identities)
        ):
            raise DecisionExplanationValidationError(
                "OPA controls must be ordered and unique"
            )
        object.__setattr__(self, "controls", controls)


OPATransport = Callable[
    [dict[str, Any]], Mapping[str, Any] | Awaitable[Mapping[str, Any]]
]


class OPAEvaluator(Protocol):
    """The narrow policy-client capability used by the middleware."""

    def evaluate(
        self, context: ExecutionContext
    ) -> OPADecision | Awaitable[OPADecision]: ...


class OPAClient:
    def __init__(
        self,
        endpoint: str,
        policy_path: str,
        *,
        timeout_seconds: float = 3.0,
        transport: OPATransport | None = None,
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

    def evaluate(
        self, context: ExecutionContext
    ) -> OPADecision | Awaitable[OPADecision]:
        """Evaluate synchronously when possible, or return an awaitable result.

        The established direct API remains synchronous for legacy transports.
        An async transport cannot be driven safely from this method, so its
        result is returned for an async caller to await.  Runtime middleware
        uses :meth:`aevaluate` to keep that transport on the caller event loop.
        """

        if self.transport is not None and is_native_async_callable(self.transport):
            return self.aevaluate(context)
        payload, encoded = self._request_payload(context)
        if self.transport is not None:
            response = self._circuit_breaker.call(self.transport, payload)
        else:
            response = self._circuit_breaker.call(self._post, encoded)
        if inspect.isawaitable(response):
            return self._parse_async_response(response)
        return self._parse_response(response)

    async def aevaluate(self, context: ExecutionContext) -> OPADecision:
        """Evaluate through the async-first extension boundary.

        Native async transports execute on the active caller loop.  Existing
        synchronous transports are delegated to the Runtime-owned fallback
        when a Runtime operation is active.
        """

        payload, encoded = self._request_payload(context)
        callback: Callable[..., Any]
        argument: dict[str, Any] | bytes
        if self.transport is not None:
            callback = self.transport
            argument = payload
        else:
            callback = self._post
            argument = encoded
        response = await self._circuit_breaker.acall(
            invoke_extension, callback, argument
        )
        return self._parse_response(response)

    def _request_payload(
        self, context: ExecutionContext
    ) -> tuple[dict[str, Any], bytes]:
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
        return payload, encoded

    async def _parse_async_response(
        self, response: Awaitable[Mapping[str, Any]]
    ) -> OPADecision:
        return self._parse_response(await response)

    @staticmethod
    def _parse_response(response: Mapping[str, Any]) -> OPADecision:
        if not isinstance(response, Mapping):
            raise ValueError("OPA response must be a JSON object")
        result = response.get("result")
        if isinstance(result, bool):
            return OPADecision(result, "OPA boolean decision")
        if isinstance(result, Mapping) and isinstance(result.get("allow"), bool):
            return OPADecision(
                bool(result["allow"]),
                str(result.get("reason", "OPA structured decision")),
                _structured_controls(result),
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
        client: OPAEvaluator,
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
            evaluator = (
                self.client.aevaluate
                if isinstance(self.client, OPAClient)
                else self.client.evaluate
            )
            decision = await invoke_extension(evaluator, context)
            if not isinstance(decision, OPADecision):
                raise TypeError("OPA evaluator must return an OPADecision")
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
                HistoryEntry(
                    self.name,
                    "deny",
                    decision.reason,
                    data={
                        **self._policy_metadata(),
                        **_decision_controls_history_data(decision),
                    },
                )
            )
        return context.append_history(
            HistoryEntry(
                self.name,
                "allow",
                decision.reason,
                data={
                    **self._policy_metadata(),
                    **_decision_controls_history_data(decision),
                },
            )
        )

    def _policy_metadata(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "policy_version": self.policy_version,
                "policy_digest": self.policy_digest,
            }.items()
            if value is not None
        }


class OPAPlugin:
    name = "opa"
    version = "1"

    def __init__(
        self,
        client: OPAEvaluator,
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


def _structured_controls(result: Mapping[str, Any]) -> tuple[DecisionControl, ...]:
    """Parse only the documented machine-readable OPA explanation contract."""

    if "decision_explanation" not in result:
        return ()
    explanation = result["decision_explanation"]
    if not isinstance(explanation, Mapping) or set(explanation) != {"controls"}:
        raise ValueError("OPA decision_explanation must contain only controls")
    raw_controls = explanation["controls"]
    if not isinstance(raw_controls, list):
        raise ValueError("OPA decision_explanation controls must be a list")
    try:
        return tuple(DecisionControl.from_dict(item) for item in raw_controls)
    except (DecisionExplanationValidationError, TypeError, ValueError) as exc:
        raise ValueError("OPA decision_explanation controls are invalid") from exc


def _decision_controls_history_data(decision: OPADecision) -> dict[str, object]:
    if decision.controls:
        return decision_controls_history_data(decision.controls)
    return unavailable_decision_controls_history_data()


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
