from __future__ import annotations

import inspect
import json
import ssl
from collections.abc import Callable, Mapping
from typing import Any, Awaitable
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .._internal.runtime.blocking import invoke_extension
from .._internal.runtime.extensions import is_native_async_callable
from ..context import ExecutionContext, ExecutionStatus, HistoryEntry
from ..middleware.base import ObservingMiddleware
from ..resilience import CircuitBreaker
from .core import RuntimeBuilder

SlackTransport = Callable[[dict[str, Any]], None | Awaitable[None]]


class SlackWebhookNotifier:
    _ALLOWED_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout_seconds: float = 5.0,
        headers: Mapping[str, str] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        max_request_bytes: int = 16 * 1024,
        failure_threshold: int = 0,
        recovery_timeout: float = 30.0,
        transport: SlackTransport | None = None,
    ) -> None:
        parsed = urlsplit(webhook_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self._ALLOWED_HOSTS
            or parsed.port not in {None, 443}
            or not parsed.path.startswith("/services/")
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("webhook must be an official HTTPS Slack webhook URL")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 0 and 30")
        if max_request_bytes <= 0:
            raise ValueError("max_request_bytes must be positive")
        self._webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds
        self.headers = _safe_headers(headers or {})
        self.ssl_context = ssl_context
        self.max_request_bytes = max_request_bytes
        self.transport = transport
        self._circuit_breaker = CircuitBreaker(
            failure_threshold, recovery_seconds=recovery_timeout
        )

    def send(self, payload: dict[str, Any]) -> None | Awaitable[None]:
        """Send synchronously when possible, or return an awaitable result.

        Existing synchronous webhook callers retain their ``None`` result.
        Runtime middleware uses :meth:`asend` for native async transports so
        their I/O remains on the caller's event loop.
        """

        if self.transport is not None and is_native_async_callable(self.transport):
            return self.asend(payload)
        encoded = self._encode_payload(payload)
        callback: Callable[..., Any]
        argument: dict[str, Any] | bytes
        if self.transport is not None:
            callback = self.transport
            argument = payload
        else:
            callback = self._post
            argument = encoded
        result = self._circuit_breaker.call(callback, argument)
        if inspect.isawaitable(result):
            return self._complete_async_send(result)
        return None

    async def asend(self, payload: dict[str, Any]) -> None:
        """Send through the async-first extension boundary."""

        encoded = self._encode_payload(payload)
        callback: Callable[..., Any]
        argument: dict[str, Any] | bytes
        if self.transport is not None:
            callback = self.transport
            argument = payload
        else:
            callback = self._post
            argument = encoded
        await self._circuit_breaker.acall(invoke_extension, callback, argument)

    def _encode_payload(self, payload: dict[str, Any]) -> bytes:
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.max_request_bytes:
            raise ValueError("Slack request exceeded byte limit")
        return encoded

    async def _complete_async_send(self, result: Awaitable[Any]) -> None:
        await result

    def _post(self, encoded: bytes) -> None:
        request = Request(
            self._webhook_url,
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
                raise RuntimeError(f"Slack webhook returned HTTP {response.status}")


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class SlackNotificationMiddleware(ObservingMiddleware):
    name = "slack"
    priority = 980
    replayable = False

    def __init__(
        self,
        sender: Callable[[dict[str, Any]], None | Awaitable[None]],
        *,
        statuses: frozenset[ExecutionStatus] = frozenset(
            {
                ExecutionStatus.DENIED,
                ExecutionStatus.FAILED,
                ExecutionStatus.UNKNOWN,
            }
        ),
    ) -> None:
        self.sender = sender
        self.statuses = frozenset(statuses)

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if context.status not in self.statuses:
            return context
        if any(entry.middleware == self.name for entry in context.history):
            return context
        reason = {
            ExecutionStatus.DENIED: "governance_denied",
            ExecutionStatus.FAILED: "execution_failed",
            ExecutionStatus.UNKNOWN: "outcome_unknown",
        }.get(context.status, "terminal_state")
        payload = {
            "text": (
                f"Governed tool {context.tool_call.name} ended as "
                f"{context.status.value} (risk={context.risk_tier.name}, "
                f"trace={context.trace_id}, reason={reason})"
            )
        }
        sender = _runtime_sender(self.sender)
        await invoke_extension(sender, payload)
        return context.append_history(
            HistoryEntry(self.name, "sent", "Slack notification sent")
        )


class SlackPlugin:
    name = "slack"
    version = "1"

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout_seconds: float = 5.0,
        headers: Mapping[str, str] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        max_request_bytes: int = 16 * 1024,
        failure_threshold: int = 0,
        recovery_timeout: float = 30.0,
        transport: SlackTransport | None = None,
    ) -> None:
        self.notifier = SlackWebhookNotifier(
            webhook_url,
            timeout_seconds=timeout_seconds,
            headers=headers,
            ssl_context=ssl_context,
            max_request_bytes=max_request_bytes,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            transport=transport,
        )

    def register(self, builder: RuntimeBuilder) -> None:
        builder.add_middleware(
            SlackNotificationMiddleware(self.notifier.send)
        )
        builder.add_service("slack", self.notifier)


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in headers.items():
        if not key or any(ch in key for ch in "\r\n:"):
            raise ValueError("invalid header name")
        if any(ch in value for ch in "\r\n"):
            raise ValueError("invalid header value")
        safe[str(key)] = str(value)
    return safe


def _runtime_sender(
    sender: Callable[[dict[str, Any]], None | Awaitable[None]],
) -> Callable[[dict[str, Any]], None | Awaitable[None]]:
    """Prefer the notifier's explicit async entry point inside a Runtime."""

    owner = getattr(sender, "__self__", None)
    if isinstance(owner, SlackWebhookNotifier):
        return owner.asend
    return sender
