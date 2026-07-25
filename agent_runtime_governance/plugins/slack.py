from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from ..context import ExecutionContext, ExecutionStatus, HistoryEntry
from ..middleware.base import ObservingMiddleware
from ..resilience import CircuitBreaker
from .core import RuntimeBuilder


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
        self._circuit_breaker = CircuitBreaker(
            failure_threshold, recovery_seconds=recovery_timeout
        )

    def send(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.max_request_bytes:
            raise ValueError("Slack request exceeded byte limit")
        def post() -> None:
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
            with urlopen(
                request, timeout=self.timeout_seconds, context=self.ssl_context
            ) as response:
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"Slack webhook returned HTTP {response.status}")

        self._circuit_breaker.call(post)


class SlackNotificationMiddleware(ObservingMiddleware):
    name = "slack"
    priority = 980
    replayable = False

    def __init__(
        self,
        sender: Callable[[dict[str, Any]], None],
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
        await asyncio.to_thread(self.sender, payload)
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
    ) -> None:
        self.notifier = SlackWebhookNotifier(
            webhook_url,
            timeout_seconds=timeout_seconds,
            headers=headers,
            ssl_context=ssl_context,
            max_request_bytes=max_request_bytes,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
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
