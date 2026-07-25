from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from ..context import ExecutionContext, ExecutionStatus, HistoryEntry
from ..middleware.base import ObservingMiddleware
from .core import RuntimeBuilder


class SlackWebhookNotifier:
    _ALLOWED_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})

    def __init__(self, webhook_url: str, *, timeout_seconds: float = 5.0) -> None:
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
        self._webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds

    def send(self, payload: dict[str, Any]) -> None:
        request = Request(
            self._webhook_url,
            data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "agent-runtime-governance/0.4",
            },
            method="POST",
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Slack webhook returned HTTP {response.status}")


class SlackNotificationMiddleware(ObservingMiddleware):
    name = "slack"
    priority = 980
    replayable = False

    def __init__(
        self,
        sender: Callable[[dict[str, Any]], None],
        *,
        statuses: frozenset[ExecutionStatus] = frozenset(
            {ExecutionStatus.DENIED, ExecutionStatus.FAILED}
        ),
    ) -> None:
        self.sender = sender
        self.statuses = frozenset(statuses)

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if context.status not in self.statuses:
            return context
        if any(entry.middleware == self.name for entry in context.history):
            return context
        reason = (
            context.decision.reason
            if context.status is ExecutionStatus.DENIED and context.decision
            else "tool execution failed"
        )
        safe_reason = " ".join((reason or "n/a").split())[:200]
        payload = {
            "text": (
                f"Governed tool {context.tool_call.name} ended as "
                f"{context.status.value} (risk={context.risk_tier.name}, "
                f"trace={context.trace_id}, reason={safe_reason})"
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
    ) -> None:
        self.notifier = SlackWebhookNotifier(
            webhook_url, timeout_seconds=timeout_seconds
        )

    def register(self, builder: RuntimeBuilder) -> None:
        builder.add_middleware(
            SlackNotificationMiddleware(self.notifier.send)
        )
        builder.add_service("slack", self.notifier)
