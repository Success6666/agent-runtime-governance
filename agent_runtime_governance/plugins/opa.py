from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from ..context import ExecutionContext, HistoryEntry
from ..decisions import DecisionOutcome, DecisionRecord
from ..middleware.base import GatingMiddleware
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
    ) -> None:
        parsed = urlsplit(endpoint)
        is_local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            parsed.scheme not in {"https", "http"}
            or (parsed.scheme == "http" and not is_local)
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("OPA endpoint must use HTTPS or local HTTP without credentials")
        normalized_path = policy_path.strip("/")
        if (
            not normalized_path
            or ".." in normalized_path.split("/")
            or not re.fullmatch(r"[A-Za-z0-9_/-]+", normalized_path)
        ):
            raise ValueError("invalid OPA policy path")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 0 and 30")
        self.url = f"{endpoint.rstrip('/')}/v1/data/{normalized_path}"
        self.timeout_seconds = timeout_seconds
        self.transport = transport

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
        response = self.transport(payload) if self.transport else self._post(payload)
        result = response.get("result")
        if isinstance(result, bool):
            return OPADecision(result, "OPA boolean decision")
        if isinstance(result, Mapping) and isinstance(result.get("allow"), bool):
            return OPADecision(
                bool(result["allow"]),
                str(result.get("reason", "OPA structured decision")),
            )
        raise ValueError("OPA response must contain result bool or result.allow bool")

    def _post(self, payload: dict[str, Any]) -> Mapping[str, Any]:
        request = Request(
            self.url,
            data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "agent-runtime-governance/0.4",
            },
            method="POST",
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"OPA returned HTTP {response.status}")
            return json.loads(response.read().decode("utf-8"))


class OPAMiddleware(GatingMiddleware):
    name = "opa"
    priority = 30
    replayable = False

    def __init__(self, client: OPAClient, *, fail_closed: bool = True) -> None:
        self.client = client
        self.fail_closed = fail_closed

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        try:
            decision = await asyncio.to_thread(self.client.evaluate, context)
        except Exception as exc:
            if self.fail_closed:
                raise
            return context.append_history(
                HistoryEntry(self.name, "error", f"OPA unavailable, fail open: {exc}")
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

    def __init__(self, client: OPAClient, *, fail_closed: bool = True) -> None:
        self.client = client
        self.fail_closed = fail_closed

    def register(self, builder: RuntimeBuilder) -> None:
        builder.add_middleware(
            OPAMiddleware(self.client, fail_closed=self.fail_closed)
        )
        builder.add_service("opa", self.client)
