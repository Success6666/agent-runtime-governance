from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta, timezone
from time import monotonic

from ..approval_store import ApprovalStore
from ..context import ExecutionContext, HistoryEntry
from ..decisions import (
    ApprovalRequest,
    DecisionOutcome,
    DecisionProvider,
    DecisionRecord,
    denial_for_request,
)
from ..identity import IdentityProvider
from .base import GatingMiddleware


class DecisionMiddleware(GatingMiddleware):
    name = "decision"
    replayable = False

    def __init__(
        self,
        provider: DecisionProvider | None = None,
        *,
        store: ApprovalStore | None = None,
        provider_timeout_seconds: float | None = None,
        approval_ttl_seconds: float | None = None,
        reservation_ttl_seconds: float = 30.0,
        identity_provider: IdentityProvider | None = None,
        require_approver: bool = True,
    ) -> None:
        if provider is None and store is None:
            raise ValueError("provider or store is required")
        if provider_timeout_seconds is not None and provider_timeout_seconds <= 0:
            raise ValueError("provider_timeout_seconds must be greater than zero")
        if approval_ttl_seconds is not None and approval_ttl_seconds <= 0:
            raise ValueError("approval_ttl_seconds must be greater than zero")
        if reservation_ttl_seconds <= 0:
            raise ValueError("reservation_ttl_seconds must be greater than zero")
        if identity_provider is not None:
            raise ValueError(
                "identity_provider must be configured on Runtime so identity is "
                "verified once at the trust boundary"
            )
        self._provider = provider
        self._store = store
        self._provider_timeout_seconds = (
            30.0 if provider_timeout_seconds is None else provider_timeout_seconds
        )
        self._approval_ttl_seconds = (
            300.0 if approval_ttl_seconds is None else approval_ttl_seconds
        )
        self._require_approver = require_approver
        self._reservation_ttl_seconds = reservation_ttl_seconds
        self._reservations: dict[str, tuple[ApprovalRequest, str, float]] = {}
        self._reservation_lock = threading.Lock()

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        if not context.requires_approval:
            return context.append_history(
                HistoryEntry(self.name, "skip", "human decision not required")
            )
        request = ApprovalRequest(
            trace_id=context.trace_id,
            request_id=context.request_id,
            tool_name=context.tool_call.name,
            arguments={
                "args": list(context.tool_call.args),
                "kwargs": dict(context.tool_call.kwargs),
            },
            risk_tier=context.risk_tier.name,
            reason="tool requires human decision",
            expires_at=self._expires_at(),
            policy_version=_metadata_text(
                context, "policy_version"
            )
            or _metadata_text(context, "policy_digest"),
            subject=context.user,
            tenant=context.tenant,
            identity_issuer=_metadata_text(context, "identity_issuer"),
        )
        if self._store is not None:
            await asyncio.to_thread(self._store.pending, request)
        if self._provider is not None:
            decision = await self._decide(context, request)
            if self._store is not None:
                decision = await asyncio.to_thread(
                    self._store.decide, request.request_id, decision
                )
                reservation = await asyncio.to_thread(
                    self._store.reserve,
                    request,
                    lease_seconds=self._reservation_ttl_seconds,
                )
                decision = reservation.decision
                if reservation.token is not None:
                    self._remember_reservation(
                        context.trace_id, request, reservation.token
                    )
        else:
            assert self._store is not None
            reservation = await asyncio.to_thread(
                self._store.reserve,
                request,
                lease_seconds=self._reservation_ttl_seconds,
            )
            decision = reservation.decision
            if reservation.token is not None:
                self._remember_reservation(
                    context.trace_id, request, reservation.token
                )
        try:
            if request.is_expired():
                raise ValueError("approval request expired")
            decision.validate_for(request)
        except ValueError as exc:
            decision = denial_for_request(request, str(exc), source=self.name)
        if (
            decision.outcome is DecisionOutcome.ALLOW
            and self._require_approver
            and not decision.approver
        ):
            decision = denial_for_request(
                request, "approval allow decision requires an approver", source=self.name
            )
        if decision.outcome is not DecisionOutcome.ALLOW:
            context = await self.release_approval(context)
        updated = context.with_decision(decision)
        if decision.outcome is DecisionOutcome.ALLOW:
            updated = updated.evolve(
                metadata={
                    **updated.metadata,
                    "approval_granted": True,
                    "approval_request_id": request.request_id,
                    "approval_decision_id": decision.decision_id,
                }
            )
        return updated.append_history(
            HistoryEntry(
                self.name,
                decision.outcome.value,
                decision.reason,
                data={
                    "request_id": request.request_id,
                    "decision_id": decision.decision_id,
                    "arguments_digest": request.arguments_digest,
                    "policy_version": request.policy_version,
                    "approver": decision.approver,
                },
            )
        )

    async def commit_approval(self, context: ExecutionContext) -> ExecutionContext:
        reservation = self._pop_reservation(context.trace_id)
        if self._store is None:
            return context
        if reservation is None:
            if not context.metadata.get("approval_granted"):
                return context
            decision = DecisionRecord(
                DecisionOutcome.DENY,
                "approval reservation was unavailable at the execution boundary",
                self.name,
                request_id=_metadata_text(context, "approval_request_id"),
                tool_name=context.tool_call.name,
                subject=context.user,
                tenant=context.tenant,
                identity_issuer=_metadata_text(context, "identity_issuer"),
            )
            return context.with_decision(decision).append_history(
                HistoryEntry(
                    self.name,
                    "deny",
                    decision.reason,
                    data={"request_id": decision.request_id},
                )
            )
        request, token = reservation
        try:
            decision = await asyncio.to_thread(self._store.commit, request, token)
            decision.validate_for(request)
            if (
                context.decision is None
                or context.decision.decision_id != decision.decision_id
            ):
                raise ValueError("approval decision changed before execution")
        except Exception:
            await asyncio.to_thread(self._store.release, request.request_id, token)
            decision = denial_for_request(
                request,
                "approval reservation could not be committed",
                source=self.name,
            )
        updated = context.with_decision(decision)
        return updated.append_history(
            HistoryEntry(
                self.name,
                "committed" if decision.outcome is DecisionOutcome.ALLOW else "deny",
                (
                    "approval consumed at execution boundary"
                    if decision.outcome is DecisionOutcome.ALLOW
                    else decision.reason
                ),
                data={"request_id": request.request_id},
            )
        )

    async def release_approval(self, context: ExecutionContext) -> ExecutionContext:
        reservation = self._pop_reservation(context.trace_id)
        if reservation is None or self._store is None:
            return context
        request, token = reservation
        try:
            await asyncio.to_thread(self._store.release, request.request_id, token)
        except Exception:
            return context.append_history(
                HistoryEntry(
                    self.name,
                    "error",
                    "approval reservation release failed; lease recovery required",
                )
            )
        return context.append_history(
            HistoryEntry(
                self.name,
                "released",
                "approval reservation released before execution",
            )
        )

    def _remember_reservation(
        self, trace_id: str, request: ApprovalRequest, token: str
    ) -> None:
        with self._reservation_lock:
            now = monotonic()
            expired = [
                key
                for key, (_, _, deadline) in self._reservations.items()
                if deadline <= now
            ]
            for key in expired:
                self._reservations.pop(key, None)
            self._reservations[trace_id] = (
                request,
                token,
                now + self._reservation_ttl_seconds,
            )

    def _pop_reservation(
        self, trace_id: str
    ) -> tuple[ApprovalRequest, str] | None:
        with self._reservation_lock:
            reservation = self._reservations.pop(trace_id, None)
        if reservation is None:
            return None
        request, token, _ = reservation
        return request, token

    @property
    def active_reservation_count(self) -> int:
        with self._reservation_lock:
            return len(self._reservations)

    async def _decide(
        self, context: ExecutionContext, request: ApprovalRequest
    ) -> DecisionRecord:
        assert self._provider is not None
        try:
            decision = await asyncio.wait_for(
                self._provider.decide(context, request),
                timeout=self._provider_timeout_seconds,
            )
            if decision.outcome is DecisionOutcome.REQUIRE_HUMAN:
                return denial_for_request(
                    request,
                    "human decision provider must return allow or deny",
                    source=self.name,
                )
            return decision.bind_to(request)
        except (asyncio.TimeoutError, TimeoutError):
            return denial_for_request(
                request, "decision provider timed out", source=self.name
            )
        except ValueError:
            return denial_for_request(
                request, "decision provider returned an invalid decision", source=self.name
            )

    def _expires_at(self) -> str | None:
        return (
            datetime.now(timezone.utc) + timedelta(seconds=self._approval_ttl_seconds)
        ).isoformat()

def _metadata_text(context: ExecutionContext, key: str) -> str | None:
    value = context.metadata.get(key)
    return None if value is None else str(value)


ApprovalMiddleware = DecisionMiddleware
