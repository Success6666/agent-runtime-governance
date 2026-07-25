from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from ..context import ExecutionContext, HistoryEntry
from ..decisions import DecisionOutcome, DecisionRecord
from .base import GatingMiddleware


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    pattern: str | Pattern[str]
    reason: str
    flags: int = re.IGNORECASE

    def compiled(self) -> Pattern[str]:
        return re.compile(self.pattern, self.flags) if isinstance(self.pattern, str) else self.pattern


class RuleMiddleware(GatingMiddleware):
    name = "rule"

    def __init__(self, rules: list[Rule] | tuple[Rule, ...]) -> None:
        self._rules = tuple((rule, rule.compiled()) for rule in rules)

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        for rule, pattern in self._rules:
            if pattern.search(context.input_text):
                decision = DecisionRecord(
                    outcome=DecisionOutcome.DENY,
                    reason=rule.reason,
                    source=f"rule:{rule.name}",
                )
                return context.with_decision(decision).append_history(
                    HistoryEntry(self.name, "deny", rule.reason, data={"rule": rule.name})
                )
        return context.append_history(HistoryEntry(self.name, "allow", "no rule matched"))

