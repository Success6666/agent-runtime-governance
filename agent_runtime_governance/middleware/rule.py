from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Pattern

from ..context import ExecutionContext, HistoryEntry
from ..decision_explanations import DecisionControl, decision_controls_history_data
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
        names = [rule.name for rule in rules]
        if len(set(names)) != len(names):
            raise ValueError("rule names must be unique")
        self._rules = tuple((rule, rule.compiled()) for rule in rules)

    async def process(self, context: ExecutionContext) -> ExecutionContext:
        controls: list[DecisionControl] = []
        for rule, pattern in self._rules:
            matched = pattern.search(context.input_text) is not None
            control = DecisionControl(
                control_id=(
                    "rule."
                    + hashlib.sha256(rule.name.encode("utf-8")).hexdigest()
                ),
                control_version=1,
                effect="deny",
                result="matched" if matched else "not_matched",
                reason_code="rule_matched" if matched else "rule_not_matched",
            )
            controls.append(control)
            if control.result == "matched":
                decision = DecisionRecord(
                    outcome=DecisionOutcome.DENY,
                    reason=rule.reason,
                    source=f"rule:{rule.name}",
                )
                return context.with_decision(decision).append_history(
                    HistoryEntry(
                        self.name,
                        "deny",
                        rule.reason,
                        data={
                            "rule": rule.name,
                            **decision_controls_history_data(controls),
                        },
                    )
                )
        controls.append(
            DecisionControl(
                control_id="rule.allow",
                control_version=1,
                effect="allow",
                result="matched",
                reason_code="no_rule_matched",
            )
        )
        return context.append_history(
            HistoryEntry(
                self.name,
                "allow",
                "no rule matched",
                data=decision_controls_history_data(controls),
            )
        )

