from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_runtime_governance.context import ExecutionContext, ToolCall
from agent_runtime_governance.contracts import canonical_json_bytes
from agent_runtime_governance.decisions import DecisionOutcome, DecisionRecord
from agent_runtime_governance.errors import ContextMutationError

json_scalars = st.none() | st.booleans() | st.integers() | st.floats(
    allow_nan=False, allow_infinity=False
) | st.text()
json_values = st.recursive(
    json_scalars,
    lambda children: st.lists(children, max_size=5)
    | st.dictionaries(st.text(max_size=20), children, max_size=5),
    max_leaves=30,
)


@given(json_values)
def test_canonical_json_is_deterministic_and_round_trippable(value) -> None:
    first = canonical_json_bytes(value, label="value")
    second = canonical_json_bytes(value, label="value")
    assert first == second
    assert json.loads(first) == value


@given(st.text(max_size=39).map(lambda value: f"r{value}"))
def test_denial_is_monotonic(reason: str) -> None:
    denied = ExecutionContext.create(ToolCall("read")).with_decision(
        DecisionRecord(DecisionOutcome.DENY, reason, "property")
    )
    with pytest.raises(ContextMutationError):
        denied.evolve(
            decision=DecisionRecord(DecisionOutcome.ALLOW, "override", "property")
        )


@given(st.dictionaries(st.text(max_size=20), json_values, max_size=8))
def test_context_metadata_is_detached_from_source(metadata) -> None:
    context = ExecutionContext.create(ToolCall("read"), metadata=metadata)
    serialized = context.to_dict()["metadata"]
    metadata.clear()
    assert serialized == context.to_dict()["metadata"]
