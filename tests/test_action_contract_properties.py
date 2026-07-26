from __future__ import annotations

import math

from hypothesis import given
from hypothesis import strategies as st

from agent_runtime_governance import ActionContract, BoundAction, ExecutionMode

_SAFE_INTEGER = (1 << 53) - 1

safe_json_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-_SAFE_INTEGER, max_value=_SAFE_INTEGER)
    | st.floats(allow_nan=False, allow_infinity=False).filter(
        lambda value: not (value == 0.0 and math.copysign(1.0, value) < 0)
    )
    | st.text(alphabet=st.characters(exclude_categories=("Cs",)))
)
safe_json_values = st.recursive(
    safe_json_scalars,
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(
        st.text(alphabet=st.characters(exclude_categories=("Cs",)), max_size=12),
        children,
        max_size=4,
    ),
    max_leaves=20,
)


def _contract() -> ActionContract:
    return ActionContract(
        contract_id="ops.property-test",
        contract_version=1,
        tool_name="property_test",
        execution_mode=ExecutionMode.MUTATING,
        parameters_schema={"type": "object"},
        effect_class="test.property",
        max_parameters_bytes=1_048_576,
    )


@given(st.dictionaries(st.text(min_size=1, max_size=12), safe_json_values, max_size=6))
def test_supported_parameters_have_deterministic_action_identity(parameters) -> None:
    contract = _contract()
    first = contract.bind(
        parameters,
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    second = contract.bind(
        dict(reversed(list(parameters.items()))),
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    assert first.parameters_digest == second.parameters_digest
    assert first.action_digest == second.action_digest


@given(st.dictionaries(st.text(min_size=1, max_size=12), safe_json_values, max_size=6))
def test_serialized_bound_actions_round_trip(parameters) -> None:
    bound = _contract().bind(
        parameters,
        identity_issuer="issuer:local",
        principal="user:operator",
        tenant="tenant:acme",
    )
    assert BoundAction.from_dict(bound.to_dict()) == bound
