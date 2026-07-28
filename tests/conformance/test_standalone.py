import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("case_name", ("success", "policy_denied", "approval_denied"))
async def test_standalone_runtime_keeps_protected_semantics(
    case_name,
    conformance_case,
    forged_metadata,
    new_conformance_harness,
    assert_protected_semantics,
) -> None:
    case = conformance_case(case_name)

    async with new_conformance_harness(case) as harness:
        observation = await harness.invoke(
            case, case.service, case.secret, forged_metadata
        )

    assert_protected_semantics(case, observation)
