# Decision Explanation Attachments (v0.9)

A decision explanation is a detached, canonical description of the
deterministic policy controls evaluated for an already bound action. It is not
an authorizer, a runtime snapshot, an audit log, or an execution receipt.

The v0.8 Evidence Bundle v1 remains closed. An attachment may reference a
bundle digest, but it never changes the bundle bytes, signature sidecars,
receipt-verification protocol, or reconciliation state.

## Build an attachment

Built-in Python policy, YAML policy, and rule middleware record a bounded,
structured projection while they evaluate. After the Runtime has produced a
context with a bound action, build an attachment from that projection:

```python
from agent_runtime_governance import (
    DecisionExplanationAttachment,
    verify_decision_explanation_document,
)

attachment = DecisionExplanationAttachment.from_context(result.context)
report = verify_decision_explanation_document(
    attachment.to_dict(),
    expected_attachment_digest=attachment.attachment_digest,
    expected_action_digest=result.context.bound_action.action_digest,
)
assert report["integrity"]["ok"] is True
assert report["binding"]["ok"] is True
```

`from_context()` requires a bound policy version and digest. If a policy event
recorded an identity that differs from the bound action, the operation fails
closed. Supplying `evidence_bundle=bundle` additionally verifies that the
bundle action and policy identities match before recording its digest.

The fields are deliberately small and closed:

- action digest and optional evidence-bundle digest;
- policy version and policy digest;
- deterministic policy decision, risk tier, and approval requirement; and
- ordered controls with a stable ID/version, effect, result, and reason code.

Raw parameters, prompts, model output, chain-of-thought, secrets, identity
values, receipts, and free-text policy reasons are rejected. `final_decision`
means the deterministic policy result. A human approval refusal remains an
approval record; it is not rewritten as a policy denial. External receipt
outcomes remain the responsibility of the v0.8 `ReceiptVerifier`.

## External policy contract

An external policy integration can contribute only an explicit structured
control sequence. For OPA HTTP responses, use this bounded result shape:

```json
{
  "result": {
    "allow": true,
    "decision_explanation": {
      "controls": [
        {
          "control_id": "opa-policy.allow",
          "control_version": 1,
          "effect": "allow",
          "result": "matched",
          "reason_code": "opa_allow"
        }
      ]
    }
  }
}
```

An OPA `reason` string remains diagnostic-only. A plain-text response cannot
produce an explanation attachment.

## Inspect and compare

The inspect command verifies first, then renders only the accepted report:

```bash
python -m agent_runtime_governance.inspect decision-explanation.json \
  --expected-attachment-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

For regression analysis, verify both inputs before comparison:

```python
from agent_runtime_governance import (
    compare_verified_decision_explanations,
    verify_decision_explanation,
)

comparison = compare_verified_decision_explanations(
    verify_decision_explanation(baseline),
    verify_decision_explanation(candidate),
)
for difference in comparison.differences:
    print(difference.field, difference.baseline, difference.candidate)
```

Comparison accepts only verified attachments for the same action digest. It is
read-only: it does not call tools, replay a Runtime, invoke an LLM or human
decision provider, query a receipt provider, or mutate persistent state.
`PolicyDriftDetector.compare()` remains a different diagnostic that replays
recorded contexts through two Runtime configurations.

## Integrity boundary

The attachment digest commits to its canonical document. Passing an expected
attachment digest detects mutation after that digest was recorded elsewhere.
Like an unsigned Evidence Bundle, a valid attachment without a protected
external commitment demonstrates structural integrity and binding consistency,
not independent source authenticity.

## Measured overhead

The committed [Windows/Python 3.14 measurement](../benchmarks/results/v0.9.0-windows-python314.json)
uses 1,000 requests and three alternating paired runs. It compares attachment
projection with projection plus offline verification on the same prepared,
bound policy context. The [paired budget](../benchmarks/budgets/v0.9.0-decision-explanations.json)
checks that narrow comparison. It is point-in-time local measurement evidence,
not a production latency or throughput guarantee.
