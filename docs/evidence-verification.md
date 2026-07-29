# Offline evidence verification (v0.8)

`python -m agent_runtime_governance.verify` validates a portable Governance
Evidence Bundle without performing network access itself. It is a v0.8
capability. It never infers a provider, endpoint, receipt, or protected anchor
from bundle contents.

## Inputs

The positional `BUNDLE` is the strict v1 JSON produced by
`EvidenceBundle.to_dict()`. Its in-bundle `signature` remains `null`. A signed
bundle uses a separate `EvidenceSignatureAttachment` file:

```bash
python -m agent_runtime_governance.verify bundle.json \
  --signature signature.json \
  --trust-roots trust-roots.json \
  --at 2026-07-03T00:00:00Z
```

Detached signature verification needs the optional dependency:

```bash
pip install "agent-runtime-governance[evidence]"
```

The core installation can still validate an unsigned bundle. If detached
signature verification is requested without the extra, the report marks
authenticity as unsupported and exits with code `2`.

Optional expected values bind the verification request to its intended
context:

```bash
python -m agent_runtime_governance.verify bundle.json \
  --expected-bundle-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --expected-tenant-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --expected-policy-version policy-v1 \
  --expected-policy-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --expected-contract-id ops.export \
  --expected-contract-version 2 \
  --expected-contract-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`--at` is a caller-supplied trust-root evaluation time for reproducible offline
checks. It is not a trusted timestamp and cannot prove when a signature was
created.

## Optional external evidence

External continuity and outcome evidence stays detached from the v1 bundle. A
deployment may explicitly select exactly one installed entry point and provide
its matching detached input:

```bash
python -m agent_runtime_governance.verify bundle.json \
  --anchor-provider protected-anchor-v1 \
  --anchor-sequence anchor-sequence.json

python -m agent_runtime_governance.verify bundle.json \
  --receipt-verifier payment-receipt-v1 \
  --receipt receipt.json
```

The verifier only looks up the named entry point in
`agent_runtime_governance.evidence_anchor_providers` or
`agent_runtime_governance.evidence_receipt_verifiers`; it does not discover and
run every installed provider. A provider receives a bounded detached request:
the anchor request contains a sequence ID, tenant digest, and ordered bundle
IDs/digests, and the receipt request contains the minimal
bundle/action/contract/tenant/execution identity plus a receipt sidecar bound
to that bundle digest. Provider payloads and raw receipts are never written
into the bundle or generic report.

The core verifier supplies no transport, credentials, retry policy, or hosted
anchor. A selected deployment provider can use its own protected service, but
the provider's result only establishes the specific continuity or outcome
claim it supports. It does not make an external side effect exactly-once.
Production receipt verifiers must cryptographically bind the receipt to the
complete request identity, not merely an execution ID or sidecar digest. The
reference in-memory verifier does this with a canonical request-identity digest
and never retains raw receipt bytes.

The entry-point protocol is synchronous. The offline verifier does not create
or borrow an event loop; an asynchronous provider result is rejected and any
returned coroutine is closed without being awaited. This keeps the CLI's
deadline and JSON-only boundary deterministic. An async service should expose
a bounded synchronous verification adapter at this boundary.

## Report and exit codes

Each verification run writes one JSON report to stdout. Its levels are
independent:

- `integrity` validates strict JSON input, schema, canonical v1 reconstruction,
  digest commitments, requested bindings, and reconciliation continuity. An
  unsigned bundle with no expected digest is `unanchored`: it is structurally
  valid, but there is no external commitment with which to detect prior
  mutation.
- `authenticity` validates a detached signature and configured trust root only
  when a signature or trust-roots file is supplied.
- `outcome_verified` is `passed` only when the selected receipt verifier
  validates its bundle-bound sidecar and returns an outcome matching the
  recorded execution status, or when it resolves a recorded `unknown` status.
  A verified outcome does not rewrite the immutable bundle. Execution status,
  integrity, or a valid signature alone never prove an external real-world
  outcome.

`integrity.audit_continuity` is `passed` only when the selected protected-anchor
provider matches the detached sequence. It fails for detected deletion,
reordering, or mismatched subject identity. Without a protected external
anchor it remains `unsupported`, so a standalone bundle never claims deletion
detection.

| Exit code | Meaning |
| --- | --- |
| `0` | Every requested, supported verification level passed. |
| `1` | Input, integrity, binding, signature, requested anchor, or requested receipt verification failed. |
| `2` | A requested level is unsupported, including an unavailable external provider, `--require-outcome`, or detached verification without the `evidence` extra. |

Malformed input is represented by a JSON failure report rather than a Python
traceback. The parser rejects duplicate JSON keys and non-finite JSON values.
The CLI captures ordinary selected-provider stdout/stderr while loading and
calling it, so conforming synchronous providers leave exactly one JSON report
on stdout. Providers run in-process: they must not write directly to OS file
descriptors or start background writers. Deploy an untrusted provider behind a
separate process boundary.

Bundle versions and fields are closed by the v1 compatibility policy in
[`evidence-schema-compatibility.md`](evidence-schema-compatibility.md). Unknown
versions or fields are verification failures, not a fallback to v1.
