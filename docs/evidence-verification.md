# Offline evidence verification (unreleased v0.8)

`python -m agent_runtime_governance.verify` validates a portable Governance
Evidence Bundle without network access. It is an unreleased v0.8 capability;
it does not attest an external side effect, supply an anchor service, or load a
receipt verifier.

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
- `outcome_verified` is currently `unsupported`; execution status and a valid
  signature never prove an external real-world outcome.

`integrity.audit_continuity` is also `unsupported` until an external protected
anchor is provided. The verifier therefore cannot detect deletion from an
unanchored, standalone bundle.

| Exit code | Meaning |
| --- | --- |
| `0` | Every requested, supported verification level passed. |
| `1` | Input, integrity, binding, or signature verification failed. |
| `2` | A requested level is unsupported, including `--require-outcome` or detached verification without the `evidence` extra. |

Malformed input is represented by a JSON failure report rather than a Python
traceback. The parser rejects duplicate JSON keys and non-finite JSON values.
