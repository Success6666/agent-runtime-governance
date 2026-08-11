# Adoption verification

Use this guide to distinguish a source inspection from an installed-package,
framework, or production-boundary verification. Each level is intentionally
small and points to the existing shipped test instead of creating a second
example or adapter.

## 1. Verify the public package

Run from a neutral directory outside a repository checkout. Pin the version;
do not use an editable install or a local wheel cache.

POSIX:

```bash
verify_root="$(mktemp -d)"
python -m venv "$verify_root/venv"
"$verify_root/venv/bin/python" -m pip install --upgrade pip
"$verify_root/venv/bin/python" -m pip install \
  --isolated --no-cache-dir --index-url https://pypi.org/simple \
  agent-runtime-governance==0.9.1
"$verify_root/venv/bin/python" -m pip check
cd "$verify_root"
"$verify_root/venv/bin/python" -c \
  'from importlib.metadata import version; import agent_runtime_governance as arg; assert version("agent-runtime-governance") == arg.__version__ == "0.9.1"; print(arg.__version__)'
```

PowerShell:

```powershell
$verifyRoot = Join-Path $env:TEMP "arg-public-verify"
python -m venv (Join-Path $verifyRoot "venv")
$python = Join-Path $verifyRoot "venv\Scripts\python.exe"
& $python -m pip install --upgrade pip
& $python -m pip install --isolated --no-cache-dir `
  --index-url https://pypi.org/simple agent-runtime-governance==0.9.1
& $python -m pip check
Set-Location $verifyRoot
& $python -c 'from importlib.metadata import version; import agent_runtime_governance as arg; assert version("agent-runtime-governance") == arg.__version__ == "0.9.1"; print(arg.__version__)'
```

Replace `0.9.1` with an exact later release when one exists. A successful
import proves that the public distribution installs and reports the expected
version. It does not prove framework behavior or production readiness.

## 2. Verify the strict single-host boundary

[`examples/strict_action_contract.py`](../examples/strict_action_contract.py)
is the compact strict-production path. It binds an immutable policy artifact,
verified identity, action contract, colocated SQLite idempotency and
reconciliation state, and signed durable audit before calling
`seal_production()`.

Follow the commands in [Production reliability](../README.md#production-reliability).
The regression test
[`test_strict_action_contract_example_runs_with_real_policy_artifact`](../tests/test_strict_action_example.py)
runs the example twice and verifies durable result reuse, the state change, and
the bound policy identity in the audit chain.

This verifies the supported single-host SQLite boundary only. Multi-host
authoritative state is tracked separately and is not implied by this example.

## 3. Verify real framework entry points

The protected conformance suite compares standalone Runtime behavior with real
framework-native entry points for success, policy denial, approval denial, and
caller-metadata forgery resistance. CI installs the exact framework versions
shown in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

From a checkout of the release tag:

```bash
python -m pip install -e ".[dev,langgraph]" "langgraph==1.2.9"
pytest -q -rs tests/conformance/test_standalone.py tests/conformance/test_langgraph.py

python -m pip install -e ".[dev,openai-agents]" "openai-agents==0.19.0"
pytest -q -rs tests/conformance/test_standalone.py tests/conformance/test_openai_agents.py
```

These checks execute a compiled LangGraph node and an OpenAI Agents SDK
`Runner` tool call. They do not call a hosted model or claim compatibility with
unlisted framework versions.

## 4. Verify release identity

Every release from v0.8 onward carries a Release Verification Manifest, wheel,
source distribution, SPDX SBOM, and `SHA256SUMS`. The release workflow binds
those files to the tag and protected `main` commit, then records GitHub build
provenance. PyPI Trusted Publishing downloads and re-verifies that immutable
release set before upload.

After publication, the `Verify public PyPI` job:

1. checks out the exact tag;
2. downloads its immutable manifest and checksums;
3. waits for the exact public PyPI version;
4. compares public wheel and source-distribution hashes with the release
   record and downloads both files;
5. installs the exact version from `https://pypi.org/simple` in a clean
   environment with no cache or editable checkout;
6. runs `pip check` and confirms both distribution and runtime versions.

See [release verification records](release-verification.md) for point-in-time
workflow links. These records are release evidence, not an uptime, future
security, latency, compliance, or downstream exactly-once guarantee.

## Verification levels

| Result | What it establishes | What it does not establish |
| --- | --- | --- |
| Source inspected | The design and tests are present in one commit | The package installs or tests pass |
| Public package verified | Exact public version imports and dependency checks pass | Framework or production behavior |
| Framework conformance passed | Pinned native framework entries preserve protected semantics | Every framework version or hosted model |
| Strict example passed | The documented single-host production profile seals and runs | Multi-host state or downstream exactly-once |
| Docker integration passed | OPA, OTLP, Prometheus, and recovery smoke passed for that run | Adopter-owned services or future availability |

Applications still own business authorization, downstream idempotency or
receipts, rollback/compensation, secrets, and key lifecycle. The SDK fails
closed when its declared governance boundary cannot be established; it does
not replace those external controls.
