# Release verification records

Point-in-time verification results for published releases. These are not a
latency SLA or a guarantee against future advisories. CI repeats the test
matrix, policy checks, dependency audit, and Docker integration smoke from
clean runners.

## Release Verification Manifest

From v0.8 onward, each release asset set includes a closed, versioned Release
Verification Manifest. The protected release job derives it from that job's
JUnit, coverage, Docker integration, dependency-audit, build, SBOM, checksum,
and pinned service-image evidence. The job validates the manifest before it
attests and uploads release assets; PyPI Trusted Publishing rechecks the
manifest's checksum and GitHub provenance before package distributions are
published.

The manifest is point-in-time CI evidence only. It is not an uptime, security,
latency, or compliance guarantee, and it does not make claims about systems or
advisories that arise after the recorded release job finishes.

The workflow runs after GitHub records a published release, so a missing or
invalid manifest blocks release assets and PyPI publication. It does not claim
to retract an already-created GitHub Release object.

## v0.8.0 (withdrawn before distribution)

The v0.8.0 GitHub Release was created on 2026-07-29 (UTC) from protected
`main` commit `f9bb37f15036080dd6f3301fd49f9e7ac837f98d`. Its
[release-artifact workflow](https://github.com/Success6666/agent-runtime-governance/actions/runs/30449591555)
passed its preceding release-verification test, isolated dependency-audit,
package-build, isolated-install, and SBOM steps, but the manifest rejected a
skipped local root-package audit entry. No package asset, checksum, SBOM,
manifest, or provenance was attached, and no PyPI distribution was published.

The GitHub Release is retained as a withdrawn prerelease rather than being
rewritten. The corrective verification path and v0.8.1 replacement release are
tracked in [#89](https://github.com/Success6666/agent-runtime-governance/issues/89).

## v0.7.0

v0.7.0 was released on 2026-07-27 (UTC) from protected `main` commit
`3998c975f88737c9e009b9d85c073122431ddb94`.

- The protected [CI workflow](https://github.com/Success6666/agent-runtime-governance/actions/runs/30298602257)
  passed its Python 3.10, 3.11, 3.12, and 3.13 matrix with 822 tests per
  interpreter and 89.34%--89.37% coverage (80% enforced minimum), plus Ruff,
  package build, repository-policy, and paired benchmark-budget checks.
- The [security workflow](https://github.com/Success6666/agent-runtime-governance/actions/runs/30298602202)
  passed the isolated production-dependency audit and CodeQL.
- The [integration workflow](https://github.com/Success6666/agent-runtime-governance/actions/runs/30298602735)
  passed Docker-backed OPA strict-policy and `UNKNOWN` reconciliation, OTLP
  Collector export, and Prometheus endpoint smoke on Python 3.13. Its Kind
  sub-check was intentionally skipped by `--skip-kind` and is not claimed as
  release evidence.
- The [release-artifact workflow](https://github.com/Success6666/agent-runtime-governance/actions/runs/30298956687)
  verified the protected source, tag/package version, isolated production
  dependencies, wheel and source-distribution builds and isolated installs,
  SPDX SBOM, SHA256 checksums, and GitHub artifact attestation before uploading
  the release assets.
- The [PyPI Trusted Publishing workflow](https://github.com/Success6666/agent-runtime-governance/actions/runs/30299616690)
  re-verified the release files, checksums, and provenance before publishing
  [`agent-runtime-governance==0.7.0`](https://pypi.org/project/agent-runtime-governance/0.7.0/).
  The public wheel and source distribution match the GitHub release checksums.

The immutable release assets and provenance entry point are available from the
[`v0.7.0` release](https://github.com/Success6666/agent-runtime-governance/releases/tag/v0.7.0).
The release proves the SDK's durable local reconciliation protocol; it does not
claim downstream external exactly-once execution without a downstream
idempotency or receipt/probe guarantee.

## v0.6.0

The release was validated on 2026-07-26 (UTC) from protected `main` commit
`69abb57b9cd0ceded0ddd922a196452c4eba9fe7`:

- 600 tests passed in the release workflow with 90.41% coverage; the enforced
  floor is 80%, and the same suite passed on Python 3.10, 3.11, 3.12, and 3.13
  in [PR #36](https://github.com/Success6666/agent-runtime-governance/pull/36);
- real OPA HTTP allow/deny, OTLP HTTP export to an OpenTelemetry Collector,
  and Prometheus HTTP scraping passed in Docker;
- an isolated environment with the OTel, YAML, and Prometheus extras had no
  known dependency vulnerabilities reported by `pip-audit` 2.10.1;
- wheel and source distributions passed `twine check`, then installed and
  imported from separate clean environments;
- the final 1,000-request, concurrency-100 paired measurement passed the
  committed budget at 1.553x mean, 1.720x p95, 1.850x p99, and 1.040x peak
  traced memory relative to its strict baseline; and
- the release workflow attached the wheel, source distribution, SPDX SBOM,
  SHA256 checksums, and a Sigstore-backed GitHub provenance attestation for all
  four subjects.

The immutable evidence is available from the
[`v0.6.0` release](https://github.com/Success6666/agent-runtime-governance/releases/tag/v0.6.0),
[release verification run](https://github.com/Success6666/agent-runtime-governance/actions/runs/30219834715),
and [provenance attestation](https://github.com/Success6666/agent-runtime-governance/attestations/37195459).
The [Trusted Publishing run](https://github.com/Success6666/agent-runtime-governance/actions/runs/30219912753)
verified those checksums and attestations before publishing
[`agent-runtime-governance==0.6.0`](https://pypi.org/project/agent-runtime-governance/0.6.0/).
An independent installation from the public PyPI index passed `pip check` and
imported version `0.6.0`; the PyPI wheel and source-distribution SHA256 digests
matched the GitHub release assets.

## v0.5.1

The release was validated on 2026-07-26 (UTC) on Windows and GitHub-hosted Linux
runners:

- 396 tests passed in the release workflow with 88.89% branch coverage; the
  enforced floor is 80%;
- the same 396-test suite passed on Python 3.10, 3.11, 3.12, and 3.13 in the
  pull-request matrix;
- 15 repository-policy tests passed;
- real OPA HTTP allow/deny, OTLP HTTP export to an OpenTelemetry Collector,
  and Prometheus HTTP scraping passed in Docker;
- the wheel and source distribution installed and imported from separate clean
  virtual environments;
- an isolated environment with the OTel, YAML, and Prometheus extras had no
  known dependency vulnerabilities reported by `pip-audit` 2.10.1 at release
  time; and
- the wheel, source distribution, SPDX SBOM, SHA256 checksums, and GitHub
  provenance were verified before PyPI Trusted Publishing.

The immutable release, assets, and verification entry point are available at
[`v0.5.1`](https://github.com/Success6666/agent-runtime-governance/releases/tag/v0.5.1).
