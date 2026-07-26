# Release verification records

Point-in-time verification results for published releases. These are not a
latency SLA or a guarantee against future advisories. CI repeats the test
matrix, policy checks, dependency audit, and Docker integration smoke from
clean runners.

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
