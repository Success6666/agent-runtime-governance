# Release verification records

Point-in-time verification results for published releases. These are not a
latency SLA or a guarantee against future advisories. CI repeats the test
matrix, policy checks, dependency audit, and Docker integration smoke from
clean runners.

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
