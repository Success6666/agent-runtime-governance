# Release verification records

Point-in-time verification results for published releases. These are not a
latency SLA or a guarantee against future advisories. CI repeats the test
matrix, policy checks, dependency audit, and Docker integration smoke from
clean runners.

## v0.7.0 (pending publication)

There is intentionally no verification result or release claim for v0.7.0 in
this file yet. The implementation must not be described as published or
verified until the protected CI/integration workflows, the post-publication
release-artifact workflow, the PyPI publication workflow, and the recorded
operator checks together provide evidence for all of the following:

- the full test suite and coverage gate on the supported Python matrix in
  `ci.yml`, plus Docker-backed integration smoke in `integration.yml`;
- deterministic-reconciliation fault and restart coverage, including atomic
  prepared-claim rollback, provider identity drift, cancellation/finalization,
  expired unfinished attempts, manual-resolution authorization, migration
  snapshots, and idempotent audit redelivery after acknowledgement failure;
- Docker-backed external integration smoke for OPA, OTLP, and Prometheus, plus
  the release's documented local durable-storage checks;
- migration validation from the supported prior SQLite schema, including a
  backup/restore drill and delivery of pending outbox envelopes;
- post-publication release-artifact verification on Python 3.13: isolated
  dependency audit, wheel/source-distribution build and `twine check`, clean
  wheel/source installation/import, SBOM, checksums, and provenance; and
- release assets, SHA256 checksums, SPDX SBOM, and GitHub provenance, followed
  by PyPI Trusted Publishing and an independent public-index installation
  check.

The eventual v0.7.0 entry must name the protected `main` commit, dates, exact
test and coverage results, immutable GitHub workflow/release links, PyPI
version, the result of the recorded migration restore/public-index installation
checks, and any measured benchmark evidence. It must distinguish the SDK's
durable local protocol from a claim of downstream exactly-once execution.

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
