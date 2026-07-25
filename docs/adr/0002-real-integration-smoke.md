# ADR 0002: Real integration smoke tests

## Status

Accepted for v0.5.0.

## Context

Mocked OPA, OpenTelemetry, and metrics tests are useful for unit behavior but do
not prove that production integration points work over real process and network
boundaries.

## Decision

- `integration/production_smoke.py` starts pinned Docker images for OPA and the
  OpenTelemetry Collector.
- The smoke test exercises the SDK against real OPA HTTP decisions, real OTLP
  HTTP export, and a real Prometheus `/metrics` endpoint.
- Kubernetes is validated as an example smoke with `kind` and a pinned node
  image. The SDK does not claim to be a Kubernetes controller or control plane.
- CI runs the Docker smoke without Kind. Local release verification can run the
  full script when Docker, Kind, and kubectl are available.

## Consequences

- Integration regressions are caught before release instead of being inferred
  from in-process mocks.
- CI remains portable while still validating external network behavior.
- Kind failures are reported as environment or example-smoke failures, not as a
  core SDK runtime failure.
