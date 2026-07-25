# Changelog

All notable changes are documented here.

## [0.4.0] - 2026-07-25

### Added

- Build-time plugin registration and trusted Python entry-point discovery.
- Prometheus terminal metrics with bounded, non-identity labels.
- Slack denial/failure notifications with strict webhook validation.
- OPA policy decisions with minimal payloads and fail-closed defaults.
- CrewAI, Agno, LlamaIndex, and Microsoft AutoGen integration examples.

### Changed

- Synchronous LLM reviewers, human decision callbacks, hooks, audit sinks,
  snapshot stores, and network integrations run outside the event-loop thread.

## [0.3.0] - 2026-07-25

### Added

- Strict, versioned YAML policy documents with stable SHA-256 digests.
- Context snapshot stores, structured replay diffs, and a text debugger.
- Regression evaluation and policy drift detection over recorded requests.
- Mermaid trace rendering for lightweight visualization.

### Fixed

- Tool calls that require approval now fail closed when no explicit human
  decision was granted.
- Deterministic replay skips LLM, human decision, audit, metrics, and other
  non-replayable middleware.

## [0.2.0] - 2026-07-25

### Added

- Immutable pipeline composition and middleware metadata.
- Runtime hooks around pipeline, semantic review, decisions, tools, and audit.
- Python-native policies for permissions, approval, denial, and risk overrides.
- In-memory metrics plus retry and timeout execution middleware.
- Optional OpenTelemetry lifecycle export and OpenAI Agents SDK example.

## [0.1.0] - 2026-07-25

### Added

- Immutable execution context with OpenTelemetry-style trace identifiers.
- Deterministic gating and observing middleware contracts.
- Rule, semantic review, human decision, and audit middleware.
- Governed tool registry with synchronous and asynchronous execution.
- Redacted JSONL audit records with optional HMAC verification.
- Basic trace replay, LangGraph integration example, tests, and CI.
