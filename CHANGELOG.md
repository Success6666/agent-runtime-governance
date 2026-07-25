# Changelog

All notable changes are documented here.

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
