# Roadmap

The architecture is frozen per release. New ideas enter this file before code.

## v0.1 - Runtime proof

- Immutable execution context and fixed middleware pipeline
- Rule, LLM, human decision, and audit middleware
- Tool registry, JSONL audit, basic replay, LangGraph example

## v0.2 - Engineering governance

- [x] Runtime hooks and immutable pipeline composition
- [x] Middleware metadata and Python policy configuration
- [x] Metrics, retry, timeout, and OpenTelemetry export
- [x] OpenAI Agents SDK example

## v0.3 - Replay and policy evolution

- [x] Versioned YAML policies
- [x] Context snapshots, replay diff, and a text debugger
- [x] Regression evaluation, policy drift detection, trace visualization

## v0.4 - Integration ecosystem

- [x] Explicit plugin API and entry-point discovery
- [x] Prometheus, Slack, and OPA integrations
- [x] CrewAI, Agno, LlamaIndex, and AutoGen examples

## v0.5 - Production reliability

- [x] Idempotent execution with durable lease state
- [x] Persistent approval stores and trusted identity providers
- [x] Deadline propagation, cancellation handling, and concurrency limits
- [x] Parameter/result contracts and payload size limits
- [x] Reliable JSONL/SQLite audit and snapshot stores
- [x] Docker-backed OPA, OpenTelemetry, Prometheus, and Kind smoke checks
- [x] Fault, property, concurrency, benchmark, and release verification assets

## Future ideas

Distributed runtime, cost governance, checkpointing, and hosted decision UI.
