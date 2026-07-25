# Roadmap

The architecture is frozen per release. New ideas enter this file before code.

## v0.1 - Runtime proof

- Immutable execution context and fixed middleware pipeline
- Rule, LLM, human decision, and audit middleware
- Tool registry, JSONL audit, basic replay, LangGraph example

## v0.2 - Engineering governance

- Runtime hooks and immutable pipeline composition
- Middleware metadata and Python policy configuration
- Metrics, retry, timeout, and OpenTelemetry export
- OpenAI Agents SDK example

## v0.3 - Replay and policy evolution

- Versioned YAML policies
- Context snapshots, replay diff, and a text debugger
- Regression evaluation, policy drift detection, trace visualization

## v0.4 - Integration ecosystem

- Explicit plugin API and entry-point discovery
- Prometheus, Slack, and OPA integrations
- CrewAI, Agno, LlamaIndex, and AutoGen examples

## Future ideas

Distributed runtime, cost governance, checkpointing, and hosted decision UI.

