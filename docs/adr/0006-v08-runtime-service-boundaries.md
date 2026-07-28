# ADR 0006: v0.8 runtime service boundaries

## Status

Accepted for the v0.8 internal extraction.

## Context

`Runtime` is the public lifecycle owner, but it has accumulated pipeline
selection, extension dispatch, durable-operation coordination, and adapter
orchestration.  Those concerns need independently testable seams without
changing public imports, `ExecutionContext` immutability, audit bytes, or
durable SQLite compatibility.

## Decision

The v0.8 dependency direction is:

```text
public Runtime facade
        |
        +-- internal lifecycle / durable-operation services
        +-- internal PipelineRunner + MiddlewareRegistry
        +-- internal ExtensionDispatcher
        |
        +-- protocol-facing middleware and adapters
                 |
                 +-- optional concrete storage adapters at construction only
```

`Pipeline` remains the stable immutable public composition value.  Its supplied
order remains authoritative for compatibility.  The internal
`MiddlewareRegistry` validates metadata and exposes a deterministic
priority-sorted view for services that explicitly need one; it does not
silently reorder an existing `Pipeline`.

`PipelineRunner` owns only deterministic middleware selection and sequential
composition.  Runtime-owned callbacks continue to own deadlines, hooks,
transition validation, cancellation, and fail-closed behavior.  This keeps a
service extraction from moving governance authority outside `Runtime`.

Further v0.8 extraction follows the same rule:

- audit redaction, integrity, codecs, and delivery move behind compatibility
  exports without changing serialized records or hash-chain bytes;
- canonical JSON has one named contract at evidence, replay, audit, and durable
  boundaries, with golden fixtures before any format migration;
- debugger/replay consumers receive immutable redacted events and never call
  back into a live Runtime;
- internal services depend on protocols rather than concrete SQLite classes.

## Consequences

- Public `Runtime`, `Pipeline`, middleware, audit, approval, and storage import
  paths remain stable.
- A module move needs an import/signature compatibility test and behavior-parity
  fixture before it is accepted.
- Pipeline registration can reject malformed metadata early while preserving
  existing explicit ordering.
- Runtime remains responsible for sealing, public lifecycle methods, deadlines,
  cancellation, and the admission of potentially blocking work.

## Non-goals

This decision does not add pipeline mutation, dynamic plugin loading, hot
reload, a workflow/DAG engine, a remote runtime, a dashboard, or a storage
implementation beyond existing supported adapters.
