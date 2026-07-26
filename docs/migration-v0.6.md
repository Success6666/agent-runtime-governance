# Migrating from v0.5 to v0.6

v0.6 gives every contracted invocation one immutable `BoundAction`. Its
`action_digest` is shared by approval, idempotency, executor revalidation,
OpenTelemetry, and audit. This changes the identity of side-effecting calls;
plan the rollout as a data migration, not only a package upgrade.

## 1. Inventory before enforcing

Build the intended profile without attaching it to the live runtime and inspect
every registered tool:

```python
report = runtime.production_readiness(production_profile)
for tool in report.tools:
    print(tool.tool_name, tool.state.value, [reason.value for reason in tool.reasons])
```

`MUTATING` and `IDEMPOTENT` tools require an `ActionContract`. `READ_ONLY`
tools have an explicit exception, although they may opt into a contract. Do not
attach `production_profile` until the inventory and required durable adapters
are ready; attaching it immediately closes admission until
`seal_production()` succeeds.

## 2. Define contracts at the tool boundary

The contract tool name and execution mode must equal the `ToolSpec`. If the
tool also declares parameter or result schemas and byte limits, the overlapping
contract values must agree. A contract may additionally declare external
preconditions and a receipt schema.

```python
contract = ActionContract(
    contract_id="ops.restart-service",
    contract_version=1,
    tool_name="restart_service",
    execution_mode=ExecutionMode.IDEMPOTENT,
    parameters_schema={
        "type": "object",
        "properties": {"service": {"type": "string"}},
        "required": ["service"],
        "additionalProperties": False,
    },
    effect_class="service.restart",
)

@runtime.tool(
    name="restart_service",
    execution_mode=ExecutionMode.IDEMPOTENT,
    action_contract=contract,
)
def restart_service(service: str) -> dict[str, object]:
    ...
```

The normalized, isolated parameter snapshot inside `BoundAction` is the source
used to materialize the tool call. Middleware and hooks cannot replace it, and
the runtime recomputes the action identity before any tool code is entered.
Nested objects and arrays are exposed to the tool as read-only mappings and
tuples. Update contracted tool annotations to accept `Mapping` and `Sequence`,
or create an explicit local working copy after entry. Defaults applied by the
Python signature are part of the snapshot and must be allowed by the schema.

## 3. Configure trusted binding inputs

`ProductionProfile` requires:

- a tenant-scoped `identity_digest_key_provider` and public key version;
- an explicit policy version and SHA-256 digest;
- a `precondition_digest_provider` for contracts that declare preconditions;
- trusted verified identity, durable idempotency, and integrity-protected,
  fail-closed audit; and
- durable integrity-protected approval storage when any tool requires approval.

Key providers return secret material but the runtime never places that key,
raw principal, or raw tenant in `BoundAction`, readiness, audit evidence, or
errors. A policy-bearing middleware such as `PolicyMiddleware` or
`OPAMiddleware` must advertise the same policy version and digest as the
profile. Missing or mismatched identity fails startup readiness.

`policy_digest` is the lowercase SHA-256 of the exact immutable policy artifact
admitted for the deployment. Hash the artifact bytes, not a revision label or
descriptive string. For an OPA bundle, this is the exact signed bundle archive;
for an OCI-delivered bundle, use the 64-hex payload of the admitted
`sha256:<digest>` manifest. The component that loads the artifact and the
`ProductionProfile`/policy middleware configuration must all derive identity
from that same digest. Deployment admission must verify the signature or OCI
provenance and confirm that the OPA instance loaded that digest. The SDK checks
configured identities; it cannot attest arbitrary remote OPA bytes by itself.

`YAMLPolicyLoader` exposes two intentionally different values. `digest` is the
normalized semantic digest retained for v0.5 compatibility and drift
comparison; `artifact_digest` hashes the exact loaded UTF-8 bytes. Strict v0.6
profiles must use `artifact_digest` and `document.artifact_middleware()`.

Register all tools, call `seal_production()`, and expose readiness only after
the returned report has `ready=True`.

## 4. Reissue approvals

v0.5 approval records remain deserializable, but they do not contain
`action_digest`. A contracted v0.6 request never consumes one. It fails closed
with:

```text
approval.action_digest_missing: re-approval required
```

Keep the legacy record for audit and issue a new approval from the v0.6 request.
Changing parameters, contract, policy identity, verified subject, tenant,
issuer, identity key version, precondition digest, risk, or expiry invalidates
the approval.

Non-contracted compatibility tools retain the v0.5 argument-digest path.

### What the action digest covers

This table is the authoritative boundary for `BoundAction.action_digest`:

| Category | Included in `action_digest` | Normalization |
| --- | --- | --- |
| Contract | `contract_digest`, which indirectly covers contract ID/version, tool name, execution mode, parameter schema, effect class, precondition requirements, receipt schema, and parameter byte limit | RFC 8785 canonical JSON, then SHA-256 |
| Parameters | Exact post-signature-binding parameter snapshot, including applied Python defaults | Strict JSON normalization, versioned envelope, then SHA-256 |
| Principal | Verified identity issuer and subject | Tenant-scoped HMAC-SHA-256; only the digest is retained |
| Tenant | Verified tenant | Tenant-scoped HMAC-SHA-256; only the digest is retained |
| Identity key | Public identity-digest key version | Included as text; secret key material is never retained |
| Policy | Policy version and immutable artifact SHA-256 | Included as version plus digest |
| External preconditions | Provider's current SHA-256 when the contract declares requirements | Included as a digest |

Approval also binds request ID, tool name, risk tier, request/decision expiry,
policy identity, verified subject, tenant, issuer, and the action digest. These
approval envelope fields are checked separately; request ID, trace/span IDs,
reviewer identity, deadline, and application idempotency key are not part of
`action_digest`. Execution result/receipt, audit sequence, timestamps, and
external world state after the precondition read are also outside the digest.

## 5. Preserve both idempotency namespaces

v0.5 uses:

```text
<raw tenant or global>:<tool name>
```

Contracted v0.6 tools use:

```text
action/v1:<stable tenant partition digest>:<stable contract partition digest>
```

The tenant partition is a domain-separated SHA-256 of the verified tenant ID.
It is stable across identity-digest key rotation and is not an authentication
or confidentiality boundary. The contract partition is a domain-separated
SHA-256 of `contract_id`; its fixed length supports every valid contract ID and
stays stable across contract-version changes. The v0.6 fingerprint is
`action_digest`. A legacy record can never satisfy a v0.6 claim, even when the
application idempotency key is the same. Retain old records for their full
operational retention period, especially `UNKNOWN` records. Do not copy old
results into the new namespace or delete uncertain entries to make a retry
pass.

Policy or identity-key rotation changes `action_digest` but not the tenant
partition, so reusing the old application key intentionally reports a conflict
instead of executing again. Use a new application idempotency key after the new
action has been reviewed. Changing the canonical verified tenant ID is a
separate storage migration and requires a bridge for every retained key.

## 6. Update persistence and audit consumers

`ExecutionContext.from_dict()` and `ApprovalRequest.from_dict()` accept v0.5
documents without the new field. Parsing only checks shape and embedded digest
self-consistency; it does not authenticate a snapshot or establish trusted
identity. `Runtime.areplay()` is non-authoritative analysis: it strips recorded
identity-verification metadata, never executes a tool, and never creates a new
`BoundAction`. Historical user, tenant, and permission fields are policy-test
inputs only. To obtain a current governed action preview, first verify the
snapshot chain/signature from a protected anchor, then call `Runtime.apreview()`
with current trusted identity claims and the recorded tool arguments. That path
re-verifies identity and binds current key, policy, and precondition state.
Caller-provided or unsigned `verified-identity` metadata is never authorization
evidence.

Audit context events use schema version 3 and add `contract_id`,
`contract_version`, and `action_digest`. The nested audit representation uses
`BoundAction.to_evidence_dict()` and does not duplicate raw parameters. Full
context and snapshot persistence keeps the isolated parameter snapshot for
controlled replay.

Audit evidence and replay snapshots have different confidentiality classes.
Audit evidence omits raw action parameters; replay snapshots contain the full
isolated parameter snapshot and may contain secrets. HMAC and hash chains
provide integrity, not confidentiality. Encrypt snapshot storage and backups,
restrict service/operator access, isolate encryption and HMAC keys, define a
bounded retention/deletion schedule, and verify deletion from replicas and
backups. Do not enable full snapshots for sensitive parameters until these
controls have been exercised in restore tests.

Consumers must ignore unknown fields and branch on `schema_version`. Verify
backup and restore of context, approval, idempotency, audit, and chain-state
files before rollout.

## 7. Roll out and roll back safely

1. Acquire a deployment-generation lock, stop new side-effecting traffic, and
   drain every v0.5 worker. v0.5 and v0.6 workers must never write the same
   approval, idempotency, snapshot, or audit stores concurrently.
2. Back up durable stores and audit chain state.
3. Deploy v0.6, run readiness, then execute a canary with a new idempotency key.
4. Verify the same `action_digest` in approval, idempotency inspection,
   OpenTelemetry, terminal context, and audit.
5. Resume traffic gradually and alert on action-binding denials separately.

Direct binary rollback of a side-effecting workload is unsafe. v0.5 neither
understands the v0.6 idempotency namespace nor requires `action_digest` on an
approval, so it can repeat a committed action or consume a stale legacy allow.
Before restoring any v0.5 write traffic:

1. Quiesce v0.6, drain all workers, and retain the deployment-generation lock.
2. Quarantine or revoke every legacy pending/allow approval from the active
   lookup store while preserving an immutable audit copy.
3. Reconcile every v0.6 `COMPLETED`, `UNKNOWN`, leased/in-flight, and failed
   application key. Install an application-level deny/result bridge for every
   key that may have reached the external system; covering only `UNKNOWN` is
   insufficient.
4. Seal the final schema-v3 audit anchor. Start v0.5 on a new chain segment or
   a separately restored v0.5 store; never let an unverified old writer append
   to the v0.6 chain state. Preserve the v0.6 chain, signatures, and anchor.
5. Restore a production-like backup and run the rollback scenario, including a
   committed call, an uncertain call, a pending approval, and audit verify,
   before reopening traffic.

If the application cannot implement the approval quarantine and idempotency
bridge, forward-fix v0.6 instead of rolling back side-effecting traffic.

The compatibility behavior is covered by
[`tests/test_v05_compatibility.py`](../tests/test_v05_compatibility.py), and the
executor, approval, idempotency, audit, timeout, cancellation, and mutation
boundaries are covered by
[`tests/test_bound_action_runtime.py`](../tests/test_bound_action_runtime.py).
