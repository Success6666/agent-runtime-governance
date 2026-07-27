from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import Request, urlopen

from prometheus_client import CollectorRegistry, start_http_server
from prometheus_client.parser import text_string_to_metric_families

from agent_runtime_governance import (
    ActionContract,
    AuditMiddleware,
    ExecutionMode,
    GovernanceDenied,
    IdempotencyAlreadyAppliedError,
    InvocationOptions,
    OPAClient,
    OPAMiddleware,
    OpenTelemetryMiddleware,
    ProductionProfile,
    PrometheusMiddleware,
    ProviderDescriptor,
    ReconciliationAttemptContext,
    ReconciliationDisposition,
    ReconciliationFinding,
    ReconciliationState,
    RiskTier,
    Runtime,
    SQLiteAuditSink,
    SQLiteIdempotencyStore,
    SQLiteReconciliationLedger,
    StaticIdentityProvider,
    ToolExecutionError,
    VerifiedPrincipal,
)

ROOT = Path(__file__).resolve().parents[1]
OPA_IMAGE = (
    "openpolicyagent/opa@"
    "sha256:57f7d06808fff6de3ea1d698e6430990973ca1370be0e54975f0083d615521da"
)
OTEL_IMAGE = (
    "otel/opentelemetry-collector-contrib@"
    "sha256:f2f01157055a9b2aab9df7118e1f1c9abf345e99b23bc7a2bc791db374a7d0f6"
)
KIND_NODE_IMAGE = (
    "kindest/node:v1.34.3@"
    "sha256:08497ee19eace7b4b5348db5c6a1591d7752b164530a36f855cb0f2bdcbadd48"
)
KIND_SMOKE_IMAGE = "agent-runtime-governance-k8s-smoke:local"
_KIND_IMAGE_PLACEHOLDER = "__ARG_KIND_SMOKE_IMAGE__"


class SmokeIdentityDigestKeyProvider:
    """Deterministic non-secret key provider for this smoke harness only."""

    def get_key(self, *, tenant: str, version: str) -> bytes:
        return hashlib.sha256(
            f"production-smoke:{version}:{tenant}".encode("utf-8")
        ).digest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run production integration smoke checks.")
    parser.add_argument("--skip-kind", action="store_true", help="Skip the local kind smoke check.")
    parser.add_argument("--keep-containers", action="store_true", help="Leave Docker containers running for debugging.")
    args = parser.parse_args()

    require("docker")
    run_opa_smoke(args.keep_containers)
    run_otel_smoke(args.keep_containers)
    run_prometheus_smoke()
    if not args.skip_kind:
        run_kind_smoke()
    print("production smoke passed")


def run_opa_smoke(keep_containers: bool) -> None:
    name = "arg-v07-opa"
    cleanup_container(name)
    pull_image(OPA_IMAGE)
    policy_dir = ROOT / "integration" / "opa"
    command = [
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--publish",
        "127.0.0.1:8181:8181",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "256m",
        "--mount",
        f"type=bind,source={policy_dir},target=/policies,readonly",
        OPA_IMAGE,
        "run",
        "--server",
        "--addr",
        "0.0.0.0:8181",
        "/policies/policy.rego",
    ]
    try:
        run(command)
        wait_http("http://127.0.0.1:8181/health", expected_status=200)
        policy_digest = hashlib.sha256(
            (policy_dir / "policy.rego").read_bytes()
        ).hexdigest()
        with TemporaryDirectory(prefix="arg-v07-opa-") as temporary:
            state = Path(temporary)
            with contextlib.ExitStack() as stack:
                allowed, sink, allowed_dispatches = _strict_opa_runtime(
                    state / "allowed",
                    permissions=frozenset({"admin", "reconciliation:probe"}),
                    policy_digest=policy_digest,
                )
                stack.callback(allowed.close)
                denied, _, _ = _strict_opa_runtime(
                    state / "denied",
                    permissions=frozenset(),
                    policy_digest=policy_digest,
                )
                stack.callback(denied.close)
                result = allowed.invoke(
                    "delete_file",
                    _governance=InvocationOptions(
                        idempotency_key="opa-smoke-allow-1"
                    ),
                )
                assert result is True
                event = sink.read_verified()[-1]
                assert event["contract_id"] == "smoke.delete-file"
                assert event["action_digest"]
                try:
                    allowed.invoke(
                        "reconcile_unknown",
                        _governance=InvocationOptions(
                            idempotency_key="opa-smoke-unknown-1"
                        ),
                    )
                except ToolExecutionError as error:
                    execution_record_id = error.execution_record_id
                    if execution_record_id is None:
                        raise AssertionError(
                            "UNKNOWN smoke action did not expose an execution record"
                        ) from error
                else:
                    raise AssertionError("UNKNOWN smoke action unexpectedly completed")
                head = asyncio.run(allowed.areconcile(execution_record_id))
                assert head.state is ReconciliationState.CONFIRMED_SUCCEEDED
                assert head.disposition is ReconciliationDisposition.APPLIED_NO_RESULT
                try:
                    allowed.invoke(
                        "reconcile_unknown",
                        _governance=InvocationOptions(
                            idempotency_key="opa-smoke-unknown-1"
                        ),
                    )
                except ToolExecutionError as error:
                    if not isinstance(error.cause, IdempotencyAlreadyAppliedError):
                        raise
                else:
                    raise AssertionError(
                        "reconciled no-result action unexpectedly dispatched again"
                    )
                assert allowed_dispatches["reconcile_unknown"] == 1
                try:
                    denied.invoke(
                        "delete_file",
                        _governance=InvocationOptions(
                            idempotency_key="opa-smoke-deny-1"
                        ),
                    )
                except GovernanceDenied:
                    pass
                else:
                    raise AssertionError(
                        "OPA did not deny a non-admin contracted call"
                    )
    finally:
        if not keep_containers:
            cleanup_container(name)


def _strict_opa_runtime(
    state: Path,
    *,
    permissions: frozenset[str],
    policy_digest: str,
) -> tuple[Runtime, SQLiteAuditSink, dict[str, int]]:
    state.mkdir(parents=True, exist_ok=True)
    policy_version = "production-smoke-policy-v1"
    state_path = state / "runtime.db"
    sink = SQLiteAuditSink(state / "audit.db", sign_key=b"a" * 32)
    runtime = Runtime(
        [
            OPAMiddleware(
                OPAClient("http://127.0.0.1:8181", "agents/tools/allow"),
                fail_closed=True,
                policy_version=policy_version,
                policy_digest=policy_digest,
            ),
            AuditMiddleware(sink, fail_closed=True),
        ],
        idempotency_store=SQLiteIdempotencyStore(state_path),
        reconciliation_ledger=SQLiteReconciliationLedger(state_path),
        identity_provider=StaticIdentityProvider(
            VerifiedPrincipal(
                issuer="production-smoke",
                subject="smoke-runner",
                tenant="smoke-tenant",
                permissions=permissions,
                source="static",
            )
        ),
        require_verified_identity=True,
        production_profile=ProductionProfile(
            identity_digest_key_provider=SmokeIdentityDigestKeyProvider(),
            identity_digest_key_version="smoke-key-v1",
            policy_version=policy_version,
            policy_digest=policy_digest,
        ),
    )
    contract = ActionContract(
        contract_id="smoke.delete-file",
        contract_version=1,
        tool_name="delete_file",
        execution_mode=ExecutionMode.IDEMPOTENT,
        parameters_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        effect_class="filesystem.delete",
    )

    reconciliation_contract = ActionContract(
        contract_id="smoke.reconcile-unknown",
        contract_version=1,
        tool_name="reconcile_unknown",
        execution_mode=ExecutionMode.IDEMPOTENT,
        parameters_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        effect_class="smoke.unknown-reconciliation",
    )

    async def reconcile_unknown_provider(
        context: ReconciliationAttemptContext,
    ) -> ReconciliationFinding:
        return ReconciliationFinding(
            proposed_state=ReconciliationState.CONFIRMED_SUCCEEDED,
            evidence_kind="smoke-receipt",
            evidence={"reconciled": True},
            observed_at=context.deadline,
        )

    provider = ProviderDescriptor(
        provider_id="production-smoke-reconciliation",
        protocol_version="1",
        supported_evidence_kinds=("smoke-receipt",),
        provider=reconcile_unknown_provider,
    )

    @runtime.tool(
        name="delete_file",
        risk=RiskTier.HIGH,
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=contract,
        reconciliation_provider=provider,
    )
    def delete_file() -> bool:
        return True

    dispatches = {"reconcile_unknown": 0}

    @runtime.tool(
        name="reconcile_unknown",
        risk=RiskTier.HIGH,
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=reconciliation_contract,
        reconciliation_provider=provider,
    )
    def reconcile_unknown() -> None:
        dispatches["reconcile_unknown"] += 1
        raise TimeoutError("production smoke simulates an uncertain side effect")

    runtime.seal_production()
    return runtime, sink, dispatches


def run_otel_smoke(keep_containers: bool) -> None:
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        raise SystemExit("Install the otel extra before running this smoke check") from exc

    name = "arg-v07-otel"
    cleanup_container(name)
    pull_image(OTEL_IMAGE)
    config = ROOT / "integration" / "otel" / "collector-config.yaml"
    provider = None
    runtime = None
    command = [
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--publish",
        "127.0.0.1:4318:4318",
        "--publish",
        "127.0.0.1:13133:13133",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "256m",
        "--mount",
        f"type=bind,source={config},target=/etc/otelcol-contrib/config.yaml,readonly",
        OTEL_IMAGE,
    ]
    try:
        run(command)
        wait_http("http://127.0.0.1:13133/", expected_status=200)
        provider = TracerProvider()
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint="http://127.0.0.1:4318/v1/traces"),
                schedule_delay_millis=50,
                max_export_batch_size=16,
            )
        )
        tracer = provider.get_tracer("arg-production-smoke")
        runtime = Runtime([OpenTelemetryMiddleware(tracer)])

        @runtime.tool(name="runtime_otel_probe")
        def observed() -> str:
            return "ok"

        assert observed() == "ok"
        if not provider.force_flush(5000):
            raise AssertionError("OpenTelemetry exporter did not flush the runtime span")
        wait_docker_logs(name, "tool.runtime_otel_probe")
        wait_docker_logs(name, "arg.tool.name")
        wait_docker_logs(name, "runtime_otel_probe")
    finally:
        if runtime is not None:
            runtime.close()
        if provider is not None:
            provider.shutdown()
        if not keep_containers:
            cleanup_container(name)


def run_prometheus_smoke() -> None:
    registry = CollectorRegistry()
    runtime = Runtime([PrometheusMiddleware(registry=registry, prefix="arg_smoke")])

    @runtime.tool()
    def ping() -> str:
        return "pong"

    server = None
    thread = None
    try:
        assert ping() == "pong"
        server, thread = start_http_server(
            19091, addr="127.0.0.1", registry=registry
        )
        body = read_url("http://127.0.0.1:19091/metrics").decode("utf-8")
        required_labels = {
            "risk_tier": "LOW",
            "status": "succeeded",
            "tool": "ping",
        }
        found = any(
            sample.name == "arg_smoke_tool_calls_total"
            and all(
                sample.labels.get(key) == value
                for key, value in required_labels.items()
            )
            for family in text_string_to_metric_families(body)
            for sample in family.samples
        )
        if not found:
            raise AssertionError(
                "Prometheus metrics endpoint did not expose the governed call"
            )
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)
        runtime.close()


def run_kind_smoke() -> None:
    if shutil.which("kind") is None or shutil.which("kubectl") is None:
        raise SystemExit("kind and kubectl are required for the Kubernetes smoke check")
    cluster, image = kind_smoke_resources()
    cleanup_kind_cluster(cluster)
    try:
        pull_image(KIND_NODE_IMAGE)
        run([
            "kind",
            "create",
            "cluster",
            "--name",
            cluster,
            "--image",
            KIND_NODE_IMAGE,
            "--wait",
            "120s",
        ], timeout=420)
        build_kind_smoke_image(image=image)
        run(
            ["kind", "load", "docker-image", "--name", cluster, image],
            timeout=180,
        )
        with TemporaryDirectory(prefix="arg-v07-kind-manifest-") as temporary:
            manifest = render_kind_smoke_manifest(Path(temporary), image)
            run(["kubectl", "apply", "-f", str(manifest)], timeout=60)
            run(
                [
                    "kubectl",
                    "wait",
                    "--for=condition=complete",
                    "job/arg-runtime-smoke",
                    "-n",
                    "arg-smoke",
                    "--timeout=120s",
                ],
                timeout=180,
            )
            out = run([
                "kubectl",
                "logs",
                "job/arg-runtime-smoke",
                "-n",
                "arg-smoke",
            ], capture=True, timeout=60)
            if "kubernetes runtime smoke passed" not in (out.stdout or ""):
                raise AssertionError("Kubernetes Job did not run the SDK smoke program")
    finally:
        cleanup_kind_cluster(cluster)
        run(["docker", "image", "rm", "--force", image], check=False, timeout=60)


def require(binary: str) -> None:
    if shutil.which(binary) is None:
        raise SystemExit(f"{binary} is required")


def run(command: list[str], *, check: bool = True, capture: bool = False, timeout: int = 180):
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        output = result.stdout or ""
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{output}")
    return result


def cleanup_container(name: str) -> None:
    run(
        ["docker", "rm", "-f", name],
        check=False,
        capture=True,
        timeout=60,
    )


def pull_image(image: str, *, attempts: int = 3) -> None:
    delay = 2.0
    last_output = ""
    for attempt in range(1, attempts + 1):
        try:
            result = run(
                ["docker", "pull", image],
                check=False,
                capture=True,
                timeout=240,
            )
        except subprocess.TimeoutExpired as exc:
            output = exc.output if exc.output is not None else ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            last_output = output
            failure = f"timed out after {exc.timeout:.0f}s"
        else:
            if result.returncode == 0:
                return
            last_output = result.stdout or ""
            failure = f"exit code {result.returncode}"
        if attempt < attempts:
            print(
                f"docker pull failed for {image} ({failure}; "
                f"attempt {attempt}/{attempts}); retrying in {delay:.0f}s"
            )
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(
        f"docker pull failed after {attempts} attempts for {image}\n{last_output}"
    )


def kind_smoke_resources() -> tuple[str, str]:
    """Allocate exact, process-scoped Docker resources for one Kind smoke run."""

    suffix = f"{os.getpid()}-{secrets.token_hex(8)}"
    return (
        f"arg-v07-smoke-{suffix}",
        f"agent-runtime-governance-k8s-smoke-{suffix}:local",
    )


def render_kind_smoke_manifest(directory: Path, image: str) -> Path:
    """Render the run-scoped image tag into the checked-in hardened Job template."""

    template = ROOT / "integration" / "k8s" / "smoke.yaml"
    content = template.read_text(encoding="utf-8")
    if content.count(_KIND_IMAGE_PLACEHOLDER) != 1:
        raise RuntimeError("Kind smoke manifest must contain exactly one image placeholder")
    rendered = directory / "smoke.yaml"
    rendered.write_text(
        content.replace(_KIND_IMAGE_PLACEHOLDER, image),
        encoding="utf-8",
    )
    return rendered


def build_kind_smoke_image(
    *,
    image: str = KIND_SMOKE_IMAGE,
    attempts: int = 3,
) -> None:
    """Build the local Kind image with bounded, cache-busting retries.

    A failed Docker build is never treated as success. A retry bypasses
    BuildKit layer cache so transient dependency-download or build-isolation
    failures are re-evaluated from a clean image build. Artifact hash pinning
    is deliberately not claimed here: that requires a separately maintained
    hash-locked constraints file.
    """

    base_command = [
        "docker",
        "build",
        "--tag",
        image,
        "--file",
        str(ROOT / "integration" / "k8s" / "Dockerfile"),
        str(ROOT),
    ]
    delay = 2.0
    last_output = ""
    for attempt in range(1, attempts + 1):
        command = [
            *base_command[:2],
            *(["--no-cache"] if attempt > 1 else []),
            *base_command[2:],
        ]
        try:
            result = run(command, check=False, capture=True, timeout=420)
        except subprocess.TimeoutExpired as exc:
            output = exc.output if exc.output is not None else ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            last_output = output
            failure = f"timed out after {exc.timeout:.0f}s"
        else:
            if result.returncode == 0:
                return
            last_output = result.stdout or ""
            failure = f"exit code {result.returncode}"
        run(
            ["docker", "image", "rm", "--force", image],
            check=False,
            capture=True,
            timeout=60,
        )
        if attempt < attempts:
            print(
                f"docker build failed for {image} ({failure}; "
                f"attempt {attempt}/{attempts}); retrying in {delay:.0f}s"
            )
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(
        f"docker build failed after {attempts} attempts for {image}\n"
        f"{last_output}"
    )


def cleanup_kind_cluster(cluster: str) -> None:
    """Delete the exact smoke cluster and verify its control-plane is gone."""

    run(
        ["kind", "delete", "cluster", "--name", cluster],
        check=False,
        capture=True,
        timeout=180,
    )
    container = f"{cluster}-control-plane"
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        clusters = run(["kind", "get", "clusters"], check=False, capture=True, timeout=30)
        node = run(
            ["docker", "container", "inspect", container],
            check=False,
            capture=True,
            timeout=30,
        )
        remaining_clusters = set((clusters.stdout or "").splitlines())
        if cluster not in remaining_clusters and node.returncode != 0:
            return
        time.sleep(0.5)

    # `kind delete` occasionally returns before Docker Desktop has finished
    # removing a control-plane that died during kubeadm. This exact name is
    # owned by this smoke test, so force-removal is bounded and safe.
    run(
        ["docker", "rm", "--force", container],
        check=False,
        capture=True,
        timeout=60,
    )
    clusters = run(["kind", "get", "clusters"], check=False, capture=True, timeout=30)
    node = run(
        ["docker", "container", "inspect", container],
        check=False,
        capture=True,
        timeout=30,
    )
    if cluster in set((clusters.stdout or "").splitlines()) or node.returncode == 0:
        raise RuntimeError(f"failed to clean up Kind smoke cluster {cluster!r}")


def wait_http(url: str, *, expected_status: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request = Request(url, method="GET")
            with urlopen(request, timeout=2.0) as response:
                if response.status == expected_status:
                    return
        except OSError:
            pass
        time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {url}")


def read_url(url: str) -> bytes:
    with urlopen(url, timeout=5.0) as response:
        return response.read()


def wait_docker_logs(container: str, needle: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["docker", "logs", container], check=False, capture=True, timeout=30)
        if needle in (result.stdout or ""):
            return
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for {needle!r} in {container} logs")


if __name__ == "__main__":
    main()
