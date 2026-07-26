from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
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
    InvocationOptions,
    JSONLAuditSink,
    OPAClient,
    OPAMiddleware,
    OpenTelemetryMiddleware,
    ProductionProfile,
    PrometheusMiddleware,
    RiskTier,
    Runtime,
    SQLiteIdempotencyStore,
    StaticIdentityProvider,
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
    name = "arg-v05-opa"
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
        with TemporaryDirectory(prefix="arg-v06-opa-") as temporary:
            state = Path(temporary)
            with contextlib.ExitStack() as stack:
                allowed, sink = _strict_opa_runtime(
                    state / "allowed",
                    permissions=frozenset({"admin"}),
                    policy_digest=policy_digest,
                )
                stack.callback(allowed.close)
                denied, _ = _strict_opa_runtime(
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
) -> tuple[Runtime, JSONLAuditSink]:
    state.mkdir(parents=True, exist_ok=True)
    policy_version = "production-smoke-policy-v1"
    sink = JSONLAuditSink(state / "audit.jsonl", sign_key=b"a" * 32)
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
        idempotency_store=SQLiteIdempotencyStore(state / "idempotency.db"),
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

    @runtime.tool(
        name="delete_file",
        risk=RiskTier.HIGH,
        execution_mode=ExecutionMode.IDEMPOTENT,
        action_contract=contract,
    )
    def delete_file() -> bool:
        return True

    runtime.seal_production()
    return runtime, sink


def run_otel_smoke(keep_containers: bool) -> None:
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        raise SystemExit("Install the otel extra before running this smoke check") from exc

    name = "arg-v05-otel"
    cleanup_container(name)
    pull_image(OTEL_IMAGE)
    config = ROOT / "integration" / "otel" / "collector-config.yaml"
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

        @runtime.tool()
        def observed() -> str:
            with tracer.start_as_current_span("inside-smoke-tool"):
                return "ok"

        assert observed() == "ok"
        provider.force_flush(5000)
        provider.shutdown()
        wait_docker_logs(name, "inside-smoke-tool")
    finally:
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
    cluster = "arg-v05-smoke"
    run(["kind", "delete", "cluster", "--name", cluster], check=False)
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
        manifest = ROOT / "integration" / "k8s" / "smoke.yaml"
        run(["kubectl", "apply", "-f", str(manifest)], timeout=60)
        run(["kubectl", "wait", "--for=condition=Ready", "node", "--all", "--timeout=120s"], timeout=180)
        out = run([
            "kubectl",
            "get",
            "configmap",
            "arg-smoke-config",
            "-n",
            "arg-smoke",
            "-o",
            "json",
        ], capture=True, timeout=60)
        data = json.loads(out.stdout)["data"]
        if data.get("runtime.txt") != "ExecutionContext pipeline smoke":
            raise AssertionError("Kubernetes smoke ConfigMap content mismatch")
    finally:
        run(["kind", "delete", "cluster", "--name", cluster], check=False, timeout=180)


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
