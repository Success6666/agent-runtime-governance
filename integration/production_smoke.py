from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from urllib.request import Request, urlopen

from prometheus_client import CollectorRegistry, start_http_server

from agent_runtime_governance import (
    GovernanceDenied,
    InvocationOptions,
    OPAClient,
    OPAMiddleware,
    OpenTelemetryMiddleware,
    PrometheusMiddleware,
    RiskTier,
    Runtime,
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
        runtime = Runtime([
            OPAMiddleware(
                OPAClient("http://127.0.0.1:8181", "agents/tools/allow"),
                fail_closed=True,
            )
        ])

        @runtime.tool(risk=RiskTier.HIGH)
        def delete_file() -> bool:
            return True

        assert delete_file(_governance=InvocationOptions(permissions=frozenset({"admin"})))
        with contextlib.suppress(GovernanceDenied):
            delete_file(_governance=InvocationOptions(permissions=frozenset()))
            raise AssertionError("OPA did not deny a non-admin delete_file call")
    finally:
        if not keep_containers:
            cleanup_container(name)


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

    assert ping() == "pong"
    start_http_server(19091, addr="127.0.0.1", registry=registry)
    body = read_url("http://127.0.0.1:19091/metrics").decode("utf-8")
    expected = 'arg_smoke_tool_calls_total{risk_tier="LOW",status="succeeded",tool="ping"} 1.0'
    if expected not in body:
        raise AssertionError("Prometheus metrics endpoint did not expose the governed call")


def run_kind_smoke() -> None:
    if shutil.which("kind") is None or shutil.which("kubectl") is None:
        raise SystemExit("kind and kubectl are required for the Kubernetes smoke check")
    cluster = "arg-v05-smoke"
    run(["kind", "delete", "cluster", "--name", cluster], check=False)
    try:
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
