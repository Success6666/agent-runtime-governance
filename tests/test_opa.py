from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError

import pytest

from agent_runtime_governance import (
    GovernanceDenied,
    OPAClient,
    OPAMiddleware,
    OPAPlugin,
    PluginManager,
    Runtime,
)
from agent_runtime_governance.context import ExecutionContext, ToolCall


def runtime_with_opa(response, *, fail_closed: bool = True):
    client = OPAClient(
        "http://localhost:8181",
        "agent/tools/allow",
        transport=lambda payload: response(payload) if callable(response) else response,
    )
    runtime = Runtime([OPAMiddleware(client, fail_closed=fail_closed)])

    @runtime.tool()
    def operate(secret: str = "hidden") -> bool:
        return True

    return runtime


def test_opa_boolean_allow() -> None:
    assert runtime_with_opa({"result": True}).invoke("operate") is True


def test_opa_structured_deny() -> None:
    runtime = runtime_with_opa(
        {"result": {"allow": False, "reason": "maintenance window"}}
    )
    with pytest.raises(GovernanceDenied, match="maintenance window"):
        runtime.invoke("operate")


def test_opa_payload_omits_tool_arguments() -> None:
    captured = {}

    def inspect_payload(payload):
        captured.update(payload)
        return {"result": True}

    runtime_with_opa(inspect_payload).invoke("operate", "top-secret")
    text = __import__("json").dumps(captured)
    assert "top-secret" not in text
    assert captured["input"]["tool"] == "operate"


def test_opa_failure_closes_by_default() -> None:
    def unavailable(payload):
        raise ConnectionError("OPA offline")

    with pytest.raises(GovernanceDenied, match="failed closed"):
        runtime_with_opa(unavailable).invoke("operate")


def test_opa_can_explicitly_fail_open() -> None:
    def unavailable(payload):
        raise ConnectionError("OPA offline")

    assert runtime_with_opa(unavailable, fail_closed=False).invoke("operate") is True


def test_invalid_opa_response_fails_closed() -> None:
    with pytest.raises(GovernanceDenied):
        runtime_with_opa({"result": {"value": True}}).invoke("operate")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://opa.example.com:8181",
        "ftp://localhost:8181",
        "https://user:pass@opa.example.com",
    ],
)
def test_opa_rejects_unsafe_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError):
        OPAClient(endpoint, "agent/allow")


@pytest.mark.parametrize("path", ["", "../secret", "agent/../../secret", "agent?x=1"])
def test_opa_rejects_unsafe_policy_paths(path: str) -> None:
    with pytest.raises(ValueError):
        OPAClient("http://localhost:8181", path)


def test_opa_client_refuses_real_http_redirect_without_visiting_target() -> None:
    target_hits: list[str | None] = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{self.server.server_port}/target",
            )
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            target_hits.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"result":true}')

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        client = OPAClient(
            f"http://127.0.0.1:{server.server_port}",
            "agent/allow",
            headers={"Authorization": "Bearer secret"},
        )
        # On Windows the local stack can report the deliberately abandoned
        # redirect response as a socket abort before urllib exposes HTTP 302.
        with pytest.raises(
            (HTTPError, ConnectionAbortedError, ConnectionResetError)
        ) as caught:
            client.evaluate(ExecutionContext.create(ToolCall("operate")))
        if isinstance(caught.value, HTTPError):
            assert caught.value.code == 302
        assert target_hits == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        assert not thread.is_alive()


def test_opa_plugin_registers_real_middleware() -> None:
    client = OPAClient(
        "http://localhost:8181", "agent/allow", transport=lambda payload: {"result": True}
    )
    manager = PluginManager()
    manager.load(OPAPlugin(client))
    runtime = manager.build()

    @runtime.tool()
    def operate() -> bool:
        return True

    assert operate() is True
    assert "opa" in manager.builder.services
