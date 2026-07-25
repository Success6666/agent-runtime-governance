from __future__ import annotations

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from agent_runtime_governance import (
    GovernanceDenied,
    InvocationOptions,
    PrometheusMiddleware,
    Rule,
    RuleMiddleware,
    Runtime,
    SlackNotificationMiddleware,
    SlackWebhookNotifier,
)


def test_prometheus_records_success_without_identity_labels() -> None:
    registry = CollectorRegistry()
    runtime = Runtime([PrometheusMiddleware(registry=registry, prefix="test_arg")])

    @runtime.tool()
    def work() -> bool:
        return True

    work()
    output = generate_latest(registry).decode()
    assert 'test_arg_tool_calls_total{risk_tier="LOW",status="succeeded",tool="work"} 1.0' in output
    assert "trace_id" not in output
    assert "user" not in output


def test_prometheus_records_denial_once() -> None:
    registry = CollectorRegistry()
    runtime = Runtime(
        [
            RuleMiddleware([Rule("deny", r"\bdeny\b", "blocked")]),
            PrometheusMiddleware(registry=registry, prefix="deny_arg"),
        ]
    )

    @runtime.tool()
    def work() -> bool:
        return True

    with pytest.raises(GovernanceDenied):
        runtime.invoke("work", _governance=InvocationOptions(input_text="deny"))
    output = generate_latest(registry).decode()
    assert 'deny_arg_tool_calls_total{risk_tier="LOW",status="denied",tool="work"} 1.0' in output


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.slack.com/services/x/y/z",
        "https://example.com/services/x/y/z",
        "https://user:pass@hooks.slack.com/services/x/y/z",
        "https://hooks.slack.com/services/x/y/z?token=secret",
        "https://hooks.slack.com:444/services/x/y/z",
        "https://hooks.slack.com/not-a-webhook",
    ],
)
def test_slack_rejects_unsafe_webhook_urls(url: str) -> None:
    with pytest.raises(ValueError):
        SlackWebhookNotifier(url)


def test_slack_notification_contains_no_tool_arguments() -> None:
    payloads: list[dict] = []
    runtime = Runtime(
        [
            RuleMiddleware([Rule("deny", r"\bdeny\b", "blocked")]),
            SlackNotificationMiddleware(payloads.append),
        ]
    )

    @runtime.tool()
    def login(password: str) -> bool:
        return True

    with pytest.raises(GovernanceDenied):
        runtime.invoke(
            "login",
            "top-secret-password",
            _governance=InvocationOptions(input_text="deny"),
        )
    assert len(payloads) == 1
    assert "top-secret-password" not in payloads[0]["text"]
    assert "login" in payloads[0]["text"]


def test_slack_default_does_not_notify_success() -> None:
    payloads: list[dict] = []
    runtime = Runtime([SlackNotificationMiddleware(payloads.append)])

    @runtime.tool()
    def work() -> bool:
        return True

    work()
    assert payloads == []
