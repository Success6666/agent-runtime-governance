from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from agent_runtime_governance import JSONLAuditSink


def test_strict_action_contract_example_runs_with_real_policy_artifact(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    audit_key = "a" * 32
    env = {
        **os.environ,
        "ARG_IDENTITY_DIGEST_KEY": "i" * 32,
        "ARG_AUDIT_HMAC_KEY": audit_key,
        "ARG_STATE_DIR": str(tmp_path),
    }
    command = [sys.executable, "examples/strict_action_contract.py"]

    first = subprocess.run(
        command,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    second = subprocess.run(
        command,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )

    assert first.stdout == second.stdout
    assert json.loads(first.stdout) == {"enabled": True, "service": "worker"}
    assert (tmp_path / "worker.state").read_text(encoding="utf-8") == "enabled"
    events = JSONLAuditSink(
        tmp_path / "audit.jsonl", sign_key=audit_key
    ).read_verified()
    assert events
    assert all(event["action_digest"] for event in events)
    assert {event["context"]["metadata"]["policy_version"] for event in events} == {
        "strict-action-example-policy-v1"
    }
