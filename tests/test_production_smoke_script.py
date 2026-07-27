"""Unit tests for failure-sensitive orchestration in the Docker smoke script."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


def _load_smoke_script():
    path = Path(__file__).parents[1] / "integration" / "production_smoke.py"
    spec = importlib.util.spec_from_file_location("production_smoke_test_module", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_kind_image_retry_bypasses_build_cache(monkeypatch) -> None:
    smoke = _load_smoke_script()
    commands: list[list[str]] = []
    build_attempts = 0

    def fake_run(command, **_kwargs):
        nonlocal build_attempts
        command = list(command)
        commands.append(command)
        if command[:2] == ["docker", "build"]:
            build_attempts += 1
            return subprocess.CompletedProcess(
                command,
                1 if build_attempts == 1 else 0,
                stdout="transient failure" if build_attempts == 1 else "",
            )
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(smoke, "run", fake_run)
    monkeypatch.setattr(smoke.time, "sleep", lambda _seconds: None)

    smoke.build_kind_smoke_image(attempts=2)

    builds = [command for command in commands if command[:2] == ["docker", "build"]]
    assert len(builds) == 2
    assert "--no-cache" not in builds[0]
    assert "--no-cache" in builds[1]


def test_kind_image_retry_reports_exhausted_build_failures(monkeypatch) -> None:
    smoke = _load_smoke_script()
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        command = list(command)
        commands.append(command)
        if command[:2] == ["docker", "build"]:
            return subprocess.CompletedProcess(command, 1, stdout="build failed")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(smoke, "run", fake_run)
    monkeypatch.setattr(smoke.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="docker build failed after 2 attempts") as failed:
        smoke.build_kind_smoke_image(image="example.test/smoke:run", attempts=2)

    assert "build failed" in str(failed.value)
    assert len([item for item in commands if item[:2] == ["docker", "build"]]) == 2
    assert len([item for item in commands if item[:4] == ["docker", "image", "rm", "--force"]]) == 2


def test_kind_image_retry_reports_timeout_output(monkeypatch) -> None:
    smoke = _load_smoke_script()
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        command = list(command)
        commands.append(command)
        if command[:2] == ["docker", "build"]:
            raise subprocess.TimeoutExpired(command, 420, output=b"build timed out")
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(smoke, "run", fake_run)
    monkeypatch.setattr(smoke.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="docker build failed after 2 attempts") as failed:
        smoke.build_kind_smoke_image(image="example.test/smoke:run", attempts=2)

    assert "build timed out" in str(failed.value)
    assert len([item for item in commands if item[:2] == ["docker", "build"]]) == 2
    assert len([item for item in commands if item[:4] == ["docker", "image", "rm", "--force"]]) == 2


def test_kind_smoke_resources_are_scoped_to_one_run(monkeypatch) -> None:
    smoke = _load_smoke_script()
    monkeypatch.setattr(smoke.os, "getpid", lambda: 4242)
    values = iter(("first", "second"))
    monkeypatch.setattr(smoke.secrets, "token_hex", lambda _bytes: next(values))

    first_cluster, first_image = smoke.kind_smoke_resources()
    second_cluster, second_image = smoke.kind_smoke_resources()

    assert first_cluster == "arg-v07-smoke-4242-first"
    assert second_cluster == "arg-v07-smoke-4242-second"
    assert first_image == "agent-runtime-governance-k8s-smoke-4242-first:local"
    assert second_image == "agent-runtime-governance-k8s-smoke-4242-second:local"


def test_kind_manifest_renders_exactly_one_run_scoped_image(tmp_path) -> None:
    smoke = _load_smoke_script()

    manifest = smoke.render_kind_smoke_manifest(tmp_path, "example.test/smoke:run")

    content = manifest.read_text(encoding="utf-8")
    assert content.count("image: example.test/smoke:run") == 1
    assert smoke._KIND_IMAGE_PLACEHOLDER not in content
