"""US-002 acceptance — sandbox_runner bpftrace path orchestrates the docker lifecycle.

Verifies that the bpftrace path issues docker subcommands in the order
``[create, start, inspect, exec, stop, rm]`` — barrier pattern, no pause; the
``exec`` step releases an in-container sentinel after probes attach. Other
subcommands such as
``wait`` and ``logs`` may appear interleaved). Also confirms backward compatibility
with the strace default and graceful degradation when the bpftrace attach raises.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable

import pytest

from security_framework import sandbox_runner
from security_framework.config import SecurityFrameworkConfig


LIFECYCLE_SUBCOMMANDS = {"create", "start", "inspect", "exec", "stop", "rm"}
EXPECTED_LIFECYCLE = ["create", "start", "inspect", "exec", "stop", "rm"]

CONTAINER_ID = "deadbeef" * 8  # 64-char fake docker id
ATTACHING_MARKER = "Attaching 6 probes...\n"


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _FakePopen:
    """Stand-in for the bpftrace docker subprocess.Popen.

    Behaves like a process that has already attached probes (stderr file has the
    marker before _wait_for_attach_marker is called).
    """

    def __init__(self, cmd: list[str], stdout=None, stderr=None, **_kwargs):
        self.args = cmd
        self.pid = 99999
        self._poll_value: int | None = None
        # The wait-for-attach polling reads the stderr file path. Inject the marker.
        if stderr is not None and hasattr(stderr, "write"):
            stderr.write(ATTACHING_MARKER)
            stderr.flush()

    def poll(self):
        return self._poll_value

    def terminate(self):
        self._poll_value = -15

    def kill(self):
        self._poll_value = -9

    def wait(self, timeout=None):
        self._poll_value = self._poll_value if self._poll_value is not None else 0
        return self._poll_value


def _make_fake_run(record: list[list[str]]):
    def fake_run(cmd, *args, **kwargs):
        record.append(list(cmd))
        if not isinstance(cmd, (list, tuple)) or len(cmd) < 2 or cmd[0] != "docker":
            return _FakeCompleted()
        sub = cmd[1]
        if sub == "create":
            return _FakeCompleted(stdout=CONTAINER_ID + "\n")
        if sub == "inspect":
            return _FakeCompleted(stdout="424242\n")  # fake container pid
        if sub == "wait":
            return _FakeCompleted(stdout="0\n")
        if sub == "logs":
            return _FakeCompleted(stdout="hello\n", stderr="")
        return _FakeCompleted()
    return fake_run


def _lifecycle_subseq(calls: Iterable[list[str]]) -> list[str]:
    return [
        c[1] for c in calls
        if len(c) >= 2 and c[0] == "docker" and c[1] in LIFECYCLE_SUBCOMMANDS
    ]


@pytest.fixture
def bpftrace_cfg(tmp_path: Path) -> SecurityFrameworkConfig:
    return SecurityFrameworkConfig(
        sandbox_docker_image="ubuntu:24.04",
        sandbox_network_mode="none",
        sandbox_timeout=5,
        workspace_copy_parent=str(tmp_path / "shadow_parent"),
        max_output_chars=4096,
        trace_mode="bpftrace",
        bpftrace_image="quay.io/iovisor/bpftrace:master",
        bpftrace_attach_timeout=2,
        bpftrace_sentinel_timeout=1,
    )


def test_bpftrace_path_issues_docker_lifecycle_in_order(
    monkeypatch, tmp_path: Path, bpftrace_cfg: SecurityFrameworkConfig
):
    calls: list[list[str]] = []
    monkeypatch.setattr(sandbox_runner.subprocess, "run", _make_fake_run(calls))
    monkeypatch.setattr(sandbox_runner.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(
        sandbox_runner, "_parse_proc_cgroup_v2", lambda pid: tmp_path,
    )

    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "hello.txt").write_text("hi\n", encoding="utf-8")
    run_dir = tmp_path / "run"

    result = sandbox_runner.run_in_sandbox(
        "ls -la", str(workspace), str(run_dir), bpftrace_cfg,
    )

    assert result["trace_method"] == "bpftrace"
    assert result["container_id"] == CONTAINER_ID
    assert _lifecycle_subseq(calls) == EXPECTED_LIFECYCLE


def test_bpftrace_attach_failure_falls_back_to_strace(
    monkeypatch, tmp_path: Path, bpftrace_cfg: SecurityFrameworkConfig
):
    calls: list[list[str]] = []
    monkeypatch.setattr(sandbox_runner.subprocess, "run", _make_fake_run(calls))
    monkeypatch.setattr(sandbox_runner.subprocess, "Popen", _FakePopen)

    def boom(pid):
        raise sandbox_runner._BpftraceUnavailable("cgroup-v1-only host")

    monkeypatch.setattr(sandbox_runner, "_parse_proc_cgroup_v2", boom)

    workspace = tmp_path / "ws"
    workspace.mkdir()
    run_dir = tmp_path / "run"

    result = sandbox_runner.run_in_sandbox(
        "echo hi", str(workspace), str(run_dir), bpftrace_cfg,
    )

    # Attach failure → graceful degrade: container completes without probes,
    # trace_method stays "bpftrace_attach_failed" + fallback recorded.
    assert result["trace_method"] == "bpftrace_attach_failed"
    assert "cgroup-v1-only" in result["trace_method_fallback"]
    # Lifecycle still completes — unpause still gets called even when attach failed.
    assert _lifecycle_subseq(calls) == EXPECTED_LIFECYCLE


def test_strace_default_path_unchanged(monkeypatch, tmp_path: Path):
    """Backward-compat — default trace_mode=strace must still single-shot docker run."""
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        return _FakeCompleted(stdout="ok\n", stderr="", returncode=0)

    monkeypatch.setattr(sandbox_runner.subprocess, "run", fake_run)

    cfg = SecurityFrameworkConfig(
        sandbox_docker_image="ubuntu:24.04",
        sandbox_network_mode="none",
        sandbox_timeout=5,
        workspace_copy_parent=str(tmp_path / "shadow_parent"),
        max_output_chars=4096,
        trace_mode="strace",
    )
    workspace = tmp_path / "ws"
    workspace.mkdir()
    run_dir = tmp_path / "run"

    result = sandbox_runner.run_in_sandbox("ls", str(workspace), str(run_dir), cfg)

    assert result["trace_method"] == "strace"
    # Exactly one docker call for strace path — a synchronous `docker run --rm`.
    docker_calls = [c for c in calls if c and c[0] == "docker"]
    assert len(docker_calls) == 1
    assert docker_calls[0][1] == "run"


def test_docker_unavailable_during_bpftrace_creates_strace_fallback(
    monkeypatch, tmp_path: Path, bpftrace_cfg: SecurityFrameworkConfig
):
    """If `docker` binary is missing, bpftrace path raises and strace re-runs."""
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        if cmd and cmd[0] == "docker":
            raise FileNotFoundError("docker")
        return _FakeCompleted()

    monkeypatch.setattr(sandbox_runner.subprocess, "run", fake_run)

    workspace = tmp_path / "ws"
    workspace.mkdir()
    run_dir = tmp_path / "run"

    result = sandbox_runner.run_in_sandbox(
        "echo hi", str(workspace), str(run_dir), bpftrace_cfg,
    )

    # bpftrace path raised _BpftraceUnavailable("docker executable not found")
    # → fell back to strace, which ALSO hits FileNotFoundError → docker_unavailable.
    assert result["trace_method"] == "strace"
    assert "docker executable not found" in result["trace_method_fallback"]
    assert result["execution_status"] == "docker_unavailable"


def test_render_probe_substitutes_markers():
    template = "cgroup == __CGROUP_ID__ && pid == __SENTINEL_PID__ && fd == __SENTINEL_FD__"
    rendered = sandbox_runner._render_probe(
        template, cgroup_id=4242, sentinel_pid=123, sentinel_fd=5,
    )
    assert "__CGROUP_ID__" not in rendered
    assert "4242" in rendered and "123" in rendered and " fd == 5" in rendered


def test_parse_proc_cgroup_v2_raises_on_missing(monkeypatch):
    def fake_read_text(self, *args, **kwargs):
        raise OSError("ENOENT")

    monkeypatch.setattr(Path, "read_text", fake_read_text)
    with pytest.raises(sandbox_runner._BpftraceUnavailable):
        sandbox_runner._parse_proc_cgroup_v2(99999)
