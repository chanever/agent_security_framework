"""Docker-based shadow execution for proposed shell commands.

Two trace modes are supported (selected via ``SecurityFrameworkConfig.trace_mode``):

* ``"strace"`` (default) — single ``docker run --rm`` with strace recording
  openat/execve/connect/unlink/rename to a host-mounted file. Observes above
  the LSM layer, so ``lsm_events`` is empty downstream.

* ``"bpftrace"`` — Path B attach: ``docker create → docker start → docker pause
  → docker inspect (.State.Pid) → parse /proc/<pid>/cgroup → render
  ``probes/probe.bt`` → launch host-side ``bpftrace`` docker wrapper →
  wait for "Attaching N probes" → docker unpause → docker wait → docker logs
  → docker stop → docker rm``. The cgroup-scoped probes include
  ``kprobe:security_file_open`` (LSM hook function observation) so
  ``trace_parser.parse_bpftrace_trace`` can populate real ``lsm_events``.

If the bpftrace path raises :class:`_BpftraceUnavailable` (missing docker, image
pull failure, cgroup v1-only host, attach timeout), the runner reruns the
strace path and records ``trace_method_fallback`` so the rest of the framework
keeps producing evidence.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from security_framework.config import SecurityFrameworkConfig


def _tail(value: str, max_chars: int) -> str:
    return value[-max_chars:] if len(value) > max_chars else value


def _copy_workspace(source: Path, destination: Path) -> None:
    ignore = shutil.ignore_patterns(".git", "__pycache__", ".venv", "node_modules", "*.pyc")
    if source.is_dir():
        shutil.copytree(source, destination, ignore=ignore, dirs_exist_ok=True)
    else:
        destination.mkdir(parents=True, exist_ok=True)


def _create_dummy_home(home_dir: Path) -> None:
    ssh_dir = home_dir / ".ssh"
    aws_dir = home_dir / ".aws"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    aws_dir.mkdir(parents=True, exist_ok=True)
    (ssh_dir / "id_rsa").write_text("DUMMY_SANDBOX_PRIVATE_KEY_DO_NOT_USE\n", encoding="utf-8")
    (aws_dir / "credentials").write_text(
        "[default]\naws_access_key_id=DUMMY\naws_secret_access_key=DUMMY\n",
        encoding="utf-8",
    )
    (home_dir / "private.txt").write_text("DUMMY_SANDBOX_PRIVATE_DATA\n", encoding="utf-8")


# ───────────────────────────── bpftrace orchestrator ───────────────────────────


PROBE_TEMPLATE = Path(__file__).parent / "probes" / "probe.bt"
_ATTACHING_RE = re.compile(r"Attaching\s+(\d+)\s+probes", re.IGNORECASE)


class _BpftraceUnavailable(RuntimeError):
    """Raised when the bpftrace path cannot proceed — triggers strace re-run."""


def _v2_mount_point() -> Path | None:
    """Locate the cgroup v2 unified hierarchy mount point.

    Pure-v2 hosts mount at ``/sys/fs/cgroup``; hybrid v1+v2 hosts (Ubuntu
    20.04 / 22.04 default) mount at ``/sys/fs/cgroup/unified``. Either yields
    the inode bpftrace's ``cgroup`` builtin compares against.
    """
    try:
        text = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "cgroup2":
            return Path(parts[1])
    return None


def _parse_proc_cgroup_v2(pid: int) -> Path:
    try:
        text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise _BpftraceUnavailable(f"cannot read /proc/{pid}/cgroup: {exc}") from exc
    for line in text.splitlines():
        if line.startswith("0::"):
            rel = line.split("::", 1)[1].strip()
            mount = _v2_mount_point() or Path("/sys/fs/cgroup")
            return mount / rel.lstrip("/")
    raise _BpftraceUnavailable(f"no cgroup v2 unified line in /proc/{pid}/cgroup")


def _render_probe(template: str, *, cgroup_id: int, sentinel_pid: int, sentinel_fd: int) -> str:
    return (
        template
        .replace("__CGROUP_ID__", str(cgroup_id))
        .replace("__SENTINEL_PID__", str(sentinel_pid))
        .replace("__SENTINEL_FD__", str(sentinel_fd))
    )


def _wait_for_attach_marker(
    stderr_path: Path,
    events_path: Path,
    *,
    timeout_s: float,
    stop_check,
) -> int:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if stop_check():
            raise _BpftraceUnavailable("bpftrace exited before attach marker")
        for path in (stderr_path, events_path):
            try:
                data = path.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                continue
            match = _ATTACHING_RE.search(data)
            if match:
                return int(match.group(1))
        time.sleep(0.02)
    raise _BpftraceUnavailable(f"bpftrace did not attach within {timeout_s}s")


def _start_bpftrace_docker(
    script_path: Path,
    events_path: Path,
    stderr_path: Path,
    cfg: SecurityFrameworkConfig,
) -> subprocess.Popen:
    cmd = [
        "docker", "run", "--rm", "-i",
        "--privileged",
        "--pid=host",
        "-v", "/sys/kernel/debug:/sys/kernel/debug:ro",
        "-v", "/sys/fs/cgroup:/sys/fs/cgroup:ro",
        "-v", "/lib/modules:/lib/modules:ro",
        "-v", f"{script_path}:/probe.bt:ro",
        cfg.bpftrace_image,
        "bpftrace", "/probe.bt",
    ]
    events_fh = events_path.open("w")
    stderr_fh = stderr_path.open("w")
    try:
        return subprocess.Popen(
            cmd,
            stdout=events_fh,
            stderr=stderr_fh,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
    except FileNotFoundError as exc:
        raise _BpftraceUnavailable("docker executable not found") from exc


def _docker_run(args: list[str], *, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)
    except FileNotFoundError as exc:
        raise _BpftraceUnavailable("docker executable not found") from exc
    except subprocess.CalledProcessError as exc:
        raise _BpftraceUnavailable(
            f"{' '.join(args[:3])} exited {exc.returncode}: {(exc.stderr or '').strip()}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise _BpftraceUnavailable(f"{' '.join(args[:3])} timed out after {timeout}s") from exc


def _attach_bpftrace_to_container(
    container_id: str,
    run_dir: Path,
    cfg: SecurityFrameworkConfig,
) -> tuple[subprocess.Popen, Path]:
    """Path B attach: pause → inspect pid → render probe → launch bpftrace docker.

    Returns ``(bpftrace_proc, events_path)``. The caller MUST unpause the
    container and reap ``bpftrace_proc`` afterwards.
    """
    _docker_run(["docker", "pause", container_id])
    inspect = _docker_run(["docker", "inspect", "-f", "{{.State.Pid}}", container_id])
    try:
        container_pid = int(inspect.stdout.strip())
    except ValueError as exc:
        raise _BpftraceUnavailable(
            f"docker inspect returned non-integer pid: {inspect.stdout!r}"
        ) from exc

    cgroup_path = _parse_proc_cgroup_v2(container_pid)
    if not cgroup_path.exists():
        raise _BpftraceUnavailable(f"resolved cgroup path does not exist: {cgroup_path}")
    cgroup_id = cgroup_path.stat().st_ino

    sentinel_path = run_dir / "bpftrace.sentinel"
    sentinel_fh = sentinel_path.open("wb")
    rendered = _render_probe(
        PROBE_TEMPLATE.read_text(encoding="utf-8"),
        cgroup_id=cgroup_id,
        sentinel_pid=os.getpid(),
        sentinel_fd=sentinel_fh.fileno(),
    )
    script_path = run_dir / "probe.rendered.bt"
    script_path.write_text(rendered, encoding="utf-8")

    events_path = run_dir / "bpftrace.events.jsonl"
    stderr_path = run_dir / "bpftrace.err"
    proc = _start_bpftrace_docker(script_path, events_path, stderr_path, cfg)

    _wait_for_attach_marker(
        stderr_path,
        events_path,
        timeout_s=cfg.bpftrace_attach_timeout,
        stop_check=lambda: proc.poll() is not None,
    )
    return proc, events_path


def _stop_bpftrace(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, AttributeError, OSError):
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass


def _run_in_sandbox_bpftrace(
    command: str,
    workspace: Path,
    run_path: Path,
    cfg: SecurityFrameworkConfig,
) -> dict:
    temp_parent = Path(cfg.workspace_copy_parent)
    temp_parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix="shadow_workspace_", dir=temp_parent))
    sandbox_workspace = temp_dir / "workspace"
    sandbox_home = temp_dir / "home" / "sandbox"
    _copy_workspace(workspace, sandbox_workspace)
    _create_dummy_home(sandbox_home)

    shell_command = f"cd /workspace && {command}"
    wrapped = f"bash -lc {shlex.quote(shell_command)}"
    create_args = [
        "docker", "create",
        "--network", cfg.sandbox_network_mode,
        "-v", f"{sandbox_workspace}:/workspace:rw",
        "-v", f"{sandbox_home}:/home/sandbox:rw",
        "-e", "HOME=/home/sandbox",
        "-w", "/workspace",
        cfg.sandbox_docker_image,
        "bash", "-lc", wrapped,
    ]
    create = _docker_run(create_args, timeout=30)
    container_id = create.stdout.strip()

    bpftrace_proc: subprocess.Popen | None = None
    events_path: Path | None = None
    attach_error: str | None = None
    stdout = ""
    stderr = ""
    exit_code: int | None = None
    status = "completed"
    timed_out = False

    try:
        _docker_run(["docker", "start", container_id])
        try:
            bpftrace_proc, events_path = _attach_bpftrace_to_container(container_id, run_path, cfg)
        except _BpftraceUnavailable as exc:
            attach_error = str(exc)
            _docker_run(["docker", "unpause", container_id], check=False)
        else:
            _docker_run(["docker", "unpause", container_id])

        try:
            wait = subprocess.run(
                ["docker", "wait", container_id],
                capture_output=True,
                text=True,
                timeout=cfg.sandbox_timeout,
                check=False,
            )
            raw = (wait.stdout or "").strip()
            if raw.lstrip("-").isdigit():
                exit_code = int(raw)
        except subprocess.TimeoutExpired:
            timed_out = True
            status = "timeout"
        except FileNotFoundError as exc:
            raise _BpftraceUnavailable("docker executable not found") from exc

        try:
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            stdout = logs.stdout or ""
            stderr = logs.stderr or ""
        except subprocess.TimeoutExpired:
            pass

        if bpftrace_proc is not None:
            _stop_bpftrace(bpftrace_proc)

        _docker_run(["docker", "stop", container_id], check=False, timeout=15)
    finally:
        _docker_run(["docker", "rm", "-f", container_id], check=False, timeout=15)

    trace_raw = ""
    if events_path is not None and events_path.exists():
        trace_raw = events_path.read_text(encoding="utf-8", errors="replace")
    trace_copy = run_path / "trace.log"
    trace_copy.write_text(trace_raw, encoding="utf-8")

    result = {
        "execution_status": status,
        "stdout": _tail(stdout, cfg.max_output_chars),
        "stderr": _tail(stderr, cfg.max_output_chars),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "trace_raw": _tail(trace_raw, cfg.max_output_chars * 4),
        "trace_log_path": str(trace_copy),
        "trace_method": "bpftrace_attach_failed" if attach_error else "bpftrace",
        "sandbox_workspace": str(sandbox_workspace),
        "sandbox_root": str(temp_dir),
        "container_id": container_id,
    }
    if attach_error:
        result["trace_method_fallback"] = attach_error
    return result


# ───────────────────────────── strace path ─────────────────────────────────────


def _run_in_sandbox_strace(
    command: str,
    workspace: Path,
    run_path: Path,
    cfg: SecurityFrameworkConfig,
) -> dict:
    temp_parent = Path(cfg.workspace_copy_parent)
    temp_parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix="shadow_workspace_", dir=temp_parent))
    sandbox_workspace = temp_dir / "workspace"
    sandbox_home = temp_dir / "home" / "sandbox"
    trace_host_path = temp_dir / "trace.log"
    _copy_workspace(workspace, sandbox_workspace)
    _create_dummy_home(sandbox_home)
    trace_host_path.touch()
    # The container writes the trace via a single-file bind mount; without
    # 0o666 the docker AppArmor profile rejects the open even as root in
    # the container, leaving the trace empty (verified empirically against
    # ubuntu host 2026-05-25).
    trace_host_path.chmod(0o666)

    shell_command = f"cd /workspace && {command}"
    if cfg.trace_mode == "strace":
        wrapped = (
            "if command -v strace >/dev/null 2>&1; then "
            f"strace -f -e trace=openat,execve,connect,unlink,rename -o /var/sandbox/trace.log bash -lc {shlex.quote(shell_command)}; "
            "else "
            "echo 'strace not found in sandbox image' >&2; "
            f"bash -lc {shlex.quote(shell_command)}; "
            "fi"
        )
    else:
        wrapped = f"bash -lc {shlex.quote(shell_command)}"

    docker_cmd = [
        "docker", "run", "--rm",
        "--network", cfg.sandbox_network_mode,
        # strace requires PTRACE_TRACEME; docker's default seccomp profile
        # blocks ptrace and strace exits silently with EPERM, leaving the
        # trace file empty. Granting SYS_PTRACE inside the sandbox is safe
        # — the container is throwaway and isolated.
        "--cap-add=SYS_PTRACE",
        "-v", f"{sandbox_workspace}:/workspace:rw",
        "-v", f"{sandbox_home}:/home/sandbox:rw",
        "-v", f"{trace_host_path}:/var/sandbox/trace.log:rw",
        "-e", "HOME=/home/sandbox",
        "-w", "/workspace",
        cfg.sandbox_docker_image,
        "bash", "-lc", wrapped,
    ]

    timed_out = False
    try:
        completed = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=cfg.sandbox_timeout,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        exit_code = completed.returncode
        status = "completed"
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        exit_code = None
        status = "timeout"
    except FileNotFoundError:
        stdout = ""
        stderr = "Docker executable was not found."
        exit_code = None
        status = "docker_unavailable"

    trace_raw = trace_host_path.read_text(encoding="utf-8", errors="replace") if trace_host_path.exists() else ""
    trace_copy = run_path / "trace.log"
    trace_copy.write_text(trace_raw, encoding="utf-8")

    return {
        "execution_status": status,
        "stdout": _tail(stdout, cfg.max_output_chars),
        "stderr": _tail(stderr, cfg.max_output_chars),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "trace_raw": _tail(trace_raw, cfg.max_output_chars * 4),
        "trace_log_path": str(trace_copy),
        "trace_method": "strace",
        "sandbox_workspace": str(sandbox_workspace),
        "sandbox_root": str(temp_dir),
        "docker_command": docker_cmd,
    }


# ───────────────────────────── public entrypoint ───────────────────────────────


def run_in_sandbox(
    command: str,
    workspace: str,
    run_dir: str | Path,
    config: SecurityFrameworkConfig | None = None,
) -> dict:
    """Run ``command`` inside a docker sandbox and collect a trace."""
    cfg = (config or SecurityFrameworkConfig.from_env()).resolve_paths()
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    workspace_path = Path(workspace).expanduser().resolve()

    if cfg.trace_mode == "bpftrace":
        try:
            return _run_in_sandbox_bpftrace(command, workspace_path, run_path, cfg)
        except _BpftraceUnavailable as exc:
            result = _run_in_sandbox_strace(command, workspace_path, run_path, cfg)
            result["trace_method"] = "strace"
            result["trace_method_fallback"] = str(exc)
            return result

    return _run_in_sandbox_strace(command, workspace_path, run_path, cfg)
