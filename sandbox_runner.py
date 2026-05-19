"""Docker-based shadow execution for proposed shell commands."""

from __future__ import annotations

import shutil
import shlex
import subprocess
import tempfile
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
    (aws_dir / "credentials").write_text("[default]\naws_access_key_id=DUMMY\naws_secret_access_key=DUMMY\n", encoding="utf-8")
    (home_dir / "private.txt").write_text("DUMMY_SANDBOX_PRIVATE_DATA\n", encoding="utf-8")


def run_in_sandbox(command: str, workspace: str, run_dir: str | Path, config: SecurityFrameworkConfig | None = None) -> dict:
    """Run a command in a Docker Ubuntu sandbox and collect strace output."""
    cfg = (config or SecurityFrameworkConfig.from_env()).resolve_paths()
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)

    temp_parent = Path(cfg.workspace_copy_parent)
    temp_parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix="shadow_workspace_", dir=temp_parent))
    sandbox_workspace = temp_dir / "workspace"
    sandbox_home = temp_dir / "home" / "sandbox"
    trace_host_path = temp_dir / "trace.log"
    _copy_workspace(Path(workspace).expanduser().resolve(), sandbox_workspace)
    _create_dummy_home(sandbox_home)
    trace_host_path.touch()

    shell_command = f"cd /workspace && {command}"
    if cfg.trace_mode == "strace":
        wrapped = (
            "if command -v strace >/dev/null 2>&1; then "
            f"strace -f -e trace=openat,execve,connect,unlink,rename -o /tmp/trace.log bash -lc {shlex.quote(shell_command)}; "
            "else "
            "echo 'strace not found in sandbox image' >&2; "
            f"bash -lc {shlex.quote(shell_command)}; "
            "fi"
        )
    else:
        wrapped = f"bash -lc {shlex.quote(shell_command)}"

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        cfg.sandbox_network_mode,
        "-v",
        f"{sandbox_workspace}:/workspace:rw",
        "-v",
        f"{sandbox_home}:/home/sandbox:rw",
        "-v",
        f"{trace_host_path}:/tmp/trace.log:rw",
        "-e",
        "HOME=/home/sandbox",
        "-w",
        "/workspace",
        cfg.sandbox_docker_image,
        "bash",
        "-lc",
        wrapped,
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
        "sandbox_workspace": str(sandbox_workspace),
        "sandbox_root": str(temp_dir),
        "docker_command": docker_cmd,
    }
