"""Parse strace output into semantic security events."""

from __future__ import annotations

import re

from security_framework.evidence import policy


PATH_ARG_RE = re.compile(r'"([^"]+)"')
EXECVE_RE = re.compile(r'execve\("([^"]+)",\s*\[([^\]]*)\]')
CONNECT_RE = re.compile(r"\bconnect\(")


def _operation_for_line(line: str) -> str:
    if "unlink" in line:
        return "delete"
    if "rename" in line:
        return "rename"
    if "O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line:
        return "write"
    return "read"


def parse_trace(trace_raw: str) -> dict:
    """Extract file, process, and network events from a raw strace log."""
    file_access = []
    process_execution = []
    network_activity = []

    for line in trace_raw.splitlines():
        if "openat(" in line or "unlink(" in line or "rename(" in line:
            for path in PATH_ARG_RE.findall(line):
                if path in {"AT_FDCWD"} or not path.startswith(("/", ".")):
                    continue
                sensitivity = "credential" if policy.is_sensitive_path(path) else "normal"
                file_access.append(
                    {
                        "path": path,
                        "operation": _operation_for_line(line),
                        "process": "unknown",
                        "status": "observed",
                        "sensitivity": sensitivity,
                        "related_to_user_task": not policy.is_sensitive_path(path),
                    }
                )

        exec_match = EXECVE_RE.search(line)
        if exec_match:
            executable = exec_match.group(1)
            args_blob = exec_match.group(2)
            args = PATH_ARG_RE.findall(args_blob)
            process_execution.append(
                {
                    "command": " ".join(args) if args else executable,
                    "parent_process": "unknown",
                    "status": "observed",
                    "related_to_user_task": True,
                }
            )

        if CONNECT_RE.search(line):
            network_activity.append(
                {
                    "destination": "unknown",
                    "method_or_protocol": "connect",
                    "process": "unknown",
                    "status": "observed",
                    "related_to_user_task": False,
                }
            )

    return {
        "file_access": file_access,
        "process_execution": process_execution,
        "network_activity": network_activity,
        "lsm_events": [],
    }
