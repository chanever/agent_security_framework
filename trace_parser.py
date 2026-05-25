"""Parse sandbox trace output into semantic security events.

Two formats are supported:

* ``parse_trace(trace_raw)`` — legacy strace text output. ``lsm_events`` is
  always empty here because strace operates above the LSM layer.
* ``parse_bpftrace_trace(trace_jsonl)`` — bpftrace JSONL emitted by
  ``probes/probe.bt``. ``lsm_events`` is populated from the cgroup-scoped
  ``kprobe:security_file_open`` records (LSM hook function observation).

``parse_trace_auto(trace_raw, trace_method)`` dispatches to the right parser.
"""

from __future__ import annotations

import json
import re

from security_framework import policy


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


# ─────────────────────────── bpftrace JSONL parser ─────────────────────────────


def parse_bpftrace_trace(trace_jsonl: str) -> dict:
    """Parse the JSONL emitted by ``probes/probe.bt`` into semantic events.

    The probe emits one JSON object per line for each of:
      - ``process_exec`` / ``process_execve`` → ``process_execution``
      - ``network_egress``                     → ``network_activity``
      - ``file_open``                          → ``file_access`` **and** ``lsm_events``
      - ``process_fork`` / ``begin`` / ``sentinel_ready`` → structural-only (not emitted)

    ``lsm_events`` is the canonical "real LSM hook observation" array that the
    placeholder strace parser cannot populate.
    """
    file_access: list[dict] = []
    process_execution: list[dict] = []
    network_activity: list[dict] = []
    lsm_events: list[dict] = []
    fork_edges: list[tuple[int, int]] = []

    for line in trace_jsonl.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        rtype = rec.get("type")

        if rtype == "process_exec":
            comm = rec.get("comm") or "unknown"
            process_execution.append(
                {
                    "command": comm,
                    "pid": rec.get("pid"),
                    "ppid": rec.get("ppid"),
                    "uid": rec.get("uid"),
                    "parent_process": "unknown",
                    "status": "observed",
                    "related_to_user_task": True,
                }
            )
        elif rtype == "process_execve":
            argv = rec.get("argv") or ""
            process_execution.append(
                {
                    "command": argv.strip() or rec.get("filename", "unknown"),
                    "pid": rec.get("pid"),
                    "filename": rec.get("filename"),
                    "parent_process": rec.get("comm") or "unknown",
                    "status": "observed",
                    "related_to_user_task": True,
                }
            )
        elif rtype == "network_egress":
            network_activity.append(
                {
                    "destination": rec.get("destination") or "unknown",
                    "method_or_protocol": "tcp_connect",
                    "process": rec.get("comm") or "unknown",
                    "pid": rec.get("pid"),
                    "status": "observed",
                    "related_to_user_task": False,
                }
            )
        elif rtype == "file_open":
            path = rec.get("path") or ""
            sensitivity = (
                "credential" if path and policy.is_sensitive_path(path) else "normal"
            )
            file_access.append(
                {
                    "path": path,
                    "operation": "open",
                    "process": rec.get("comm") or "unknown",
                    "pid": rec.get("pid"),
                    "status": "observed",
                    "sensitivity": sensitivity,
                    "related_to_user_task": not policy.is_sensitive_path(path),
                }
            )
            lsm_events.append(
                {
                    "hook": "security_file_open",
                    "path": path,
                    "pid": rec.get("pid"),
                    "comm": rec.get("comm"),
                    "ts": rec.get("ts"),
                    "sensitivity": sensitivity,
                }
            )
        elif rtype == "process_fork":
            try:
                parent_pid = int(rec.get("ppid"))
                child_pid = int(rec.get("pid"))
            except (TypeError, ValueError):
                continue
            fork_edges.append((parent_pid, child_pid))
        # begin / sentinel_ready are structural; do not surface.

    from security_framework.event_logger import enrich_semantic_trace
    return enrich_semantic_trace(
        {
            "file_access": file_access,
            "process_execution": process_execution,
            "network_activity": network_activity,
            "lsm_events": lsm_events,
        },
        fork_edges=fork_edges,
    )


def parse_trace_auto(trace_raw: str, trace_method: str = "strace") -> dict:
    """Dispatch to the right parser based on the trace method recorded.

    ``trace_method`` follows the same vocabulary as
    :attr:`security_framework.config.SecurityFrameworkConfig.trace_mode`.
    Unknown methods fall back to the strace parser (graceful degrade).
    """
    if trace_method == "bpftrace":
        return parse_bpftrace_trace(trace_raw)
    return parse_trace(trace_raw)
