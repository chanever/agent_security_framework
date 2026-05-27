"""Event log formatter — derived from AgentSentinel's tracer_event_analyzer pattern.

Converts the raw semantic events produced by ``trace_parser.parse_bpftrace_trace()``
into two LLM-friendly artifacts:

1. ``formatted_events`` — a list of one-line strings like
   ``"Process 200 (python3) read file /home/sandbox/.ssh/id_rsa"``. These mirror
   the structure AgentSentinel feeds to its per-event auditor LLM
   (``audit/tracer_event_analyzer.go``), but here they are only logged. No
   enforcement, no per-event LLM round-trip — the verifier batch-judges the
   full Evidence Package afterwards.

2. ``process_tree`` — a nested ``pid → {comm, children: […]}`` structure
   assembled from the ``process_exec`` / ``process_fork`` records. Same shape
   AgentSentinel passes to its LLM as ``### System Trace``.

This module is observation-only by design — the chanever architecture puts
enforcement at the safeguard gate (real-execution allow/block), so adding
in-band stops would only truncate the attack chain the verifier needs to see.
"""

from __future__ import annotations

from typing import Iterable


def format_file_event(event: dict) -> str:
    pid = event.get("pid") or event.get("ns_tgid") or "?"
    comm = event.get("process") or event.get("comm") or "unknown"
    path = event.get("path") or "?"
    op = event.get("operation") or "open"
    return f"Process {pid} ({comm}) {op} file {path}"


def format_process_event(event: dict) -> str:
    pid = event.get("pid") or "?"
    parent = event.get("parent_process") or "unknown"
    command = event.get("command") or event.get("filename") or "?"
    return f"Process {pid} (parent={parent}) execute {command}"


def format_network_event(event: dict) -> str:
    pid = event.get("pid") or "?"
    process = event.get("process") or "unknown"
    dest = event.get("destination") or "?"
    proto = event.get("method_or_protocol") or "connect"
    return f"Process {pid} ({process}) {proto} to {dest}"


def format_lsm_event(event: dict) -> str:
    hook = event.get("hook") or "lsm"
    pid = event.get("pid") or "?"
    comm = event.get("comm") or "unknown"
    path = event.get("path") or "?"
    sensitivity = event.get("sensitivity")
    base = f"[LSM:{hook}] Process {pid} ({comm}) open {path}"
    if sensitivity == "credential":
        base += " [CREDENTIAL]"
    return base


def format_events(semantic_trace: dict) -> list[str]:
    """Concatenate one-line descriptions for every event kind, preserving order."""
    lines: list[str] = []
    for ev in semantic_trace.get("process_execution") or []:
        lines.append(format_process_event(ev))
    for ev in semantic_trace.get("file_access") or []:
        lines.append(format_file_event(ev))
    for ev in semantic_trace.get("network_activity") or []:
        lines.append(format_network_event(ev))
    for ev in semantic_trace.get("lsm_events") or []:
        lines.append(format_lsm_event(ev))
    return lines


def build_process_tree(
    process_execution: Iterable[dict],
    fork_edges: Iterable[tuple[int, int]] = (),
) -> dict:
    """Assemble a pid → {comm, children, command} dict from exec + fork records.

    ``fork_edges`` is a ``(parent_pid, child_pid)`` iterable harvested from
    ``process_fork`` JSONL records. When no edges are supplied every observed
    pid becomes a top-level child of a synthetic root so the JSON shape stays
    consistent.
    """
    nodes: dict[int, dict] = {}
    for ev in process_execution:
        pid = ev.get("pid")
        if pid is None:
            continue
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            continue
        nodes[pid_int] = {
            "pid": pid_int,
            "comm": ev.get("parent_process") or ev.get("command") or "unknown",
            "command": ev.get("command"),
            "children": [],
        }

    for parent_pid, child_pid in fork_edges:
        try:
            parent_pid = int(parent_pid)
            child_pid = int(child_pid)
        except (TypeError, ValueError):
            continue
        if child_pid not in nodes:
            nodes[child_pid] = {
                "pid": child_pid,
                "comm": "unknown",
                "command": None,
                "children": [],
            }
        if parent_pid not in nodes:
            nodes[parent_pid] = {
                "pid": parent_pid,
                "comm": "unknown",
                "command": None,
                "children": [],
            }
        nodes[parent_pid]["children"].append(nodes[child_pid])

    placed_pids = {
        c["pid"]
        for n in nodes.values()
        for c in n["children"]
    }
    roots = [n for pid, n in nodes.items() if pid not in placed_pids]
    if len(roots) == 1:
        return roots[0]
    return {"pid": 0, "comm": "root", "command": None, "children": roots}


def enrich_semantic_trace(semantic_trace: dict, fork_edges: Iterable[tuple[int, int]] = ()) -> dict:
    """Return a copy of ``semantic_trace`` with formatted_events + process_tree added."""
    enriched = dict(semantic_trace)
    enriched["formatted_events"] = format_events(semantic_trace)
    enriched["process_tree"] = build_process_tree(
        semantic_trace.get("process_execution") or [],
        fork_edges,
    )
    return enriched
