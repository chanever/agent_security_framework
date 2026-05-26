"""Verify the AgentSentinel-style event log formatter + process tree builder.

These tests anchor the LLM-facing presentation of the semantic trace. They do
NOT assert any enforcement behavior — the design choice is observation-only.
"""

from __future__ import annotations

import json

from security_framework import event_logger
from security_framework.evidence.evidence_builder import build_evidence_package
from security_framework.sandbox.trace_parser import parse_bpftrace_trace


def test_format_file_event_includes_pid_comm_path():
    line = event_logger.format_file_event({
        "pid": 200, "process": "python3", "path": "/etc/passwd", "operation": "open",
    })
    assert "Process 200" in line and "python3" in line and "/etc/passwd" in line


def test_format_lsm_event_marks_credential():
    line = event_logger.format_lsm_event({
        "hook": "security_file_open", "pid": 100, "comm": "bash",
        "path": "/home/sandbox/.ssh/id_rsa", "sensitivity": "credential",
    })
    assert "[LSM:security_file_open]" in line and "[CREDENTIAL]" in line


def test_build_process_tree_with_fork_edges_nests_children():
    process_execution = [
        {"pid": 100, "command": "bash", "parent_process": "init"},
        {"pid": 200, "command": "python3 setup.py", "parent_process": "bash"},
    ]
    tree = event_logger.build_process_tree(
        process_execution, fork_edges=[(100, 200)],
    )
    assert tree["pid"] == 100
    assert len(tree["children"]) == 1
    assert tree["children"][0]["pid"] == 200


def test_build_process_tree_synthetic_root_when_multiple_orphans():
    process_execution = [
        {"pid": 100, "command": "bash", "parent_process": "init"},
        {"pid": 300, "command": "curl", "parent_process": "shell"},
    ]
    tree = event_logger.build_process_tree(process_execution, fork_edges=[])
    assert tree["pid"] == 0 and tree["comm"] == "root"
    assert {c["pid"] for c in tree["children"]} == {100, 300}


def test_parse_bpftrace_trace_emits_formatted_events_and_tree():
    jsonl = "\n".join(json.dumps(rec) for rec in [
        {"type": "process_exec", "pid": 100, "ppid": 1, "comm": "bash", "uid": 1000, "ts": 1000},
        {"type": "process_fork", "ppid": 100, "pid": 200, "ts": 1400},
        {"type": "process_execve", "pid": 200, "comm": "bash",
         "filename": "/usr/bin/python3", "argv": "python3 setup.py", "ts": 1500},
        {"type": "file_open", "pid": 200, "comm": "python3",
         "path": "/home/sandbox/.ssh/id_rsa", "ts": 2000},
        {"type": "network_egress", "pid": 200, "comm": "python3",
         "destination": "140.82.112.3:443", "ts": 2200},
    ])
    out = parse_bpftrace_trace(jsonl)

    assert out["formatted_events"], "formatted_events must be populated"
    joined = "\n".join(out["formatted_events"])
    assert "/home/sandbox/.ssh/id_rsa" in joined
    assert "140.82.112.3:443" in joined
    assert "[LSM:security_file_open]" in joined
    assert "[CREDENTIAL]" in joined

    tree = out["process_tree"]
    # Fork edge 100→200 should nest 200 inside 100, leaving 100 as the root.
    assert tree["pid"] == 100
    child_pids = {c["pid"] for c in tree["children"]}
    assert 200 in child_pids


def test_evidence_builder_propagates_event_log_artifacts():
    trace = {
        "file_access": [],
        "process_execution": [{"pid": 100, "command": "bash"}],
        "network_activity": [],
        "lsm_events": [],
        "formatted_events": ["Process 100 (init) execute bash"],
        "process_tree": {"pid": 100, "comm": "init", "children": []},
    }
    evidence = build_evidence_package(
        user_task="probe",
        context={"cwd": "/tmp", "history": [], "step": 0},
        action={"type": "execute_command", "command": "bash"},
        classification={"external_env": False, "reasons": []},
        sandbox_result={"execution_status": "completed", "trace_method": "bpftrace"},
        semantic_trace=trace,
    )
    st = evidence["system_trace"]
    assert st["formatted_events"] == ["Process 100 (init) execute bash"]
    assert st["process_tree"]["pid"] == 100


def test_no_enforcement_artifacts_in_output():
    """Sanity — observation-only design must not surface any stop/terminate keys."""
    out = parse_bpftrace_trace("")
    for forbidden in ("terminate_process", "process_stop_policy", "enforcement"):
        for k in out:
            assert forbidden not in str(k)
