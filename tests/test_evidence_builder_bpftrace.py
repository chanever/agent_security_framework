"""US-005 acceptance — evidence_builder flows lsm_events + trace_method through."""

from __future__ import annotations

from security_framework.evidence_builder import build_evidence_package


def _semantic_trace_with_lsm() -> dict:
    return {
        "file_access": [
            {"path": "/etc/passwd", "operation": "open", "process": "bash",
             "status": "observed", "sensitivity": "credential",
             "related_to_user_task": False},
        ],
        "process_execution": [
            {"command": "bash", "pid": 100, "parent_process": "unknown",
             "status": "observed", "related_to_user_task": True},
        ],
        "network_activity": [
            {"destination": "140.82.112.3:443", "method_or_protocol": "tcp_connect",
             "process": "python3", "status": "observed",
             "related_to_user_task": False},
        ],
        "lsm_events": [
            {"hook": "security_file_open", "path": "/etc/passwd", "pid": 100,
             "comm": "bash", "ts": 123, "sensitivity": "credential"},
            {"hook": "security_file_open", "path": "/home/sandbox/.ssh/id_rsa",
             "pid": 200, "comm": "python3", "ts": 456, "sensitivity": "credential"},
        ],
    }


def test_lsm_events_flow_into_system_trace():
    sandbox_result = {
        "execution_status": "completed",
        "stdout": "",
        "stderr": "",
        "exit_code": 0,
        "timed_out": False,
        "trace_method": "bpftrace",
    }
    evidence = build_evidence_package(
        user_task="inspect filesystem",
        context={"cwd": "/tmp/ws", "history": [], "step": 1},
        action={"type": "execute_command", "command": "ls /", "reason": "list root"},
        classification={"external_env": False, "reasons": []},
        sandbox_result=sandbox_result,
        semantic_trace=_semantic_trace_with_lsm(),
    )
    lsm = evidence["system_trace"]["lsm_events"]
    assert lsm, "lsm_events must propagate from semantic_trace to system_trace"
    assert len(lsm) == 2
    assert {e["path"] for e in lsm} == {"/etc/passwd", "/home/sandbox/.ssh/id_rsa"}
    for ev in lsm:
        assert ev["hook"] == "security_file_open"


def test_trace_method_flows_into_shadow_agent_execution():
    sandbox_result = {
        "execution_status": "completed",
        "trace_method": "bpftrace",
        "stdout": "", "stderr": "", "exit_code": 0, "timed_out": False,
    }
    evidence = build_evidence_package(
        user_task="probe", context={"cwd": "/tmp", "history": [], "step": 0},
        action={"type": "execute_command", "command": "ls"},
        classification={"external_env": False, "reasons": []},
        sandbox_result=sandbox_result,
        semantic_trace=_semantic_trace_with_lsm(),
    )
    assert evidence["shadow_agent_execution"]["trace_method"] == "bpftrace"


def test_trace_method_fallback_recorded_when_present():
    sandbox_result = {
        "execution_status": "completed",
        "trace_method": "strace",
        "trace_method_fallback": "cgroup-v1-only host",
        "stdout": "", "stderr": "", "exit_code": 0, "timed_out": False,
    }
    evidence = build_evidence_package(
        user_task="probe", context={"cwd": "/tmp", "history": [], "step": 0},
        action={"type": "execute_command", "command": "ls"},
        classification={"external_env": False, "reasons": []},
        sandbox_result=sandbox_result,
        semantic_trace={"file_access": [], "process_execution": [],
                        "network_activity": [], "lsm_events": []},
    )
    shadow = evidence["shadow_agent_execution"]
    assert shadow["trace_method"] == "strace"
    assert shadow["trace_method_fallback"] == "cgroup-v1-only host"


def test_default_trace_method_is_strace_when_sandbox_lacks_key():
    """Backward-compat — old sandbox_result dicts (no trace_method key) report 'strace'."""
    sandbox_result = {
        "execution_status": "completed",
        "stdout": "", "stderr": "", "exit_code": 0, "timed_out": False,
    }
    evidence = build_evidence_package(
        user_task="probe", context={"cwd": "/tmp", "history": [], "step": 0},
        action={"type": "execute_command", "command": "ls"},
        classification={"external_env": False, "reasons": []},
        sandbox_result=sandbox_result,
        semantic_trace=None,
    )
    assert evidence["shadow_agent_execution"]["trace_method"] == "strace"
    assert evidence["system_trace"]["lsm_events"] == []


def test_credential_lsm_path_surfaces_notable_behavior():
    """An LSM-observed credential open should still trip the credential_file_access flag.

    The notable_behavior calculation reads from file_access (not lsm_events), so this
    confirms the bpftrace path's dual-population (file_access AND lsm_events) is
    enough to keep the legacy heuristic working without code changes elsewhere.
    """
    evidence = build_evidence_package(
        user_task="probe", context={"cwd": "/tmp", "history": [], "step": 0},
        action={"type": "execute_command", "command": "cat /etc/passwd"},
        classification={"external_env": False, "reasons": []},
        sandbox_result={"execution_status": "completed", "trace_method": "bpftrace"},
        semantic_trace=_semantic_trace_with_lsm(),
    )
    nb = evidence["shadow_agent_execution"]["notable_behavior"]
    assert "credential_file_access_observed" in nb
    assert "network_activity_observed" in nb
