"""US-004 acceptance — bpftrace JSONL parser populates lsm_events."""

from __future__ import annotations

import json

from security_framework.sandbox.trace_parser import (
    parse_bpftrace_trace,
    parse_trace,
    parse_trace_auto,
)


SAMPLE_JSONL = "\n".join(
    json.dumps(rec)
    for rec in [
        {"type": "begin", "ts": 0},
        {"type": "process_exec", "pid": 100, "ppid": 1, "comm": "bash",
         "uid": 1000, "ts": 1000},
        {"type": "process_execve", "pid": 200, "comm": "bash",
         "filename": "/usr/bin/python3",
         "argv": "python3 /workspace/setup.py install", "ts": 1500},
        {"type": "process_fork", "ppid": 100, "pid": 200, "ts": 1400},
        {"type": "network_egress", "pid": 200, "comm": "python3",
         "destination": "140.82.112.3:443", "ts": 2000},
        {"type": "file_open", "pid": 100, "comm": "bash",
         "path": "/etc/passwd", "ts": 2100},
        {"type": "file_open", "pid": 200, "comm": "python3",
         "path": "/home/sandbox/.ssh/id_rsa", "ts": 2200},
        {"type": "sentinel_ready", "pid": 99999, "ts": 0},
    ]
)


def test_lsm_events_populated_from_file_open():
    """Headline contract — lsm_events must not be empty when file_open records exist."""
    out = parse_bpftrace_trace(SAMPLE_JSONL)
    assert out["lsm_events"], "lsm_events must be populated from file_open records"
    assert len(out["lsm_events"]) == 2
    for ev in out["lsm_events"]:
        assert ev["hook"] == "security_file_open"
        assert "path" in ev and "pid" in ev


def test_credential_path_marked_sensitive():
    out = parse_bpftrace_trace(SAMPLE_JSONL)
    ssh_lsm = [e for e in out["lsm_events"] if e["path"].endswith("id_rsa")]
    assert ssh_lsm and ssh_lsm[0]["sensitivity"] == "credential"


def test_network_egress_destination_preserved():
    out = parse_bpftrace_trace(SAMPLE_JSONL)
    assert any(
        e["destination"] == "140.82.112.3:443" for e in out["network_activity"]
    )


def test_process_exec_and_execve_both_surface():
    out = parse_bpftrace_trace(SAMPLE_JSONL)
    commands = [p["command"] for p in out["process_execution"]]
    assert any("python3 /workspace/setup.py install" in c for c in commands)
    assert any(c == "bash" for c in commands)


def test_structural_records_not_emitted_as_events():
    """begin / process_fork / sentinel_ready must not pollute event arrays."""
    out = parse_bpftrace_trace(SAMPLE_JSONL)
    for arr in (out["file_access"], out["process_execution"], out["network_activity"], out["lsm_events"]):
        for item in arr:
            assert "begin" not in str(item)
            assert "sentinel_ready" not in str(item)


def test_malformed_lines_are_ignored():
    junk = SAMPLE_JSONL + "\nAttaching 6 probes...\nnot-json\n{broken json"
    out = parse_bpftrace_trace(junk)
    # Same event counts as the clean fixture — junk silently dropped.
    assert len(out["lsm_events"]) == 2


def test_parse_trace_strace_path_lsm_remains_empty():
    """Backward-compat — strace parser still emits lsm_events: []."""
    out = parse_trace('openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n')
    assert out["lsm_events"] == []


def test_dispatcher_routes_to_bpftrace():
    out = parse_trace_auto(SAMPLE_JSONL, trace_method="bpftrace")
    assert out["lsm_events"]  # non-empty


def test_dispatcher_defaults_to_strace():
    strace_text = 'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\n'
    out = parse_trace_auto(strace_text, trace_method="strace")
    assert out["file_access"] and out["lsm_events"] == []


def test_dispatcher_unknown_method_defaults_to_strace():
    out = parse_trace_auto("openat(...)", trace_method="nonexistent")
    assert "lsm_events" in out and out["lsm_events"] == []
