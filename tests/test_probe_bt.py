"""US-003 acceptance — probe.bt exists with required cgroup-scoped probes."""

from __future__ import annotations

from pathlib import Path

import pytest

PROBE_BT = Path(__file__).resolve().parent.parent / "probes" / "probe.bt"


@pytest.fixture(scope="module")
def probe_text() -> str:
    assert PROBE_BT.is_file(), f"probe.bt missing at {PROBE_BT}"
    return PROBE_BT.read_text(encoding="utf-8")


REQUIRED_PROBES = (
    "tracepoint:syscalls:sys_enter_execve",
    "tracepoint:sched:sched_process_exec",
    "tracepoint:sched:sched_process_fork",
    "tracepoint:sock:inet_sock_set_state",
    "kprobe:security_file_open",
    "tracepoint:syscalls:sys_enter_write",
)


def test_probe_bt_exists(probe_text):
    assert probe_text.strip(), "probe.bt is empty"


@pytest.mark.parametrize("probe", REQUIRED_PROBES)
def test_each_probe_is_declared(probe_text, probe):
    assert probe in probe_text, f"missing probe declaration: {probe}"


def test_cgroup_marker_present(probe_text):
    # At least every cgroup-scoped probe (5 of the 6) substitutes __CGROUP_ID__.
    assert probe_text.count("__CGROUP_ID__") >= 5, (
        "expected at least 5 __CGROUP_ID__ template markers"
    )


def test_sentinel_markers_present(probe_text):
    assert "__SENTINEL_PID__" in probe_text
    assert "__SENTINEL_FD__" in probe_text


def test_emits_known_event_types(probe_text):
    for kind in ("begin", "process_execve", "process_exec", "process_fork",
                 "network_egress", "file_open", "sentinel_ready"):
        assert f"\\\"type\\\":\\\"{kind}\\\"" in probe_text, (
            f"probe.bt should emit JSONL records with type={kind!r}"
        )
