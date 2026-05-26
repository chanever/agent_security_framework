"""US-006 acceptance — static_analyzer drives semgrep via the docker wrapper."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from security_framework import static_analyzer
from security_framework.config import SecurityFrameworkConfig


FIXTURE = Path(__file__).parent / "fixtures" / "eval_pkg"


SAMPLE_SEMGREP_JSON = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected.exec-detected",
            "path": "/src/vuln.py",
            "start": {"line": 12, "col": 5},
            "end": {"line": 12, "col": 30},
            "extra": {
                "severity": "ERROR",
                "message": "Detected use of eval(). This is dangerous.",
                "metadata": {"category": "security"},
            },
        },
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "/src/vuln.py",
            "start": {"line": 22, "col": 5},
            "end": {"line": 22, "col": 50},
            "extra": {
                "severity": "WARNING",
                "message": "Detected subprocess call with shell=True.",
            },
        },
    ],
    "errors": [],
})


def _cfg(tmp_path: Path) -> SecurityFrameworkConfig:
    return SecurityFrameworkConfig(
        semgrep_image="semgrep/semgrep:latest",
        semgrep_rules="p/security-audit",
        semgrep_timeout=30,
        workspace_copy_parent=str(tmp_path / "shadow_parent"),
    )


def test_skipped_when_external_env_false():
    res = static_analyzer.analyze_static(
        action={"type": "command", "command": "ls"},
        context={"cwd": str(FIXTURE)},
        targets=[],
        classification={"external_env": False, "reasons": []},
    )
    assert res["status"] == "skipped"
    assert res["findings"] == []


def test_skipped_when_no_code_target_and_empty_workspace(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = static_analyzer.analyze_static(
        action={"type": "command", "command": "git clone https://example.com/repo"},
        context={"cwd": str(empty)},
        targets=[{"type": "url", "url": "https://example.com/repo", "source": ""}],
        classification={"external_env": True, "reasons": []},
    )
    assert res["status"] == "skipped"


def test_success_with_mocked_semgrep_docker(monkeypatch, tmp_path: Path):
    """Headline contract — mocked docker semgrep → status=success, normalized findings."""
    docker_calls: list[list[str]] = []

    class _FakeCompleted:
        def __init__(self):
            self.stdout = SAMPLE_SEMGREP_JSON
            self.stderr = ""
            self.returncode = 1  # semgrep returns nonzero when findings exist

    def fake_run(cmd, *args, **kwargs):
        docker_calls.append(list(cmd))
        return _FakeCompleted()

    from security_framework.static_analyzers import pypi_analyzer as _pypi_analyzer_mod; monkeypatch.setattr(_pypi_analyzer_mod.subprocess, "run", fake_run)

    res = static_analyzer.analyze_static(
        action={"type": "command", "command": "pip install ."},
        context={"cwd": str(FIXTURE)},
        targets=[{"type": "local_package", "path": ".", "source": "pip install ."}],
        classification={"external_env": True, "reasons": ["package_install"]},
        config=_cfg(tmp_path),
    )
    assert res["status"] == "success"
    assert len(res["findings"]) == 2
    for f in res["findings"]:
        assert {"rule_id", "severity", "path", "line", "message", "source"} <= set(f)
        assert f["source"] == "semgrep"
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert f["path"].startswith("vuln.py") or f["path"].endswith("vuln.py")
    severities = [f["severity"] for f in res["findings"]]
    assert "HIGH" in severities and "MEDIUM" in severities

    assert "Semgrep found 2 findings" in res["summary"]

    # Docker invocation shape: rules/image/scan-root present.
    assert docker_calls, "docker run was not invoked"
    invocation = docker_calls[0]
    assert invocation[0] == "docker" and invocation[1] == "run"
    assert "semgrep/semgrep:latest" in invocation
    assert "--config" in invocation
    assert "p/security-audit" in invocation


def test_unavailable_when_docker_missing(monkeypatch, tmp_path: Path):
    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError("docker")

    from security_framework.static_analyzers import pypi_analyzer as _pypi_analyzer_mod; monkeypatch.setattr(_pypi_analyzer_mod.subprocess, "run", fake_run)
    res = static_analyzer.analyze_static(
        action={"type": "command", "command": "pip install ."},
        context={"cwd": str(FIXTURE)},
        targets=[{"type": "local_package", "path": ".", "source": ""}],
        classification={"external_env": True, "reasons": []},
        config=_cfg(tmp_path),
    )
    assert res["status"] == "unavailable"
    assert "docker" in res["summary"].lower()


def test_unavailable_when_semgrep_returns_empty_stdout(monkeypatch, tmp_path: Path):
    class _FakeCompleted:
        stdout = ""
        stderr = "Error: image pull failed"
        returncode = 125

    from security_framework.static_analyzers import pypi_analyzer as _pypi_analyzer_mod
    monkeypatch.setattr(
        _pypi_analyzer_mod.subprocess, "run", lambda *a, **k: _FakeCompleted(),
    )
    res = static_analyzer.analyze_static(
        action={"type": "command", "command": "pip install ."},
        context={"cwd": str(FIXTURE)},
        targets=[{"type": "local_package", "path": ".", "source": ""}],
        classification={"external_env": True, "reasons": []},
        config=_cfg(tmp_path),
    )
    assert res["status"] == "unavailable"


def test_unavailable_on_timeout(monkeypatch, tmp_path: Path):
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=30)

    from security_framework.static_analyzers import pypi_analyzer as _pypi_analyzer_mod; monkeypatch.setattr(_pypi_analyzer_mod.subprocess, "run", fake_run)
    res = static_analyzer.analyze_static(
        action={"type": "command", "command": "pip install ."},
        context={"cwd": str(FIXTURE)},
        targets=[{"type": "local_package", "path": ".", "source": ""}],
        classification={"external_env": True, "reasons": []},
        config=_cfg(tmp_path),
    )
    assert res["status"] == "unavailable"
    assert "timed out" in res["summary"]


def test_resolve_scan_root_rejects_path_escape(monkeypatch, tmp_path: Path):
    """A local_package target pointing outside cwd must NOT become the scan root."""
    inside = tmp_path / "ws"
    inside.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "secret.py").write_text("# not the agent's workspace\n", encoding="utf-8")

    scan_root = static_analyzer._resolve_scan_root(
        action={"type": "command", "command": "pip install ../elsewhere"},
        context={"cwd": str(inside)},
        targets=[{"type": "local_package", "path": "../elsewhere", "source": ""}],
    )
    # Escaping target is dropped; falls back to cwd.
    assert scan_root == inside.resolve()


def test_severity_normalization():
    raw = {
        "check_id": "demo.rule",
        "path": "/src/x.py",
        "start": {"line": 7},
        "extra": {"severity": "INFO", "message": "low-confidence"},
    }
    f = static_analyzer._normalize_finding(raw, Path("/tmp"))
    assert f["severity"] == "LOW"
    assert f["path"] == "x.py"
    assert f["line"] == 7


@pytest.mark.skipif(
    shutil.which("docker") is None or os.environ.get("SEMGREP_LIVE") != "1",
    reason="Live semgrep run gated on docker + SEMGREP_LIVE=1",
)
def test_live_semgrep_against_fixture(tmp_path: Path):
    """Actually pulls semgrep/semgrep:latest and scans the eval_pkg fixture.

    Gated to off-by-default — set ``SEMGREP_LIVE=1`` to run.
    """
    res = static_analyzer.analyze_static(
        action={"type": "command", "command": "pip install ."},
        context={"cwd": str(FIXTURE)},
        targets=[{"type": "local_package", "path": ".", "source": ""}],
        classification={"external_env": True, "reasons": ["package_install"]},
        config=_cfg(tmp_path),
    )
    assert res["status"] == "success"
    assert res["findings"], "semgrep p/security-audit should flag the fixture"
    paths = {f["path"] for f in res["findings"]}
    assert any("vuln.py" in p for p in paths)
