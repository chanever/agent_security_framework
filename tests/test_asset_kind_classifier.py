import json
import subprocess

from security_framework.classification.asset_kind_classifier import classify_asset_kind
from security_framework.config import SecurityFrameworkConfig


def _config(tmp_path, **values):
    defaults = {
        "artifact_root": str(tmp_path / "artifacts"),
        "workspace_copy_parent": str(tmp_path / "copies"),
    }
    defaults.update(values)
    return SecurityFrameworkConfig(**defaults).resolve_paths()


def _fake_cli(monkeypatch, kind: str, confidence: float = 0.95):
    def fake_run(command, input, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "structured_output": {
                        "kind": kind,
                        "confidence": confidence,
                        "reason": f"classified as {kind}",
                        "evidence": [kind],
                    }
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)


def test_claude_cli_classifies_package(monkeypatch, tmp_path):
    _fake_cli(monkeypatch, "package")
    result = classify_asset_kind(
        {"type": "command", "command": "pip install ."},
        {"task": "install"},
        {"external_env": True, "reasons": ["package_install"]},
        [{"type": "local_package", "path": ".", "source": "pip install ."}],
        _config(tmp_path),
    )

    assert result["status"] == "completed"
    assert result["kind"] == "package"


def test_claude_cli_classifies_repository(monkeypatch, tmp_path):
    _fake_cli(monkeypatch, "repository")
    result = classify_asset_kind(
        {"type": "command", "command": "git clone https://example.com/repo.git"},
        {"task": "clone"},
        {"external_env": True, "reasons": ["git_clone"]},
        [{"type": "repo", "url": "https://example.com/repo.git"}],
        _config(tmp_path),
    )

    assert result["status"] == "completed"
    assert result["kind"] == "repository"


def test_claude_cli_classifies_agent_skill(monkeypatch, tmp_path):
    _fake_cli(monkeypatch, "agent_skill")
    result = classify_asset_kind(
        {"type": "command", "command": "cat skill.md"},
        {"task": "read skill"},
        {"external_env": True, "reasons": ["skill_file_read"]},
        [],
        _config(tmp_path),
    )

    assert result["status"] == "completed"
    assert result["kind"] == "agent_skill"


def test_non_external_action_is_skipped(tmp_path):
    result = classify_asset_kind(
        {"type": "command", "command": "ls -al"},
        {"task": "list"},
        {"external_env": False, "reasons": ["local_command"]},
        [],
        _config(tmp_path),
    )

    assert result["status"] == "skipped"
    assert result["kind"] is None


def test_claude_cli_low_confidence_is_uncertain(monkeypatch, tmp_path):
    _fake_cli(monkeypatch, "package", confidence=0.2)
    result = classify_asset_kind(
        {"type": "command", "command": "pip install ."},
        {"task": "install"},
        {"external_env": True, "reasons": ["package_install"]},
        [],
        _config(tmp_path, asset_kind_classifier_confidence_threshold=0.6),
    )

    assert result["status"] == "uncertain"
    assert result["kind"] is None
