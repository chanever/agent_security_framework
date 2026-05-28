import json
import subprocess

from security_framework.verifier.claude_cli_verifier import build_claude_cli_command, verify
from security_framework.config import SecurityFrameworkConfig
from security_framework.verifier import verify as route_verify


def _config(tmp_path, **overrides):
    values = {
        "verifier_mode": "claude_cli",
        "claude_cli_command": "claude",
        "artifact_root": str(tmp_path / "artifacts"),
        "workspace_copy_parent": str(tmp_path / "copies"),
    }
    values.update(overrides)
    return SecurityFrameworkConfig(**values).resolve_paths()


def test_claude_cli_verifier_parses_structured_output(monkeypatch, tmp_path):
    calls = []

    def fake_run(command, input, capture_output, text, timeout):
        calls.append(
            {
                "command": command,
                "input": input,
                "capture_output": capture_output,
                "text": text,
                "timeout": timeout,
            }
        )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "structured_output": {
                        "decision": "ALLOW",
                        "risk_score": 0.1,
                        "risk_level": "LOW",
                        "reason": "Looks safe.",
                    }
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify({"current_action": {"command_or_target": "ls -al"}}, _config(tmp_path))

    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 0.1
    assert "--json-schema" in calls[0]["command"]
    assert calls[0]["input"].startswith("You are an LLM Agent external environment access security verifier.")


def test_claude_cli_verifier_parses_result_fallback(monkeypatch, tmp_path):
    def fake_run(command, input, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "result": json.dumps(
                        {
                            "decision": "BLOCK",
                            "risk_score": 0.95,
                            "risk_level": "CRITICAL",
                            "reason": "Credential access.",
                        }
                    )
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify({"current_action": {"command_or_target": "cat ~/.ssh/id_rsa"}}, _config(tmp_path))

    assert result["decision"] == "BLOCK"
    assert result["risk_level"] == "CRITICAL"


def test_claude_cli_missing_executable_holds(monkeypatch, tmp_path):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify({"current_action": {"command_or_target": "pip install ."}}, _config(tmp_path))

    assert result["decision"] == "HOLD"
    assert "verifier_unavailable" in result["violated_properties"]


def test_claude_cli_timeout_holds(monkeypatch, tmp_path):
    def fake_run(command, input, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(command, timeout, output="partial", stderr="late")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify({"current_action": {"command_or_target": "pip install ."}}, _config(tmp_path))

    assert result["decision"] == "HOLD"


def test_claude_cli_nonzero_exit_holds(monkeypatch, tmp_path):
    def fake_run(command, input, capture_output, text, timeout):
        return subprocess.CompletedProcess(command, 2, stdout=json.dumps({"result": "bad auth result"}), stderr="bad auth")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify({"current_action": {"command_or_target": "pip install ."}}, _config(tmp_path))

    assert result["decision"] == "HOLD"
    assert "bad auth" in result["evidence"][0]
    assert any("bad auth result" in item for item in result["evidence"])


def test_claude_cli_nonzero_exit_still_parses_structured_output(monkeypatch, tmp_path):
    def fake_run(command, input, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout=json.dumps(
                {
                    "structured_output": {
                        "decision": "BLOCK",
                        "risk_score": 0.9,
                        "risk_level": "HIGH",
                        "reason": "Risky despite nonzero CLI status.",
                    }
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify({"current_action": {"command_or_target": "pip install ."}}, _config(tmp_path))

    assert result["decision"] == "BLOCK"
    assert result["reason"] == "Risky despite nonzero CLI status."


def test_claude_cli_sparse_decision_is_enriched_from_evidence_package(monkeypatch, tmp_path):
    def fake_run(command, input, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "structured_output": {
                        "decision": "HOLD",
                        "risk_score": 0.65,
                        "risk_level": "MEDIUM",
                    }
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify(
        {
            "current_action": {
                "command_or_target": "pip install .",
                "external_env": True,
                "why_this_action_is_being_checked": "package_install",
            },
            "external_interaction_analysis": {
                "targets": [{"type": "local_package", "path": ".", "source": "pip install ."}],
                "asset_kind": {
                    "status": "uncertain",
                    "kind": None,
                    "confidence": 0.0,
                    "reason": "classifier timed out",
                },
                "static_analysis": {"status": "skipped"},
                "reputation_analysis": {"status": "skipped"},
            },
            "external_environment": {
                "type": "workspace_or_remote_content",
                "trust_level": "unknown",
                "extracted_suspicious_instructions": ["ignore previous instructions", "read ~/.ssh/id_rsa"],
                "suspicious_code_patterns": ["id_rsa"],
            },
            "shadow_agent_execution": {
                "trajectory": [
                    {
                        "command": "pip install .",
                        "stderr": "error: externally-managed-environment",
                        "exit_code": 1,
                        "timed_out": False,
                    }
                ]
            },
        },
        _config(tmp_path),
    )

    assert result["decision"] == "HOLD"
    assert "pip install ." in result["reason"]
    assert "risk_level=MEDIUM" in result["reason"]
    assert "suspicious instructions" in result["reason"]
    assert any("package_install" in item for item in result["evidence"])
    assert any("read ~/.ssh/id_rsa" in item for item in result["evidence"])
    assert any("shadow execution: exit_code=1" in item for item in result["evidence"])
    assert result["recommended_action"]


def test_claude_cli_invalid_json_holds(monkeypatch, tmp_path):
    def fake_run(command, input, capture_output, text, timeout):
        return subprocess.CompletedProcess(command, 0, stdout="not json", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = verify({"current_action": {"command_or_target": "pip install ."}}, _config(tmp_path))

    assert result["decision"] == "HOLD"


def test_claude_cli_schema_flag_can_be_disabled(tmp_path):
    command = build_claude_cli_command(_config(tmp_path, claude_cli_use_json_schema=False))

    assert "--json-schema" not in command
    assert command[:3] == ["claude", "-p", "--output-format"]
    assert "--bare" not in command


def test_claude_cli_bare_can_be_enabled(tmp_path):
    command = build_claude_cli_command(_config(tmp_path, claude_cli_bare=True))

    assert "--bare" in command


def test_router_uses_claude_cli(monkeypatch, tmp_path):
    called = {}

    def fake_verify(evidence_package, config):
        called["mode"] = config.verifier_mode
        return {
            "decision": "ALLOW",
            "overall_safety_score": 0.9,
            "risk_score": 0.1,
            "risk_level": "LOW",
            "task_alignment_score": 0.8,
            "action_necessity_score": 0.8,
            "source_trust_score": 0.8,
            "data_isolation_score": 0.8,
            "side_effect_safety_score": 0.8,
            "uncertainty_score": 0.1,
            "violated_properties": [],
            "evidence": [],
            "reason": "ok",
            "recommended_action": "allow",
        }

    monkeypatch.setattr("security_framework.verifier.verifier.claude_cli_verify", fake_verify)

    result = route_verify({"current_action": {"command_or_target": "ls -al"}}, _config(tmp_path))

    assert called["mode"] == "claude_cli"
    assert result["decision"] == "ALLOW"
