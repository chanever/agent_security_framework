import json

from security_framework.claude_verifier import normalize_verifier_result, verify
from security_framework.config import SecurityFrameworkConfig
from security_framework.verifier import verify as route_verify


def _config(tmp_path):
    return SecurityFrameworkConfig(
        verifier_mode="claude",
        claude_api_key="test-key",
        claude_api_url="https://example.invalid/v1/messages",
        artifact_root=str(tmp_path / "artifacts"),
        workspace_copy_parent=str(tmp_path / "copies"),
    ).resolve_paths()


def test_normalizes_invalid_decision_to_hold():
    result = normalize_verifier_result({"decision": "maybe", "risk_score": 0.7})

    assert result["decision"] == "HOLD"
    assert result["risk_level"] == "MEDIUM"


def test_missing_claude_api_key_holds(tmp_path):
    cfg = SecurityFrameworkConfig(
        verifier_mode="claude",
        claude_api_key="",
        artifact_root=str(tmp_path / "artifacts"),
        workspace_copy_parent=str(tmp_path / "copies"),
    )

    result = verify({"current_action": {"command_or_target": "pip install ."}}, cfg)

    assert result["decision"] == "HOLD"
    assert "verifier_unavailable" in result["violated_properties"]


def test_claude_verifier_parses_json_response(monkeypatch, tmp_path):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "decision": "ALLOW",
                                    "risk_score": 0.1,
                                    "risk_level": "LOW",
                                    "reason": "Looks safe.",
                                }
                            ),
                        }
                    ]
                }
            ).encode("utf-8")

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: FakeResponse())

    result = verify({"current_action": {"command_or_target": "ls -al"}}, _config(tmp_path))

    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 0.1


def test_router_uses_mock_by_default():
    result = route_verify(
        {
            "current_action": {"command_or_target": "ls -al"},
            "system_trace": {"file_access": [], "network_activity": []},
            "external_environment": {"extracted_suspicious_instructions": []},
            "external_interaction_analysis": {
                "static_analysis": {"findings": []},
                "reputation_analysis": {"signals": []},
            },
            "allowed_scope": {"network_allowed": []},
        }
    )

    assert result["decision"] == "ALLOW"
