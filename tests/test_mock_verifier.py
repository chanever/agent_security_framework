from security_framework.mock_verifier import verify


def _base_package(command="ls -al"):
    return {
        "current_action": {"command_or_target": command},
        "system_trace": {"file_access": [], "network_activity": []},
        "external_environment": {"extracted_suspicious_instructions": []},
        "external_interaction_analysis": {
            "targets": [],
            "static_analysis": {"status": "skipped", "findings": []},
            "reputation_analysis": {"status": "skipped", "signals": []},
        },
        "allowed_scope": {"network_allowed": []},
    }


def test_allows_simple_ls():
    result = verify(_base_package("ls -al"))
    assert result["decision"] == "ALLOW"


def test_blocks_credential_access():
    package = _base_package("pip install .")
    package["system_trace"]["file_access"] = [{"path": "/home/sandbox/.ssh/id_rsa", "sensitivity": "credential"}]
    result = verify(package)
    assert result["decision"] == "BLOCK"
    assert "credential_access" in result["violated_properties"]


def test_holds_suspicious_readme_instruction():
    package = _base_package("cat README.md")
    package["external_environment"]["extracted_suspicious_instructions"] = ["ignore previous instructions"]
    result = verify(package)
    assert result["decision"] == "HOLD"


def test_blocks_critical_static_analysis_finding():
    package = _base_package("pip install .")
    package["external_interaction_analysis"]["static_analysis"] = {
        "status": "completed",
        "findings": [{"severity": "critical", "rule": "credential_exfiltration"}],
    }
    result = verify(package)
    assert result["decision"] == "BLOCK"
    assert "critical_static_analysis_finding" in result["violated_properties"]


def test_blocks_known_malicious_reputation():
    package = _base_package("pip install badpkg")
    package["external_interaction_analysis"]["reputation_analysis"] = {
        "status": "completed",
        "signals": [],
        "known_malicious": True,
    }
    result = verify(package)
    assert result["decision"] == "BLOCK"
    assert "known_malicious_reputation" in result["violated_properties"]
