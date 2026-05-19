from security_framework.trigger import classify_command


def test_safe_ls_does_not_need_shadow_execution():
    result = classify_command("ls -al")
    assert result["risk_level"] == "low"
    assert result["needs_shadow_execution"] is False


def test_pip_install_needs_shadow_execution():
    result = classify_command("pip install .")
    assert result["outside_env"] is True
    assert "package_install" in result["reasons"]
    assert result["needs_shadow_execution"] is True


def test_rm_rf_blocks_immediately():
    result = classify_command("rm -rf /tmp/example")
    assert result["block_immediately"] is True
    assert result["risk_level"] == "critical"
