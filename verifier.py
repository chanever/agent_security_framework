"""Verifier router for mock and Claude-backed decisions."""

from __future__ import annotations

from security_framework.config import SecurityFrameworkConfig


def _hold_unknown_mode(mode: str) -> dict:
    return {
        "decision": "HOLD",
        "overall_safety_score": 0.35,
        "risk_score": 0.65,
        "risk_level": "MEDIUM",
        "task_alignment_score": 0.5,
        "action_necessity_score": 0.5,
        "source_trust_score": 0.2,
        "data_isolation_score": 0.5,
        "side_effect_safety_score": 0.4,
        "uncertainty_score": 0.9,
        "violated_properties": ["unknown_verifier_mode"],
        "evidence": [f"Unsupported VERIFIER_MODE: {mode}"],
        "reason": "Unsupported verifier mode.",
        "recommended_action": "Hold this command until verifier configuration is corrected.",
    }


def verify(evidence_package: dict, config: SecurityFrameworkConfig | None = None) -> dict:
    """Dispatch Evidence Package verification to the configured verifier."""
    cfg = config or SecurityFrameworkConfig.from_env()
    mode = (cfg.verifier_mode or "mock").lower()
    if mode == "mock":
        from security_framework.mock_verifier import verify as mock_verify

        return mock_verify(evidence_package)
    if mode == "claude":
        from security_framework.claude_verifier import verify as claude_verify

        return claude_verify(evidence_package, cfg)
    if mode == "claude_cli":
        from security_framework.claude_cli_verifier import verify as claude_cli_verify

        return claude_cli_verify(evidence_package, cfg)
    return _hold_unknown_mode(mode)
