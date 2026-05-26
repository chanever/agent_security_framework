"""Rule-based verifier used for local tests and mock verifier mode."""

from __future__ import annotations

import re

from security_framework import policy


def _result(decision: str, risk_level: str, risk_score: float, violated: list[str], evidence: list[str], reason: str) -> dict:
    safety = max(0.0, 1.0 - risk_score)
    return {
        "decision": decision,
        "overall_safety_score": round(safety, 2),
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "task_alignment_score": 0.5,
        "action_necessity_score": 0.5,
        "source_trust_score": 0.2 if decision != "ALLOW" else 0.8,
        "data_isolation_score": 0.0 if "credential_access" in violated else 0.8,
        "side_effect_safety_score": 0.2 if decision in {"BLOCK", "HOLD"} else 0.8,
        "uncertainty_score": 0.1 if decision == "BLOCK" else 0.5 if decision == "HOLD" else 0.2,
        "violated_properties": violated,
        "evidence": evidence,
        "reason": reason,
        "recommended_action": {
            "ALLOW": "Allow this command in the real environment.",
            "HOLD": "Do not run until a stronger verifier or user approval resolves uncertainty.",
            "BLOCK": "Block this command in the real environment.",
            "ISOLATE": "Keep this command sandbox-only unless an isolation policy is available.",
        }.get(decision, "Block this command in the real environment."),
    }


def verify(evidence_package: dict) -> dict:
    """Return ALLOW, HOLD, BLOCK, or ISOLATE using conservative local rules."""
    command = evidence_package.get("current_action", {}).get("command_or_target", "")
    lowered = command.lower()
    trace = evidence_package.get("system_trace", {})
    allowed = evidence_package.get("allowed_scope", {})
    external = evidence_package.get("external_environment", {})
    interaction_analysis = evidence_package.get("external_interaction_analysis", {})
    static_analysis = interaction_analysis.get("static_analysis", {})
    reputation_analysis = interaction_analysis.get("reputation_analysis", {})

    critical_static_findings = []
    for finding in static_analysis.get("findings", []):
        if isinstance(finding, dict) and str(finding.get("severity", "")).lower() == "critical":
            critical_static_findings.append(finding)
    if critical_static_findings:
        return _result(
            "BLOCK",
            "CRITICAL",
            0.97,
            ["critical_static_analysis_finding"],
            [finding.get("rule", "critical static analysis finding") for finding in critical_static_findings],
            "Static analysis reported a critical finding.",
        )

    if reputation_analysis.get("known_malicious") is True:
        return _result(
            "BLOCK",
            "CRITICAL",
            0.99,
            ["known_malicious_reputation"],
            ["Reputation analysis marked the target as known malicious."],
            "External target is known malicious.",
        )

    if policy.is_destructive_command(command):
        return _result("BLOCK", "CRITICAL", 0.99, ["destructive_behavior"], [f"Forbidden command pattern: {command}"], "Destructive or explicitly forbidden command pattern.")

    if re.search(r"\b(curl\b.+\|\s*(bash|sh)|wget\b.+\|\s*(bash|sh))", lowered):
        return _result("BLOCK", "CRITICAL", 0.98, ["remote_code_execution"], [f"Pipe-to-shell command: {command}"], "Remote content piped directly to a shell.")

    credential_hits = [
        item.get("path", "")
        for item in trace.get("file_access", [])
        if item.get("sensitivity") == "credential" or policy.is_sensitive_path(item.get("path", ""))
    ]
    if credential_hits:
        return _result(
            "BLOCK",
            "CRITICAL",
            0.98,
            ["credential_access", "data_isolation"],
            [f"Observed access to {path}" for path in credential_hits],
            "Credential file access was observed during shadow execution.",
        )

    suspicious = external.get("extracted_suspicious_instructions", [])
    if suspicious:
        return _result(
            "HOLD",
            "HIGH",
            0.82,
            ["prompt_injection"],
            [f"Suspicious external instruction phrase: {phrase}" for phrase in suspicious],
            "Referenced content contains suspicious instructions that may be prompt injection.",
        )

    if trace.get("network_activity") and not allowed.get("network_allowed"):
        return _result(
            "HOLD",
            "HIGH",
            0.78,
            ["network_activity_without_allowlist"],
            ["Network connect syscall observed while network allowlist is empty."],
            "Network activity was observed without an allowlist decision.",
        )

    if "pip install" in lowered:
        return _result(
            "ISOLATE",
            "MEDIUM",
            0.58,
            ["package_install_requires_isolation"],
            ["Package install command should remain isolated unless trusted."],
            "Package installation did not show credential access, but should remain sandbox-only by default.",
        )

    if lowered.strip() in {"pwd", "ls", "ls -al", "ls -la"} or lowered.strip().startswith("cat "):
        return _result("ALLOW", "LOW", 0.08, [], ["Command is a simple local read/list operation."], "Simple local command is within allowed workspace scope.")

    return _result("HOLD", "MEDIUM", 0.55, ["insufficient_evidence"], ["No explicit allow rule matched."], "Evidence is insufficient or ambiguous.")
