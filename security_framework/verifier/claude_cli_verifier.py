"""Claude Code CLI verifier adapter for Evidence Package review."""

from __future__ import annotations

import json
import shlex
import subprocess

from security_framework.verifier.claude_verifier import _fallback, _load_prompt, _parse_json_object, normalize_verifier_result
from security_framework.config import SecurityFrameworkConfig


VERIFIER_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": ["ALLOW", "ALLOW_WITH_SANITIZATION", "HOLD", "BLOCK", "ISOLATE"]},
        "overall_safety_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "risk_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "task_alignment_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "action_necessity_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "source_trust_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "data_isolation_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "side_effect_safety_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "uncertainty_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "violated_properties": {"type": "array", "items": {"type": "string"}},
        "evidence": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "reason": {"type": "string", "minLength": 20},
        "recommended_action": {"type": "string", "minLength": 10},
    },
    "required": ["decision", "risk_score", "risk_level", "reason"],
    "additionalProperties": True,
}


def _tail(value: str | bytes | None, max_chars: int = 2000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[-max_chars:] if len(value) > max_chars else value


def _summarize_cli_payload(stdout: str, stderr: str = "") -> list[str]:
    """Keep the useful part of Claude CLI JSON/error output for fallback evidence."""
    evidence = []
    if stderr:
        evidence.append(_tail(stderr))
    try:
        payload = json.loads(stdout)
    except Exception:
        if stdout:
            evidence.append(_tail(stdout))
        return evidence

    if isinstance(payload, dict):
        for key in ("error", "message", "result", "terminal_reason", "permission_denials"):
            value = payload.get(key)
            if value:
                evidence.append(_tail(json.dumps({key: value}, ensure_ascii=False)))
        if not evidence and stdout:
            evidence.append(_tail(stdout))
        return evidence

    if stdout:
        evidence.append(_tail(stdout))
    return evidence


def _build_prompt(evidence_package: dict) -> str:
    evidence_json = json.dumps(evidence_package, ensure_ascii=False, indent=2)
    system_prompt = _load_prompt("claude_system_prompt.txt")
    user_prompt = _load_prompt("claude_user_prompt_template.txt").replace("{{EVIDENCE_PACKAGE_JSON}}", evidence_json)
    return f"{system_prompt}\n\n{user_prompt}"


def build_claude_cli_command(config: SecurityFrameworkConfig) -> list[str]:
    """Build the Claude Code headless command without shell interpolation."""
    command = shlex.split(config.claude_cli_command)
    if not command:
        command = ["claude"]
    if config.claude_cli_bare:
        command.append("--bare")
    command.extend(["-p", "--output-format", "json"])
    if config.claude_cli_use_json_schema:
        command.extend(["--json-schema", json.dumps(VERIFIER_JSON_SCHEMA, separators=(",", ":"))])
    command.extend(["--max-turns", str(config.claude_cli_max_turns)])
    if config.claude_cli_model:
        command.extend(["--model", config.claude_cli_model])
    return command


def _extract_decision_payload(stdout: str) -> dict:
    response = json.loads(stdout)
    if isinstance(response, dict):
        structured = response.get("structured_output")
        if isinstance(structured, dict):
            return structured
        if response.get("decision"):
            return response
        result = response.get("result")
        if isinstance(result, dict):
            return result
        if isinstance(result, str):
            return _parse_json_object(result)
    if isinstance(response, str):
        return _parse_json_object(response)
    return _parse_json_object(stdout)


def _first_shadow_step(evidence_package: dict) -> dict:
    shadow = evidence_package.get("shadow_agent_execution")
    if not isinstance(shadow, dict):
        return {}
    trajectory = shadow.get("trajectory")
    if isinstance(trajectory, list) and trajectory:
        first = trajectory[0]
        if isinstance(first, dict):
            return first
    return {}


def _is_sparse_result(result: dict) -> bool:
    reason = str(result.get("reason", "")).strip()
    evidence = result.get("evidence")
    return reason in {"", "Claude verifier returned a decision."} and not evidence


def _compact_text(value: object, max_chars: int = 220) -> str:
    text = str(value or "").strip().replace("\n", " ")
    return text[:max_chars] + "..." if len(text) > max_chars else text


def _context_evidence(evidence_package: dict) -> list[str]:
    action = evidence_package.get("current_action")
    action = action if isinstance(action, dict) else {}
    external_analysis = evidence_package.get("external_interaction_analysis")
    external_analysis = external_analysis if isinstance(external_analysis, dict) else {}
    external_environment = evidence_package.get("external_environment")
    external_environment = external_environment if isinstance(external_environment, dict) else {}
    asset_kind = external_analysis.get("asset_kind")
    asset_kind = asset_kind if isinstance(asset_kind, dict) else {}
    static_analysis = external_analysis.get("static_analysis")
    static_analysis = static_analysis if isinstance(static_analysis, dict) else {}
    reputation_analysis = external_analysis.get("reputation_analysis")
    reputation_analysis = reputation_analysis if isinstance(reputation_analysis, dict) else {}
    shadow_step = _first_shadow_step(evidence_package)

    evidence = []
    command = action.get("command_or_target")
    if command:
        evidence.append(f"command: {_compact_text(command)}")
    why_checked = action.get("why_this_action_is_being_checked")
    if why_checked:
        evidence.append(f"action category: {_compact_text(why_checked)}")
    if "external_env" in action:
        evidence.append(f"external_env: {bool(action.get('external_env'))}")
    targets = external_analysis.get("targets")
    if targets:
        evidence.append(f"targets: {_compact_text(json.dumps(targets, ensure_ascii=False))}")
    external_type = external_environment.get("type")
    trust_level = external_environment.get("trust_level")
    if external_type or trust_level:
        evidence.append(f"external content: type={_compact_text(external_type)}, trust_level={_compact_text(trust_level)}")
    suspicious_instructions = external_environment.get("extracted_suspicious_instructions")
    if suspicious_instructions:
        evidence.append(f"suspicious instructions: {_compact_text(json.dumps(suspicious_instructions, ensure_ascii=False))}")
    suspicious_patterns = external_environment.get("suspicious_code_patterns")
    if suspicious_patterns:
        evidence.append(f"suspicious patterns: {_compact_text(json.dumps(suspicious_patterns, ensure_ascii=False))}")
    asset_status = asset_kind.get("status")
    if asset_status:
        evidence.append(
            "asset_kind: "
            f"status={_compact_text(asset_status)}, "
            f"kind={_compact_text(asset_kind.get('kind'))}, "
            f"confidence={asset_kind.get('confidence', 0.0)}"
        )
    asset_reason = asset_kind.get("reason")
    if asset_reason:
        evidence.append(f"asset_kind reason: {_compact_text(asset_reason)}")
    if static_analysis.get("status"):
        evidence.append(f"static_analysis: {static_analysis.get('status')}")
    if reputation_analysis.get("status"):
        evidence.append(f"reputation_analysis: {reputation_analysis.get('status')}")
    if shadow_step:
        evidence.append(
            "shadow execution: "
            f"exit_code={shadow_step.get('exit_code')}, "
            f"timed_out={bool(shadow_step.get('timed_out'))}"
        )
        stderr = _compact_text(shadow_step.get("stderr"))
        if stderr:
            evidence.append(f"shadow stderr: {stderr}")
    return evidence


def _enrich_sparse_verifier_result(result: dict, evidence_package: dict) -> dict:
    if not _is_sparse_result(result):
        return result

    enriched = dict(result)
    evidence = _context_evidence(evidence_package)
    decision = enriched.get("decision", "HOLD")
    risk_level = enriched.get("risk_level", "MEDIUM")
    command = next((item.removeprefix("command: ") for item in evidence if item.startswith("command: ")), "the requested action")
    suspicious = next((item for item in evidence if item.startswith("suspicious instructions: ")), "")
    suspicious_detail = f" Evidence includes {suspicious}." if suspicious else ""
    enriched["evidence"] = evidence
    enriched["reason"] = (
        f"Claude verifier returned {decision} without a detailed reason. "
        f"Framework context shows `{command}` was treated as a guarded action with "
        f"risk_level={risk_level}.{suspicious_detail} "
        "Real execution was blocked because the verifier decision was not ALLOW."
    )
    enriched["reason_source"] = "framework_fallback"
    if not enriched.get("recommended_action"):
        enriched["recommended_action"] = (
            "Do not run this command in the real environment until the verifier provides enough evidence to allow it."
        )
    return enriched


def verify(evidence_package: dict, config: SecurityFrameworkConfig | None = None) -> dict:
    """Run Claude Code in headless mode and return a normalized verifier decision."""
    cfg = (config or SecurityFrameworkConfig.from_env()).resolve_paths()
    prompt = _build_prompt(evidence_package)
    command = build_claude_cli_command(cfg)

    try:
        completed = subprocess.run(
            command,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=cfg.claude_cli_timeout,
        )
    except FileNotFoundError:
        return _fallback(f"Claude CLI executable was not found: {command[0]}.")
    except subprocess.TimeoutExpired as exc:
        return _fallback("Claude CLI verifier request timed out.", [_tail(exc.stdout), _tail(exc.stderr)])

    try:
        result = normalize_verifier_result(_extract_decision_payload(completed.stdout))
        return _enrich_sparse_verifier_result(result, evidence_package)
    except Exception as exc:
        if completed.returncode != 0:
            evidence = _summarize_cli_payload(completed.stdout, completed.stderr)
            detail = f" {evidence[0]}" if evidence else ""
            return _fallback(
                f"Claude CLI verifier exited with status {completed.returncode}.{detail}",
                evidence,
            )
        return _fallback(f"Claude CLI verifier returned an unparsable response: {exc}.", [_tail(completed.stdout)])
