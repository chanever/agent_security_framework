"""Claude Code CLI verifier adapter for Evidence Package review."""

from __future__ import annotations

import json
import shlex
import subprocess

from security_framework.claude_verifier import _fallback, _load_prompt, _parse_json_object, normalize_verifier_result
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
        "evidence": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
        "recommended_action": {"type": "string"},
    },
    "required": ["decision", "risk_score", "risk_level", "reason"],
    "additionalProperties": True,
}


def _tail(value: str | bytes | None, max_chars: int = 500) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[-max_chars:] if len(value) > max_chars else value


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

    if completed.returncode != 0:
        return _fallback(
            f"Claude CLI verifier exited with status {completed.returncode}.",
            [_tail(completed.stderr), _tail(completed.stdout)],
        )

    try:
        return normalize_verifier_result(_extract_decision_payload(completed.stdout))
    except Exception as exc:
        return _fallback(f"Claude CLI verifier returned an unparsable response: {exc}.", [_tail(completed.stdout)])
