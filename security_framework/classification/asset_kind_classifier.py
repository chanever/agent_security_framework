"""Classify external actions into analysis asset kinds."""

from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any

from security_framework.verifier.claude_verifier import _parse_json_object
from security_framework.config import SecurityFrameworkConfig
from security_framework.verifier.claude_cli_verifier import _summarize_cli_payload


ASSET_KINDS = {"agent_skill", "package", "repository"}

ASSET_KIND_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {"type": "string", "enum": ["agent_skill", "package", "repository"]},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reason": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["kind", "confidence", "reason"],
    "additionalProperties": True,
}


def skipped_result(reason: str = "No external environment interaction detected.") -> dict:
    return {
        "status": "skipped",
        "kind": None,
        "confidence": 0.0,
        "reason": reason,
        "evidence": [],
    }


def uncertain_result(reason: str, evidence: list[str] | None = None) -> dict:
    return {
        "status": "uncertain",
        "kind": None,
        "confidence": 0.0,
        "reason": reason,
        "evidence": evidence or [],
    }


def _list_value(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [str(value)]


def _normalize_payload(payload: dict, threshold: float) -> dict:
    kind = str(payload.get("kind", "")).lower()
    try:
        confidence = float(payload.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    reason = str(payload.get("reason", "Asset kind classifier returned a result."))
    evidence = _list_value(payload.get("evidence"))
    if kind not in ASSET_KINDS:
        return uncertain_result(f"Unsupported asset kind from classifier: {kind or 'missing'}.", evidence)
    if confidence < threshold:
        return uncertain_result(f"Asset kind classifier confidence {confidence:.2f} is below threshold {threshold:.2f}.", evidence)
    return {
        "status": "completed",
        "kind": kind,
        "confidence": round(confidence, 2),
        "reason": reason,
        "evidence": evidence,
    }


def _payload(action: dict, context: dict, classification: dict, targets: list[dict]) -> dict:
    return {
        "task": context.get("task", ""),
        "cwd": context.get("cwd", ""),
        "action": action,
        "classification": classification,
        "targets": targets,
    }


def _prompt(payload: dict) -> str:
    return (
        "Classify this external-environment action for routing static and reputation analysis.\n"
        "Return exactly one JSON object with kind, confidence, reason, and evidence.\n"
        "Allowed kind values are: agent_skill, package, repository.\n"
        "Use agent_skill for skill files or instructions such as SKILL.md.\n"
        "Use package for package installs, package metadata, requirements files, setup.py, pyproject.toml, npm/yarn/apt/pip targets.\n"
        "Use repository for git clones, source repositories, or downloaded source trees.\n\n"
        f"Input JSON:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )


def _call_claude_cli(payload: dict, config: SecurityFrameworkConfig) -> dict:
    command = shlex.split(config.claude_cli_command) or ["claude"]
    if config.claude_cli_bare:
        command.append("--bare")
    command.extend(["-p", "--output-format", "json"])
    if config.claude_cli_use_json_schema:
        command.extend(["--json-schema", json.dumps(ASSET_KIND_JSON_SCHEMA, separators=(",", ":"))])
    command.extend(["--max-turns", str(config.claude_cli_max_turns)])
    if config.claude_cli_model:
        command.extend(["--model", config.claude_cli_model])
    try:
        completed = subprocess.run(command, input=_prompt(payload), capture_output=True, text=True, timeout=config.claude_cli_timeout)
    except FileNotFoundError:
        return uncertain_result(f"Claude CLI asset kind classifier executable was not found: {command[0]}.")
    except subprocess.TimeoutExpired as exc:
        evidence = []
        if exc.stdout:
            evidence.append(str(exc.stdout)[-500:])
        if exc.stderr:
            evidence.append(str(exc.stderr)[-500:])
        return uncertain_result("Claude CLI asset kind classifier request timed out.", evidence)
    if completed.returncode != 0:
        evidence = _summarize_cli_payload(completed.stdout, completed.stderr)
        detail = f" {evidence[0]}" if evidence else ""
        return uncertain_result(
            f"Claude CLI asset kind classifier exited with status {completed.returncode}.{detail}",
            evidence,
        )
    try:
        response = json.loads(completed.stdout)
        payload_out = response.get("structured_output") if isinstance(response, dict) else None
        if not isinstance(payload_out, dict):
            if isinstance(response, dict) and response.get("kind"):
                payload_out = response
            elif isinstance(response, dict):
                payload_out = _parse_json_object(str(response.get("result", completed.stdout)))
            else:
                payload_out = _parse_json_object(str(response))
        return _normalize_payload(payload_out, config.asset_kind_classifier_confidence_threshold)
    except Exception as exc:
        return uncertain_result(f"Claude CLI asset kind classifier returned an unparsable response: {exc}.", [(completed.stdout or "")[-500:]])


def classify_asset_kind(action: dict, context: dict, classification: dict, targets: list[dict], config: SecurityFrameworkConfig) -> dict:
    """Return an asset-kind routing decision for an external action."""
    if not classification.get("external_env"):
        return skipped_result()

    return _call_claude_cli(_payload(action, context, classification, targets), config)
