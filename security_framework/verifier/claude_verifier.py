"""Claude verifier adapter for Evidence Package review."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from security_framework.config import SecurityFrameworkConfig


DECISIONS = {"ALLOW", "ALLOW_WITH_SANITIZATION", "HOLD", "BLOCK", "ISOLATE"}
RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


def _fallback(reason: str, evidence: list[str] | None = None) -> dict:
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
        "violated_properties": ["verifier_unavailable"],
        "evidence": evidence or [],
        "reason": reason,
        "reason_source": "framework_fallback",
        "recommended_action": "Hold this command until verifier uncertainty is resolved.",
    }


def _load_prompt(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def _extract_response_text(response: dict) -> str:
    parts = []
    for block in response.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(parts).strip()


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def _parse_json_object(text: str) -> dict:
    stripped = _strip_code_fence(text)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _float_value(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _list_value(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_verifier_result(payload: dict[str, Any]) -> dict:
    """Return a stable verifier schema even when Claude omits optional fields."""
    decision = str(payload.get("decision", "HOLD")).upper()
    if decision not in DECISIONS:
        decision = "HOLD"

    risk_level = str(payload.get("risk_level", "MEDIUM")).upper()
    if risk_level not in RISK_LEVELS:
        risk_level = "MEDIUM"

    risk_score = _float_value(payload.get("risk_score"), 0.65)
    safety_score = _float_value(payload.get("overall_safety_score"), max(0.0, 1.0 - risk_score))

    return {
        "decision": decision,
        "overall_safety_score": round(max(0.0, min(1.0, safety_score)), 2),
        "risk_score": round(max(0.0, min(1.0, risk_score)), 2),
        "risk_level": risk_level,
        "task_alignment_score": _float_value(payload.get("task_alignment_score"), 0.5),
        "action_necessity_score": _float_value(payload.get("action_necessity_score"), 0.5),
        "source_trust_score": _float_value(payload.get("source_trust_score"), 0.2),
        "data_isolation_score": _float_value(payload.get("data_isolation_score"), 0.5),
        "side_effect_safety_score": _float_value(payload.get("side_effect_safety_score"), 0.4),
        "uncertainty_score": _float_value(payload.get("uncertainty_score"), 0.5),
        "violated_properties": _list_value(payload.get("violated_properties")),
        "evidence": _list_value(payload.get("evidence")),
        "reason": str(payload.get("reason", "Claude verifier returned a decision.")),
        "reason_source": str(payload.get("reason_source", "claude_verifier")),
        "recommended_action": str(payload.get("recommended_action", "")),
    }


def verify(evidence_package: dict, config: SecurityFrameworkConfig | None = None) -> dict:
    """Call Claude and return a normalized verifier decision."""
    cfg = (config or SecurityFrameworkConfig.from_env()).resolve_paths()
    if not cfg.claude_api_key:
        return _fallback("Claude verifier is enabled, but ANTHROPIC_API_KEY or CLAUDE_API_KEY is not set.")

    evidence_json = json.dumps(evidence_package, ensure_ascii=False, indent=2)
    system_prompt = _load_prompt("claude_system_prompt.txt")
    user_prompt = _load_prompt("claude_user_prompt_template.txt").replace("{{EVIDENCE_PACKAGE_JSON}}", evidence_json)
    body = {
        "model": cfg.claude_model,
        "max_tokens": cfg.claude_max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    request = urllib.request.Request(
        cfg.claude_api_url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-api-key": cfg.claude_api_key,
            "anthropic-version": cfg.claude_api_version,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=cfg.claude_timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        return _fallback(f"Claude verifier HTTP error: {exc.code}.", [detail])
    except urllib.error.URLError as exc:
        return _fallback(f"Claude verifier connection error: {exc.reason}.")
    except TimeoutError:
        return _fallback("Claude verifier request timed out.")

    try:
        response_payload = json.loads(raw)
        decision_payload = _parse_json_object(_extract_response_text(response_payload))
        return normalize_verifier_result(decision_payload)
    except Exception as exc:
        return _fallback(f"Claude verifier returned an unparsable response: {exc}.", [raw[:500]])
