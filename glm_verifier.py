"""LLM-backed verifier using the local ``claude`` CLI (OAuth subscription auth).

Drops in alongside the existing rule-based ``mock_verifier.verify()`` to enable
the R5 ablation row. Selected via ``VERIFIER_MODE=glm`` (the original chanever
config field; we honour it for backwards-compat) or via direct import.

Flow:
1. Load ``prompts/glm_system_prompt.txt`` and ``prompts/glm_user_prompt_template.txt``.
2. Substitute ``{{EVIDENCE_PACKAGE_JSON}}`` with the serialised evidence.
3. Pipe the combined prompt to ``claude -p`` (no Anthropic key required when
   the user is logged in via OAuth subscription).
4. Parse the LLM's JSON response and coerce to the same schema the
   ``mock_verifier`` emits so the rest of the framework stays unchanged.

If the CLI is missing, times out, or returns malformed JSON, fall back to
the mock verifier and tag ``decision_source: "glm_fallback_mock"`` so the
downstream evidence package records the degradation.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

def _conservative_fallback(error: str) -> dict:
    """Return a HOLD verdict when the LLM CLI cannot be reached.

    Upstream removed ``mock_verifier`` so the safest behaviour when the GLM
    judge fails is a conservative HOLD — the safeguard maps non-ALLOW to
    block, preserving the gate-at-safeguard contract even without an LLM.
    """
    return {
        "decision": "HOLD",
        "overall_safety_score": 0.0,
        "risk_score": 0.0,
        "risk_level": "MEDIUM",
        "task_alignment_score": 0.0,
        "action_necessity_score": 0.0,
        "source_trust_score": 0.0,
        "data_isolation_score": 0.0,
        "side_effect_safety_score": 0.0,
        "uncertainty_score": 1.0,
        "violated_properties": [],
        "evidence": [],
        "reason": f"GLM verifier unavailable ({error}); defaulting to HOLD.",
        "recommended_action": "Manual review required.",
        "decision_source": "glm_fallback_hold",
        "glm_error": error,
    }


PROMPTS = Path(__file__).resolve().parent / "prompts"
SYSTEM_PROMPT_FILE = PROMPTS / "glm_system_prompt.txt"
USER_TEMPLATE_FILE = PROMPTS / "glm_user_prompt_template.txt"

DEFAULT_TIMEOUT = 120

# Override via env if needed.
DEFAULT_CMD = os.environ.get("GLM_VERIFIER_CMD", "claude -p")

ALLOWED_DECISIONS = {"ALLOW", "ALLOW_WITH_SANITIZATION", "HOLD", "BLOCK", "ISOLATE"}


class GLMVerifierError(RuntimeError):
    pass


def _build_prompt(evidence_package: dict) -> str:
    system = SYSTEM_PROMPT_FILE.read_text(encoding="utf-8") if SYSTEM_PROMPT_FILE.exists() else ""
    user_template = (
        USER_TEMPLATE_FILE.read_text(encoding="utf-8") if USER_TEMPLATE_FILE.exists() else ""
    )
    user = user_template.replace(
        "{{EVIDENCE_PACKAGE_JSON}}",
        json.dumps(evidence_package, ensure_ascii=False),
    )
    return f"{system.strip()}\n\n{user.strip()}\n"


def _extract_first_json_object(text: str) -> dict:
    """Pick the first ``{...}`` JSON object in ``text``.

    The LLM is asked for raw JSON but may still emit prose / code fences. We
    locate the first balanced ``{...}`` block and ``json.loads`` it.
    """
    start = text.find("{")
    if start == -1:
        raise GLMVerifierError(f"no JSON object in output: {text[:200]!r}")
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(text[start:], start=start):
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blob = text[start : i + 1]
                try:
                    return json.loads(blob)
                except json.JSONDecodeError as exc:
                    raise GLMVerifierError(f"JSON parse failed: {exc}: {blob[:200]!r}") from exc
    raise GLMVerifierError(f"unbalanced JSON in output: {text[:200]!r}")


def _normalize(result: dict, *, raw_output: str) -> dict:
    decision = (result.get("decision") or "HOLD").upper()
    if decision not in ALLOWED_DECISIONS:
        decision = "HOLD"
    out = {
        "decision": decision,
        "overall_safety_score": float(result.get("overall_safety_score") or 0.0),
        "risk_score": float(result.get("risk_score") or 0.0),
        "risk_level": result.get("risk_level") or "MEDIUM",
        "task_alignment_score": float(result.get("task_alignment_score") or 0.0),
        "action_necessity_score": float(result.get("action_necessity_score") or 0.0),
        "source_trust_score": float(result.get("source_trust_score") or 0.0),
        "data_isolation_score": float(result.get("data_isolation_score") or 0.0),
        "side_effect_safety_score": float(result.get("side_effect_safety_score") or 0.0),
        "uncertainty_score": float(result.get("uncertainty_score") or 0.0),
        "violated_properties": result.get("violated_properties") or [],
        "evidence": result.get("evidence") or [],
        "reason": result.get("reason") or "",
        "recommended_action": result.get("recommended_action") or "",
        "decision_source": "glm",
        "raw_output": raw_output[:8192],
    }
    return out


def verify(evidence_package: dict, *, timeout: int = DEFAULT_TIMEOUT, cmd: str = DEFAULT_CMD) -> dict:
    """Send the evidence package to the LLM judge and return a normalized verdict.

    Errors (missing CLI / timeout / malformed JSON) fall back to the mock
    verifier with ``decision_source="glm_fallback_mock"``.
    """
    prompt = _build_prompt(evidence_package)
    argv = shlex.split(cmd)
    try:
        completed = subprocess.run(
            argv,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return _conservative_fallback(f"CLI not found: {exc}")
    except subprocess.TimeoutExpired:
        return _conservative_fallback(f"timeout after {timeout}s")

    raw = completed.stdout or ""
    if not raw.strip():
        stderr_excerpt = (completed.stderr or "").strip()[:200]
        return _conservative_fallback(f"empty stdout (stderr: {stderr_excerpt})")

    try:
        parsed = _extract_first_json_object(raw)
    except GLMVerifierError as exc:
        return _conservative_fallback(str(exc))

    return _normalize(parsed, raw_output=raw)
