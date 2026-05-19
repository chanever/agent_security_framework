"""Command classifier used before shadow execution."""

from __future__ import annotations

import re
import shlex

from security_framework import policy


OUTSIDE_ENV_PATTERNS = [
    (re.compile(r"\bcurl\b"), "network_access"),
    (re.compile(r"\bwget\b"), "network_access"),
    (re.compile(r"\bgit\s+clone\b"), "git_clone"),
    (re.compile(r"\bpip\s+install\b"), "package_install"),
    (re.compile(r"\bnpm\s+install\b"), "package_install"),
    (re.compile(r"\byarn\s+add\b"), "package_install"),
    (re.compile(r"\bapt(?:-get)?\s+install\b"), "package_install"),
    (re.compile(r"\bpython(?:3)?\s+setup\.py\b"), "setup_script"),
    (re.compile(r"\b(?:bash|sh)\s+install\.sh\b"), "install_script"),
    (re.compile(r"\bdocker\s+pull\b"), "container_pull"),
    (re.compile(r"\bpython(?:3)?\s+-c\s+.*(requests|httpx|urllib)"), "python_network_code"),
    (re.compile(r"\bnode\b.*(install|postinstall|preinstall)"), "node_install_script"),
]

LOCAL_SAFE_PATTERNS = [
    re.compile(r"^\s*pwd\s*$"),
    re.compile(r"^\s*ls(?:\s+-[A-Za-z0-9]+)?(?:\s+\.)?\s*$"),
    re.compile(r"^\s*cat\s+[\w./-]+\s*$"),
]


def _shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def classify_command(command: str) -> dict:
    """Classify a shell command by outside-environment access and risk."""
    lowered = command.lower()
    reasons: list[str] = []

    if policy.is_destructive_command(command):
        return {
            "outside_env": True,
            "risk_level": "critical",
            "reasons": ["destructive_or_forbidden_command"],
            "needs_shadow_execution": False,
            "block_immediately": True,
        }

    for pattern, reason in OUTSIDE_ENV_PATTERNS:
        if pattern.search(lowered):
            reasons.append(reason)

    if policy.NETWORK_TOOL_PATTERN.search(lowered):
        reasons.append("network_tool")
    if re.search(r"\b(nc|ncat|telnet|ssh|scp|rsync)\b", lowered):
        reasons.append("remote_access_tool")

    words = _shell_words(command)
    if words and words[0] in {"python", "python3", "node", "ruby", "perl"} and not reasons:
        reasons.append("local_script_execution")

    if any(pattern.match(command) for pattern in LOCAL_SAFE_PATTERNS) and not reasons:
        return {
            "outside_env": False,
            "risk_level": "low",
            "reasons": ["local_safe_command"],
            "needs_shadow_execution": False,
            "block_immediately": False,
        }

    outside_env = bool(reasons and any(reason != "local_script_execution" for reason in reasons))
    if "remote_access_tool" in reasons:
        risk = "high"
    elif outside_env:
        risk = "high" if any(reason in {"package_install", "setup_script", "install_script"} for reason in reasons) else "medium"
    elif reasons:
        risk = "medium"
    else:
        risk = "medium"
        reasons.append("unknown_command")

    return {
        "outside_env": outside_env,
        "risk_level": risk,
        "reasons": sorted(set(reasons)),
        "needs_shadow_execution": risk in {"medium", "high", "critical"} or outside_env,
        "block_immediately": False,
    }
