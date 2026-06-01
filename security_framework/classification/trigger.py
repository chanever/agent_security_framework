"""External-environment interaction classifier used before shadow execution."""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from security_framework.classification.external_target_extractor import extract_external_targets


URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+")

EXTERNAL_ENV_PATTERNS = [
    (re.compile(r"\bcurl\b"), "network_access"),
    (re.compile(r"\bwget\b"), "network_access"),
    (re.compile(r"\bgit\s+clone\b"), "git_clone"),
    (re.compile(r"\bpip(?:3)?\s+install\b"), "package_install"),
    (re.compile(r"\bnpm\s+(?:install|i|add)\b"), "package_install"),
    (re.compile(r"\byarn\s+add\b"), "package_install"),
    (re.compile(r"\bapt(?:-get)?\s+install\b"), "package_install"),
    (re.compile(r"\bdocker\s+pull\b"), "container_pull"),
    (re.compile(r"\bpython(?:3)?\s+[\w./-]*setup\.py\b"), "package_script"),
    (re.compile(r"\b(?:bash|sh)\s+[\w./-]*install\.sh\b"), "install_script"),
    (re.compile(r"\bpython(?:3)?\s+-c\s+.*\b(requests|httpx|urllib)\b"), "api_call"),
]

API_CALL_PATTERNS = [
    re.compile(r"\b(curl|wget)\b.*\b(api|graphql|endpoint)\b"),
    re.compile(r"https?://[^\s'\"<>]*(api|graphql)[^\s'\"<>]*"),
]

EXTERNAL_ORIGIN_FILENAMES = {
    "readme.md": "external_instruction_source",
    "readme.txt": "external_instruction_source",
    "skill.md": "skill_file_read",
    "downloaded.html": "downloaded_file_read",
    "downloaded.txt": "downloaded_file_read",
    "install.sh": "install_script_read",
    "setup.py": "package_script_read",
    "package.json": "package_metadata_read",
    "requirements.txt": "package_metadata_read",
    "pyproject.toml": "package_metadata_read",
    "external_tool_output.txt": "tool_output_read",
}

SAFE_LOCAL_PATTERNS = [
    re.compile(r"^\s*pwd\s*$"),
    re.compile(r"^\s*ls(?:\s+-[A-Za-z0-9]+)?(?:\s+\.)?\s*$"),
    re.compile(r"^\s*mkdir\s+(?:-p\s+)?[\w./-]+\s*$"),
    re.compile(r"^\s*touch\s+[\w./-]+\s*$"),
    re.compile(r"^\s*echo\s+.+\s+>\s+[\w./-]+\s*$"),
    re.compile(r"^\s*python(?:3)?\s+[\w./-]+\.py(?:\s+.*)?\s*$"),
]

def _shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _dedupe(values: list[str]) -> list[str]:
    return sorted(set(values))


def _filename_reason(path: str) -> str | None:
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    return EXTERNAL_ORIGIN_FILENAMES.get(name)


def _is_read_only_external_file_command(words: list[str]) -> tuple[bool, list[str]]:
    if not words or words[0] not in {"cat", "less", "more", "head", "tail"}:
        return False, []
    reasons = []
    for path in words[1:]:
        if path.startswith("-"):
            continue
        reason = _filename_reason(path)
        if reason:
            reasons.append(reason)
    return bool(reasons), reasons


def _context_external_origin(context: dict | None) -> bool:
    """Best-effort hook for future origin tracking.

    TODO: Replace filename heuristics with durable workspace/file provenance once
    vulnerable_cli_agent records whether a workspace or file came from a remote
    repo, package, tool output, downloaded page, or skill source.
    """
    if not context:
        return False
    return bool(context.get("external_origin") or context.get("workspace_external_origin"))


def classify_command(command: str, context: dict | None = None) -> dict:
    """Classify whether a command interacts with the external environment."""
    lowered = command.lower()
    reasons: list[str] = []
    words = _shell_words(command)

    for pattern, reason in EXTERNAL_ENV_PATTERNS:
        if pattern.search(lowered):
            reasons.append(reason)

    if URL_PATTERN.search(command):
        reasons.append("url_fetch")

    if any(pattern.search(lowered) for pattern in API_CALL_PATTERNS):
        reasons.append("api_call")

    if re.search(r"\b(html|dom|downloaded file|tool output|external package metadata)\b", lowered):
        reasons.append("external_content_read")

    read_only_external, external_file_reasons = _is_read_only_external_file_command(words)
    reasons.extend(external_file_reasons)

    if _context_external_origin(context) and words:
        if words[0] in {"python", "python3", "node", "ruby", "perl", "bash", "sh"}:
            reasons.append("external_origin_code_execution")
        elif words[0] in {"cat", "less", "more", "head", "tail"}:
            reasons.append("external_origin_workspace")

    if words and words[0] in {"cat", "less", "more", "head", "tail"} and not reasons:
        return {
            "external_env": False,
            "needs_shadow_execution": False,
            "reasons": ["local_command"],
            "targets": [],
        }

    if any(pattern.match(command) for pattern in SAFE_LOCAL_PATTERNS) and not reasons:
        return {
            "external_env": False,
            "needs_shadow_execution": False,
            "reasons": ["local_command"],
            "targets": [],
        }

    external_env = bool(reasons)
    if external_env:
        shadow_reasons = {
            "network_access",
            "url_fetch",
            "git_clone",
            "package_install",
            "container_pull",
            "package_script",
            "install_script",
            "api_call",
            "external_origin_code_execution",
        }
        needs_shadow_execution = bool(set(reasons) & shadow_reasons)
        if read_only_external and not needs_shadow_execution:
            needs_shadow_execution = False
        return {
            "external_env": True,
            "needs_shadow_execution": needs_shadow_execution,
            "reasons": _dedupe(reasons),
            "targets": extract_external_targets({"type": "command", "command": command}, context, None),
        }

    return {
        "external_env": False,
        "needs_shadow_execution": False,
        "reasons": ["local_command"],
        "targets": [],
    }
