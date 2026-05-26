"""Verifier router pinned to Claude Code CLI decisions."""

from __future__ import annotations

from security_framework.config import SecurityFrameworkConfig
from security_framework.verifier.claude_cli_verifier import verify as claude_cli_verify


def verify(evidence_package: dict, config: SecurityFrameworkConfig | None = None) -> dict:
    """Verify an Evidence Package with Claude Code CLI."""
    cfg = config or SecurityFrameworkConfig.from_env()
    return claude_cli_verify(evidence_package, cfg)
