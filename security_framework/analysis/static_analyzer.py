"""Placeholder static analysis adapter.

Real analyzers such as Semgrep, Gitleaks, Trivy, or custom YARA-style rules
can be wired into this interface later.
"""

from __future__ import annotations


def skipped_result(reason: str = "No external interaction or install/source action detected.") -> dict:
    return {
        "status": "skipped",
        "findings": [],
        "summary": reason,
    }


def analyze_static(action: dict, context: dict, targets: list[dict], classification: dict, asset_kind: dict | None = None) -> dict:
    """Return a stable placeholder result for future static analysis."""
    del action, context, targets, asset_kind
    if not classification.get("external_env"):
        return skipped_result()
    return {
        "status": "not_implemented",
        "findings": [],
        "summary": "Static analysis is planned but not implemented yet.",
    }
