"""Placeholder reputation analysis adapter.

Future implementations can call OSV, deps.dev, OpenSSF Scorecard, GitHub
Advisory DB, Socket.dev, or internal allow/deny lists through this interface.
"""

from __future__ import annotations


def skipped_result(reason: str = "No external package, repo, URL, or source target detected.") -> dict:
    return {
        "status": "skipped",
        "signals": [],
        "summary": reason,
    }


def analyze_reputation(action: dict, context: dict, targets: list[dict], classification: dict, asset_kind: dict | None = None) -> dict:
    """Return a stable placeholder result for future reputation analysis."""
    del action, context, asset_kind
    if not classification.get("external_env") or not targets:
        return skipped_result()
    return {
        "status": "not_implemented",
        "signals": [],
        "summary": "Reputation analysis is planned but not implemented yet.",
        "target_count": len(targets),
    }
