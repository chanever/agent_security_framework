"""Per-artifact-type reputation lookups.

Public API: ``reputation_analyzer.analyze_reputation`` keeps the same
signature it has today. Internally it now consults ``artifact_classifier``
to enumerate artifact graph nodes and dispatches each to the type-specific
lookup. Per-type modules expose:

    lookup(node: dict, *, timeout: int) -> dict  # one signal entry

with shape consistent with the rest of the evidence pipeline:

    {
      "source": "osv" | "scorecard" | "npm-registry" | "skill-heuristic",
      "target_type": "package" | "github_repo" | "skill",
      "target_name": "<name>",
      ...source-specific fields...,
      "summary": "<one-line>",
    }
"""

from __future__ import annotations

from typing import Callable

from . import npm_reputation
from . import pypi_reputation
from . import repo_reputation
from . import skill_reputation


# artifact_type → reputation lookup function
_DISPATCH: dict[str, Callable] = {
    "pypi_package":      pypi_reputation.lookup,
    "npm_package":       npm_reputation.lookup,
    "github_repo":       repo_reputation.lookup,
    "skill":             skill_reputation.lookup,
    "mcp_server":        skill_reputation.lookup,
    "github_action":     repo_reputation.lookup,
    # local_directory / container_image / url have no first-party
    # reputation source today — they fall through to a benign "skipped".
}


def lookup_node(node: dict, *, timeout: int = 10) -> dict | None:
    fn = _DISPATCH.get(node.get("artifact_type", ""))
    if fn is None:
        return None
    return fn(node, timeout=timeout)
