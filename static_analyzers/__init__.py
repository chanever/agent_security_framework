"""Per-artifact-type static analyzers.

The legacy ``static_analyzer.analyze_static`` entrypoint stays the public
API. It now dispatches via ``artifact_classifier`` to the per-type
sub-analyzer in this package and merges all findings into one normalized
result. Each sub-module exposes:

    analyze(node: dict, cfg: SecurityFrameworkConfig) -> dict

with shape:

    {
      "status": "success" | "unavailable" | "skipped",
      "findings": [{"rule_id", "severity", "path", "line", "message", "source"}],
      "summary": "<one-line>",
      "analyzer": "<name>",
    }
"""

from __future__ import annotations

from typing import Callable

from . import npm_analyzer
from . import pypi_analyzer
from . import repo_analyzer
from . import skill_analyzer


# artifact_type → analyzer function
_DISPATCH: dict[str, Callable] = {
    "pypi_package":       pypi_analyzer.analyze,
    "npm_package":        npm_analyzer.analyze,
    "github_repo":        repo_analyzer.analyze,
    "skill":              skill_analyzer.analyze,
    "local_directory":    repo_analyzer.analyze,  # generic fallthrough
    # The rest currently fall through to repo_analyzer's "language-detect
    # then call appropriate per-language analyzer" path.
    "requirements_file":  pypi_analyzer.analyze,
    "github_action":      repo_analyzer.analyze,
    "container_image":    repo_analyzer.analyze,
    "mcp_server":         repo_analyzer.analyze,
}


def analyze_node(node: dict, cfg) -> dict:
    artifact_type = node.get("artifact_type", "")
    fn = _DISPATCH.get(artifact_type)
    if fn is None:
        return {
            "status": "skipped",
            "findings": [],
            "summary": f"No analyzer registered for artifact_type={artifact_type!r}",
            "analyzer": "none",
        }
    return fn(node, cfg)
