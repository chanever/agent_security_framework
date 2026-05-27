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


# artifact_type → analyzer function.
#
# Scope: this module statically analyzes four artifact types — pypi, npm, repo
# (incl. local_directory / github_action / mcp_server, which route through the
# repo chain), and skill. ``container_image`` is intentionally NOT handled here:
# we have no labelled container corpus to validate a Trivy path, so rather than
# ship an unevaluated analyzer we let such nodes fall through to a transparent
# "no analyzer registered" skip. The classifier still detects `docker pull`
# targets so the verifier sees the image was fetched.
_DISPATCH: dict[str, Callable] = {
    "pypi_package":       pypi_analyzer.analyze,        # chained semgrep (py) + obfuscation
    "npm_package":        npm_analyzer.analyze,         # semgrep --lang=javascript + GuardDog npm
    "github_repo":        repo_analyzer.analyze,        # semgrep + Gitleaks (secret scan)
    "skill":              skill_analyzer.analyze,       # ref-walk + frontmatter + phrase
    # Route through repo_analyzer's chained semgrep + gitleaks chain.
    "local_directory":    repo_analyzer.analyze,
    "requirements_file":  pypi_analyzer.analyze,
    "github_action":      repo_analyzer.analyze,
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
