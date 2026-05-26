"""Generic repo / mixed-artifact static analyzer.

When the artifact graph node is a ``github_repo`` (clone target) or a
``local_directory`` that has *multiple* language signals or none recognised
specifically, we still want to run the standard semgrep chain. Acts as a
catch-all that won't refuse to scan just because we couldn't pin a single
artifact_type.

Secret detection (Gitleaks / TruffleHog) is *not* shelled out from this
module — it's listed as future work in BENCHMARK.md §7. The existing
GuardDog ``exfiltrate-sensitive-data`` + chanever ``sensitive-file-read``
rules already cover the obvious credential-read patterns.
"""

from __future__ import annotations

from . import pypi_analyzer


def analyze(node: dict, cfg) -> dict:
    result = pypi_analyzer.analyze(node, cfg)
    if result.get("status") == "success":
        result["summary"] = result["summary"].replace("PyPI semgrep", "repo-scan semgrep")
    result["analyzer"] = "repo"
    return result
