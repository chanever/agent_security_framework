"""npm package static analyzer.

Same semgrep docker pipeline as pypi_analyzer but the GuardDog rules tagged
``languages: javascript`` and the ``npm-*.yml`` filenames carry npm-specific
patterns (npm-install-script, npm-serialize-environment, npm-exec-base64,
npm-silent-process-execution, etc.). The semgrep registry also has
``p/javascript`` which we layer on for general JS security audit.
"""

from __future__ import annotations

from . import pypi_analyzer


def analyze(node: dict, cfg) -> dict:
    # The semgrep configs we chain handle both Python and JavaScript files
    # via per-rule language tags; semgrep auto-detects file language. The
    # pypi_analyzer's docker invocation is therefore the same for npm
    # scanning — only the label changes.
    result = pypi_analyzer.analyze(node, cfg)
    if result.get("status") == "success":
        result["summary"] = result["summary"].replace("PyPI semgrep", "npm semgrep")
    result["analyzer"] = "npm"
    return result
