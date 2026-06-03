"""Generic repo / mixed-artifact static analyzer.

A repo node runs the same chained semgrep pass (p/security-audit + GuardDog
+ GuardDog unscoped + chanever rules) the pypi analyzer uses. The chain is
language-agnostic enough to cover eval/exec, base64, env reads, and the
shell-out patterns ``pip install .`` install-hook attacks rely on.

Gitleaks (git-aware secret detection) was previously run alongside semgrep,
but our threat model is "agent installs untrusted external source" — a
leaked credential inside the repo doesn't make installing it more
dangerous (the agent doesn't gain those credentials), and on popular OSS
the gitleaks signal was dominated by test-fixture placeholder secrets
(django auth_tests fixtures, fastapi docs/examples, etc.) which created a
large false-positive load. We rely on the semgrep chain for repo nodes.
"""

from __future__ import annotations

from . import pypi_analyzer


def analyze(node: dict, cfg) -> dict:
    result = pypi_analyzer.analyze(node, cfg)
    return {
        "status": result.get("status", "skipped"),
        "findings": result.get("findings") or [],
        "summary": result.get("summary") or "",
        "analyzer": "repo",
    }
