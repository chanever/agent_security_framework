"""GitHub repo reputation — OpenSSF Scorecard public API.

Endpoint: ``GET https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}``

Returns Scorecard's 0.0–10.0 quality score plus per-check breakdown:
Maintained, CI-Tests, Dangerous-Workflow, Pinned-Dependencies, Branch-Protection,
SAST, Vulnerabilities, Token-Permissions, etc. Score < 3.0 is treated as a
RED reputation signal in our summary.

We do not call the GitHub REST API directly for stars / forks / age in this
v0 — Scorecard's signals are higher quality and cover the same threat surface
(maintained, age-of-commit, vulnerabilities). GitHub stars are easy to
fabricate; Scorecard checks are harder.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

SCORECARD_URL_FMT = "https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"


_GITHUB_SOURCE_RE = re.compile(
    r"(?:https?://github\.com/|git@github\.com:|github\.com/)([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)


def _parse_owner_repo(source: str) -> tuple[str, str] | None:
    m = _GITHUB_SOURCE_RE.search(source.strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def _query_scorecard(owner: str, repo: str, *, timeout: int) -> dict | None:
    url = SCORECARD_URL_FMT.format(owner=owner, repo=repo)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError):
        return None


def _bucket(score: float) -> str:
    if score < 3.0:
        return "RED"
    if score < 5.0:
        return "YELLOW"
    return "GREEN"


def lookup(node: dict, *, timeout: int = 10) -> dict | None:
    source = node.get("source") or ""
    parsed = _parse_owner_repo(source)
    if not parsed:
        return {
            "source": "scorecard",
            "target_type": "github_repo",
            "target_name": source,
            "status": "skipped",
            "summary": "Scorecard only supports github.com URLs.",
        }
    owner, repo = parsed
    payload = _query_scorecard(owner, repo, timeout=timeout)
    if payload is None:
        return {
            "source": "scorecard",
            "target_type": "github_repo",
            "target_name": f"{owner}/{repo}",
            "status": "unavailable",
            "summary": f"Scorecard API unreachable for {owner}/{repo}",
        }
    score = float(payload.get("score") or 0.0)
    checks = payload.get("checks") or []
    low_scoring = [
        {"name": c.get("name"), "score": c.get("score")}
        for c in checks
        if isinstance(c.get("score"), (int, float)) and c["score"] <= 2
    ]
    return {
        "source": "scorecard",
        "target_type": "github_repo",
        "target_name": f"{owner}/{repo}",
        "status": "success",
        "score": score,
        "score_bucket": _bucket(score),
        "low_scoring_checks": low_scoring[:10],
        "commit": (payload.get("repo") or {}).get("commit"),
        "date": payload.get("date"),
        "summary": (
            f"Scorecard {owner}/{repo}: score={score:.1f} ({_bucket(score)}), "
            f"{len(low_scoring)} checks ≤ 2/10"
        ),
    }
