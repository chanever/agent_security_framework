"""Reputation analyzer — OSV.dev API integration.

Replaces the chanever placeholder with a real call to https://osv.dev (Google's
public Open Source Vulnerabilities database, no auth required). For each
``package`` target in an external interaction the analyzer queries OSV's
ecosystem-aware vuln index and folds the result into a normalized signals list
that the verifier can read.

Status taxonomy:
- ``skipped``: ``external_env=false`` OR no package-shaped targets
- ``success``: API call returned (per-target signals included even when empty)
- ``unavailable``: network failure / non-JSON response

Each finding becomes one signal entry:

    {
      "source": "osv",
      "target_type": "package",
      "target_name": "<pkg>",
      "ecosystem": "PyPI" | "npm" | …,
      "vuln_count": <int>,
      "severities": ["CRITICAL", "HIGH", ...],
      "ids": ["GHSA-...", "CVE-..."],
      "summary": "OSV: N vulns (X CRITICAL, Y HIGH, ...)"
    }

A small in-process cache (``_CACHE``) avoids hitting OSV more than once per
``(ecosystem, name)`` pair within a single Python session — meaningful for
benchmark runs that hit the same package across cases.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

OSV_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT_S = 10

# Map our target-extractor ecosystem ids to OSV's canonical names.
_OSV_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
}

# Per-process cache keyed by (ecosystem, name).
_CACHE: dict[tuple[str, str], dict[str, Any]] = {}

# Severity buckets — OSV's CVSS strings are normalized into these.
_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def skipped_result(reason: str = "No external package, repo, URL, or source target detected.") -> dict:
    return {
        "status": "skipped",
        "signals": [],
        "summary": reason,
    }


def _severity_from_string(s: str) -> str:
    s = s.upper()
    if "CRITICAL" in s:
        return "CRITICAL"
    if "HIGH" in s:
        return "HIGH"
    if "MEDIUM" in s or "MODERATE" in s:
        return "MEDIUM"
    if "LOW" in s:
        return "LOW"
    return ""


def _normalize_severity(vuln: dict) -> str:
    """Resolve OSV's polymorphic severity into a single bucket.

    OSV stores severity in three different places depending on the source
    advisory: (1) ``severity[].score`` as a CVSS vector, (2)
    ``database_specific.severity`` as a level string (GitHub Advisory uses
    this), (3) ``affected[].database_specific.severity``. Check all of them.
    """
    for entry in vuln.get("severity") or []:
        bucket = _severity_from_string(entry.get("score") or "")
        if bucket:
            return bucket
    ds = (vuln.get("database_specific") or {}).get("severity") or ""
    bucket = _severity_from_string(ds)
    if bucket:
        return bucket
    for affected in vuln.get("affected") or []:
        ads = (affected.get("database_specific") or {}).get("severity") or ""
        bucket = _severity_from_string(ads)
        if bucket:
            return bucket
    return "UNKNOWN"


def _query_osv(name: str, ecosystem: str, *, timeout: int = DEFAULT_TIMEOUT_S) -> dict | None:
    """Single OSV POST. Returns the parsed payload or None on failure."""
    cache_key = (ecosystem, name)
    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError):
        return None
    _CACHE[cache_key] = payload
    return payload


def _signal_from_payload(name: str, ecosystem: str, payload: dict) -> dict:
    vulns = payload.get("vulns") or []
    severities: list[str] = []
    ids: list[str] = []
    for v in vulns:
        severities.append(_normalize_severity(v))
        if v.get("id"):
            ids.append(v["id"])
    counts = {bucket: severities.count(bucket) for bucket in _SEV_ORDER}
    summary = (
        f"OSV: {len(vulns)} vulns "
        f"(CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, "
        f"MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']})"
    )
    return {
        "source": "osv",
        "target_type": "package",
        "target_name": name,
        "ecosystem": ecosystem,
        "vuln_count": len(vulns),
        "severities": severities,
        "ids": ids[:20],
        "summary": summary,
    }


def analyze_reputation(
    action: dict,
    context: dict,
    targets: list[dict],
    classification: dict,
    *,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict:
    """Per-artifact-type reputation lookup via the dispatcher.

    Each artifact node (from ``artifact_classifier.classify``) is routed to
    its type-specific lookup (PyPI/npm → OSV, github_repo → OpenSSF
    Scorecard, skill → manifest heuristic). Signals are concatenated and
    summary aggregates per-type counts.
    """
    if not classification.get("external_env") or not targets:
        return skipped_result()

    from security_framework import artifact_classifier
    from security_framework import reputation as _reputation_pkg

    nodes = artifact_classifier.classify(targets or [], context=context or {})
    if not nodes:
        return skipped_result("No artifact graph nodes for reputation lookup.")

    signals: list[dict] = []
    failures: list[str] = []
    for node in nodes:
        sig = _reputation_pkg.lookup_node(node, timeout=timeout)
        if sig is None:
            continue  # type without a reputation source — silently skipped
        if sig.get("status") == "unavailable":
            failures.append(f"{node['artifact_type']}:{node.get('name','')}")
            continue
        if sig.get("status") == "skipped":
            continue
        signals.append(sig)

    if not signals and failures:
        return {
            "status": "unavailable",
            "signals": [],
            "summary": f"Reputation lookups unreachable for: {', '.join(failures[:5])}",
        }

    # Aggregate per-source for the summary line.
    crit = sum(s.get("severities", []).count("CRITICAL") for s in signals)
    high = sum(s.get("severities", []).count("HIGH") for s in signals)
    total_vulns = sum(int(s.get("vuln_count", 0)) for s in signals)
    by_source: dict[str, int] = {}
    for s in signals:
        by_source[s.get("source", "?")] = by_source.get(s.get("source", "?"), 0) + 1
    parts = [f"{n} {src}" for src, n in sorted(by_source.items())]
    summary = (
        f"Reputation: {len(signals)} signals ({', '.join(parts)}); "
        f"{total_vulns} total vulns ({crit} CRITICAL, {high} HIGH)"
    )
    if failures:
        summary += f"; {len(failures)} lookup failures"
    return {
        "status": "success",
        "signals": signals,
        "summary": summary,
    }
