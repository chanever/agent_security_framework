"""Shared OSV.dev query helper used by pypi + npm reputation modules."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

OSV_URL = "https://api.osv.dev/v1/query"

# Per-process cache keyed by (ecosystem, name).
_CACHE: dict[tuple[str, str], dict[str, Any]] = {}

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


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


def normalize_severity(vuln: dict) -> str:
    """OSV's severity field has 3 locations depending on the source advisory.
    Check all of them and pick the highest bucket present."""
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


def query(name: str, ecosystem: str, *, timeout: int = 10) -> dict | None:
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
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError):
        return None
    _CACHE[cache_key] = payload
    return payload


def signal_from_payload(name: str, ecosystem: str, payload: dict) -> dict:
    vulns = payload.get("vulns") or []
    severities: list[str] = []
    ids: list[str] = []
    for v in vulns:
        severities.append(normalize_severity(v))
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
