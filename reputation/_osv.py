"""Shared OSV.dev query helper used by pypi + npm reputation modules."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from packaging.version import InvalidVersion, Version

OSV_URL = "https://api.osv.dev/v1/query"

# Per-process cache keyed by (ecosystem, name).
_CACHE: dict[tuple[str, str], dict[str, Any]] = {}

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _pypi_range_covers(target_ver: Version, range_obj: dict) -> bool:
    """Walk the OSV ``events`` array (introduced/fixed/last_affected) for a
    single ``affected.ranges[]`` entry and decide whether ``target_ver`` is
    inside it. PEP 440 semantics — the version arithmetic is delegated to
    ``packaging.version``.
    """
    introduced = fixed = last_affected = None
    for e in range_obj.get("events", []) or []:
        if "introduced" in e:
            introduced = e["introduced"]
        elif "fixed" in e:
            fixed = e["fixed"]
        elif "last_affected" in e:
            last_affected = e["last_affected"]
    try:
        if introduced and introduced != "0" and target_ver < Version(introduced):
            return False
        if fixed and target_ver >= Version(fixed):
            return False
        if last_affected and target_ver > Version(last_affected):
            return False
    except InvalidVersion:
        return True  # malformed range bound → conservative keep
    return True


def vuln_affects_version(vuln: dict, ecosystem: str, target_version: str | None) -> bool:
    """Whether the OSV vulnerability record applies to ``target_version``.
    Returns True when ``target_version`` is None (no filter) or when any
    ``affected[*]`` entry lists the version explicitly or covers it via a
    PyPI range. For non-PyPI ecosystems only exact ``versions`` matches
    drop a vuln — ranges keep it (conservative)."""
    if not target_version:
        return True
    parsed: Version | None = None
    if ecosystem.lower() in {"pypi", "pypi-multi"}:
        try:
            parsed = Version(target_version)
        except InvalidVersion:
            return True
    for affected in vuln.get("affected") or []:
        versions = affected.get("versions") or []
        if target_version in versions:
            return True
        if parsed is None:
            continue
        for range_obj in affected.get("ranges") or []:
            if range_obj.get("type") in {"ECOSYSTEM", "SEMVER"} and _pypi_range_covers(parsed, range_obj):
                return True
    return False


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


def signal_from_payload(
    name: str, ecosystem: str, payload: dict,
    target_version: str | None = None,
) -> dict:
    """Reduce an OSV query payload into a chanever-shaped reputation signal.
    When ``target_version`` is given, only vulnerabilities whose affected
    ranges actually cover that version count toward ``vuln_count`` — past
    CVEs fixed before the version the agent is installing don't accumulate
    as evidence the verifier has to argue against.
    """
    all_vulns = payload.get("vulns") or []
    vulns = [v for v in all_vulns if vuln_affects_version(v, ecosystem, target_version)]
    severities: list[str] = []
    ids: list[str] = []
    for v in vulns:
        severities.append(normalize_severity(v))
        if v.get("id"):
            ids.append(v["id"])
    counts = {bucket: severities.count(bucket) for bucket in _SEV_ORDER}
    ver_tag = f", version={target_version}" if target_version else ""
    summary = (
        f"OSV: {len(vulns)}/{len(all_vulns)} vulns affect{ver_tag} "
        f"(CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, "
        f"MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']})"
    )
    return {
        "source": "osv",
        "target_type": "package",
        "target_name": name,
        "target_version": target_version,
        "ecosystem": ecosystem,
        "vuln_count": len(vulns),
        "vuln_count_all_versions": len(all_vulns),
        "severities": severities,
        "ids": ids[:20],
        "summary": summary,
    }
