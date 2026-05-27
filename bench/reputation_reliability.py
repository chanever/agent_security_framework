#!/usr/bin/env python3
"""Reliability check — each reputation module on labelled external sources.

For each of the 4 per-artifact-type reputation modules, run a labelled
panel of sources (known-legit / known-malicious / known-typosquat /
nonexistent / etc.) and print a contingency matrix. The goal is honest
documentation: when the module says X, does X match ground truth?

Usage:
    python bench/reputation_reliability.py
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from reputation.pypi_reputation import lookup as pypi_lookup  # noqa: E402
from reputation.npm_reputation import lookup as npm_lookup  # noqa: E402
from reputation.repo_reputation import lookup as repo_lookup  # noqa: E402
from reputation.skill_reputation import lookup as skill_lookup  # noqa: E402


# ─────────────────────────── corpora ─────────────────────────────────────


# (name, expected) where expected is one of:
#   "benign-popular"      — established package, should NOT flag as known-bad
#   "known-malicious"     — in DataDog and/or OSSF
#   "typosquat-suspect"   — within Levenshtein 2 of a top-100 package
#   "nonexistent"         — name does not exist on the registry
PYPI_PANEL = [
    ("requests", "benign-popular"),
    ("numpy", "benign-popular"),
    ("setuptools", "benign-popular"),
    ("click", "benign-popular"),
    ("0wneg", "known-malicious"),
    ("1337test", "known-malicious"),
    ("EZBEAMER", "known-malicious"),
    ("282828282828282828", "known-malicious"),
    ("PaypalOtpBypass", "known-malicious"),
    ("reqeusts", "typosquat-suspect"),
    ("urlllib3", "typosquat-suspect"),
    ("nymp", "typosquat-suspect"),
    ("not-a-real-pypi-pkg-9d4f2a", "nonexistent"),
]

NPM_PANEL = [
    ("lodash", "benign-popular"),
    ("react", "benign-popular"),
    ("axios", "benign-popular"),
    ("000webhost-api", "known-malicious"),
    ("000webhost-admin", "known-malicious"),
    ("lod4sh", "typosquat-suspect"),
    ("ax1os", "typosquat-suspect"),
    ("not-real-pkg-zzz-9d4f2a", "nonexistent"),
]

REPO_PANEL = [
    ("https://github.com/psf/requests", "benign-popular"),
    ("https://github.com/lodash/lodash", "benign-popular"),
    ("https://github.com/anthropics/claude-skills", "benign-popular"),
    ("https://github.com/this-org-does-not-exist-9d4f2a/x", "nonexistent"),
    ("https://github.com/torvalds/linux", "benign-popular"),
]


# Local skill fixtures — labelled by directory family.
def _skill_panel() -> list[tuple[Path, str]]:
    benign = Path("/home/user/agent-mds/eval/benchmarks/benign-skills")
    malicious_dir = Path("/home/user/agent-mds/eval/benchmarks/skill-inject")
    cases: list[tuple[Path, str]] = []
    if benign.exists():
        for d in sorted(benign.iterdir())[:5]:
            if d.is_dir():
                cases.append((d, "benign-skill"))
    if malicious_dir.exists():
        for d in sorted(malicious_dir.iterdir())[:5]:
            if d.is_dir():
                cases.append((d, "malicious-skill"))
    return cases


# ─────────────────────────── runners ─────────────────────────────────────


def _section(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def run_pypi() -> dict:
    _section("pypi_reputation")
    rows = []
    for name, expected in PYPI_PANEL:
        t0 = time.monotonic()
        r = pypi_lookup({"artifact_type": "pypi_package", "name": name}, timeout=15)
        elapsed = time.monotonic() - t0
        if r is None:
            decision = "no-result"
            kbp = False
            ts = "n/a"
            sources = []
        else:
            kbp = r.get("known_bad_package", False)
            sources = r.get("known_bad_sources", [])
            ts = (r.get("typosquat") or {}).get("status", "?")
            decision = "FLAG-malicious" if kbp else (
                "FLAG-typosquat" if ts == "near" else "clean"
            )
        rows.append({"name": name, "expected": expected, "decision": decision,
                     "known_bad": kbp, "sources": sources, "typosquat": ts,
                     "elapsed_s": round(elapsed, 1)})
        print(f"  {name:30s} expected={expected:20s} → {decision:18s} (KB={kbp} typosquat={ts}) [{elapsed:.1f}s]")
    return {"panel": "pypi", "rows": rows, "summary": _summarize_pypi_npm(rows)}


def run_npm() -> dict:
    _section("npm_reputation")
    rows = []
    for name, expected in NPM_PANEL:
        t0 = time.monotonic()
        r = npm_lookup({"artifact_type": "npm_package", "name": name}, timeout=15)
        elapsed = time.monotonic() - t0
        if r is None:
            decision = "no-result"; kbp = False; ts = "n/a"; sources = []
        else:
            kbp = r.get("known_bad_package", False)
            sources = r.get("known_bad_sources", [])
            ts = (r.get("typosquat") or {}).get("status", "?")
            decision = "FLAG-malicious" if kbp else (
                "FLAG-typosquat" if ts == "near" else "clean"
            )
        rows.append({"name": name, "expected": expected, "decision": decision,
                     "known_bad": kbp, "sources": sources, "typosquat": ts,
                     "elapsed_s": round(elapsed, 1)})
        print(f"  {name:30s} expected={expected:20s} → {decision:18s} (KB={kbp} typosquat={ts}) [{elapsed:.1f}s]")
    return {"panel": "npm", "rows": rows, "summary": _summarize_pypi_npm(rows)}


def run_repo() -> dict:
    _section("repo_reputation")
    rows = []
    for url, expected in REPO_PANEL:
        t0 = time.monotonic()
        r = repo_lookup({"artifact_type": "github_repo", "source": url}, timeout=20)
        elapsed = time.monotonic() - t0
        if r is None:
            decision = "no-result"; bucket = "n/a"
        else:
            bucket = r.get("score_bucket") or r.get("status")
            decision = bucket
        rows.append({"url": url, "expected": expected, "bucket": bucket,
                     "elapsed_s": round(elapsed, 1)})
        print(f"  {url[-50:]:50s} expected={expected:15s} → bucket={bucket} [{elapsed:.1f}s]")
    return {"panel": "repo", "rows": rows}


def run_skill() -> dict:
    _section("skill_reputation")
    panel = _skill_panel()
    rows = []
    for case_dir, expected in panel:
        node = {
            "artifact_type": "skill",
            "name": case_dir.name,
            "scan_root": str(case_dir),
            "source": str(case_dir),
            "instruction_surfaces": ["SKILL.md"],
        }
        r = skill_lookup(node) or {}
        bucket = r.get("trust_bucket", "no-result")
        rows.append({
            "case": case_dir.name,
            "expected": expected,
            "bucket": bucket,
            "author_known_bad": r.get("author_known_bad"),
            "distribution": (r.get("distribution_source") or {}).get("trust"),
        })
        print(f"  {case_dir.name[:50]:50s} expected={expected:18s} → bucket={bucket}")
    return {"panel": "skill", "rows": rows}


def _summarize_pypi_npm(rows: list[dict]) -> dict:
    expected_to_decisions: dict[str, Counter] = {}
    for r in rows:
        expected_to_decisions.setdefault(r["expected"], Counter())[r["decision"]] += 1
    return {k: dict(v) for k, v in expected_to_decisions.items()}


def main() -> int:
    results = {
        "pypi": run_pypi(),
        "npm": run_npm(),
        "repo": run_repo(),
        "skill": run_skill(),
    }
    out = Path("/tmp/reputation_reliability.json")
    out.write_text(json.dumps(results, indent=2))

    _section("Contingency tables — pypi/npm")
    for panel_name in ("pypi", "npm"):
        print(f"\n  --- {panel_name} ---")
        for expected, decisions in results[panel_name]["summary"].items():
            decs = ", ".join(f"{d}={c}" for d, c in sorted(decisions.items()))
            print(f"    expected={expected:20s} → {decs}")

    print(f"\nDetails → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
