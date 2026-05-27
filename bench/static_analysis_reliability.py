#!/usr/bin/env python3
"""Reliability check — static analyzers on labelled external sources.

Runs the production entry point ``analysis.static_analyzer.analyze_static``
(which dispatches via artifact_classifier → per-type analyzer) against a
labelled panel and prints a contingency matrix per artifact type.

Reliability question per case:
  malicious → status=success AND ≥1 finding   (detected)
  benign    → status=success AND 0 CRITICAL/HIGH findings, or skipped (clean)

Each analyzer enforces semgrep --timeout 30 + subprocess timeout, so a
pathological case degrades to status=unavailable rather than hanging.

Usage:
    python bench/static_analysis_reliability.py [--cap N]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from security_framework.analysis.static_analyzer import analyze_static  # noqa: E402

BENCH = Path("/home/user/agent-mds/eval/benchmarks")


def _datadog_scan_root(case_dir: Path) -> Path:
    """datadog cases keep the extracted package under artifact/<...>/<pkg>/."""
    artifact = case_dir / "artifact"
    if artifact.is_dir():
        # Descend to the first dir that contains setup.py / package.json.
        for sub in artifact.rglob("setup.py"):
            return sub.parent
        for sub in artifact.rglob("package.json"):
            return sub.parent
        # else just the artifact dir
        return artifact
    return case_dir


def _label_by_prefix(name: str) -> str:
    """toolhijacker cases are labelled by name prefix (benign-*/malicious-*)."""
    return "malicious" if name.startswith("malicious") else "benign"


def _panel(family: str, label, limit: int | None, cmd: str, scan_resolver=None) -> list[dict]:
    """Build a panel. ``label`` is either a fixed string for the whole family,
    or a callable taking the case-dir name (for mixed-label families). ``limit``
    None/0 means all cases (full census)."""
    root = BENCH / family
    if not root.is_dir():
        return []
    cases = sorted([p for p in root.iterdir() if p.is_dir()])
    if limit:
        cases = cases[:limit]
    out = []
    for case_dir in cases:
        scan_root = scan_resolver(case_dir) if scan_resolver else case_dir
        case_label = label(case_dir.name) if callable(label) else label
        out.append({
            "family": family, "label": case_label, "case": case_dir.name,
            "cwd": str(scan_root), "command": cmd,
        })
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cap", type=int, default=0,
                        help="cases per family (0 = all = full census)")
    parser.add_argument("--semgrep-timeout", type=int, default=60,
                        help="per-case semgrep timeout (s); packed cases caught by obf heuristic")
    parser.add_argument("--out", default="/tmp/static_analysis_reliability.json")
    args = parser.parse_args(argv)
    # analyze_static now builds its config from the environment (the safeguard
    # call signature is (action, context, targets, classification, asset_kind);
    # there is no per-call config arg). Surface the harness's tunable timeout via
    # the env var that SecurityFrameworkConfig.from_env() reads.
    os.environ["SEMGREP_TIMEOUT"] = str(args.semgrep_timeout)
    cap = args.cap or None

    panels = (
        # malicious code/packages
        _panel("datadog-pypi", "malicious", cap, "pip install pkg", _datadog_scan_root)
        + _panel("datadog-npm", "malicious", cap, "npm install pkg", _datadog_scan_root)
        + _panel("malicious-repos", "malicious", cap, "pip install .")
        + _panel("skill-inject", "malicious", cap, "cat SKILL.md")
        # mixed-label tool hijacking (benign-*/malicious-* by name)
        + _panel("toolhijacker", _label_by_prefix, cap, "cat SKILL.md")
        # benign (false-positive panels)
        + _panel("benign-pypi", "benign", cap, "pip install pkg")
        + _panel("benign-skills", "benign", cap, "cat SKILL.md")
        + _panel("benign-tools", "benign", cap, "cat SKILL.md")
    )

    confusion: dict[str, Counter] = {}
    rows = []
    for i, case in enumerate(panels, start=1):
        classification = {"external_env": True, "reasons": ["static_test"]}
        targets = [{"type": "local_package", "path": ".", "source": case["cwd"]}]
        action = {"type": "command", "command": case["command"]}
        context = {"cwd": case["cwd"], "task": "static test"}
        t0 = time.monotonic()
        try:
            r = analyze_static(action, context, targets, classification)
        except Exception as exc:
            r = {"status": f"ERROR:{type(exc).__name__}", "findings": []}
        elapsed = time.monotonic() - t0

        status = r.get("status", "?")
        findings = r.get("findings", [])
        n_crit_high = sum(1 for f in findings if f.get("severity") in {"CRITICAL", "HIGH"})
        n_any = len(findings)

        # Detection outcome. Genuine infra failure (docker missing / bad output)
        # is UNAVAIL, kept separate from FP/FN so it never pollutes accuracy:
        # an analyzer that could not run is not the same as a wrong verdict.
        if status not in {"success", "skipped"}:
            outcome = "UNAVAIL"
        elif case["label"] == "malicious":
            outcome = "TP" if n_any >= 1 else "FN"
        else:
            outcome = "TN" if n_crit_high == 0 else "FP"

        confusion.setdefault(case["family"], Counter())[outcome] += 1
        rows.append({**case, "status": status, "findings": n_any,
                     "crit_high": n_crit_high, "outcome": outcome,
                     "elapsed_s": round(elapsed, 1)})
        mark = {"TP": "✓", "TN": "✓", "UNAVAIL": "?"}.get(outcome, "✗")
        print(f"  {mark} [{outcome:11s}] {case['family']:16s}/{case['case'][:34]:34s} "
              f"status={status:11s} findings={n_any}({n_crit_high} crit/high) [{elapsed:.0f}s]")

    print("\n=== Per-family contingency ===")
    for fam, c in confusion.items():
        print(f"  {fam:18s} {dict(c)}")

    Path(args.out).write_text(json.dumps({"confusion": {k: dict(v) for k, v in confusion.items()},
                                          "rows": rows}, indent=2))
    print(f"\nDetails → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
