#!/usr/bin/env python3
"""Drive CHASE (Collaborative Hierarchical Agents for Security Exploration) over
the chanever framework reliability corpus so the two PyPI-malware approaches
can be compared head-to-head.

CHASE (AIware 2025, Toda & Mori, arXiv:2601.06838) is a multi-agent LLM that
inspects an unpacked PyPI package: a Supervisor LLM plans, Worker LLMs run a
Deobfuscator + Web Researcher, and a Formatter produces a structured verdict
(`malicious` | `benign`). Reported numbers: 98.4% recall, 0.08% FP on 3000
packages.

This wrapper:

  1. Reuses chanever's bench panel construction so the case list is identical
     to ``framework_reliability.py``.
  2. Restricts to the pypi families (``datadog-pypi`` + ``benign-pypi``) —
     CHASE inspects setup.py / Python source, so npm / repo / skill cases
     fall outside its threat model.
  3. Points CHASE at each case's already-unpacked artifact dir (the same
     ``scan_root`` chanever's bench uses).
  4. Reads CHASE's ``structured-final-summary.json`` for the ``final_verdict``
     field, maps ``malicious`` → block, ``benign`` → allow.
  5. Builds the same TP/TN/FP/FN confusion + metrics chanever's bench emits
     so the two can be compared by source type.

Patches expected on the CHASE side (see /home/user/chase):
  * ``run_chase.py`` accepts ``--llm-runner anthropic`` (no local GPU needed).
  * ``.env`` carries ``ANTHROPIC_API_KEY`` and Deno is on ``PATH``.

Per-case cost: 6-10 Anthropic API calls + several DuckDuckGo searches,
≈3-5 minutes. ``--cap 5`` (50 cases) ≈ 3-4h. Start small.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

CHANEVER = Path("/home/user/agent_security_framework")
CHASE_REPO = Path("/home/user/chase")
CHASE_PY = CHASE_REPO / ".venv/bin/python"
DENO_BIN_DIR = Path("/home/user/.deno/bin")

sys.path.insert(0, str(CHANEVER))
from bench.framework_reliability import _datadog_scan_root, _panel               # noqa: E402


# ─────────────────────────── panel + verdict ──────────────────────────────

def build_panel(cap: int | None) -> list[dict]:
    """Only the two PyPI families — CHASE's threat model is malicious PyPI
    packages, so npm / repo / skill cases don't apply."""
    return (
        _panel("datadog-pypi", "malicious", cap, "pip install {name}", _datadog_scan_root)
        + _panel("benign-pypi", "benign",    cap, "pip install {name}", _datadog_scan_root)
    )


def parse_verdict(pkg_dir: Path) -> str | None:
    """Read CHASE's ``structured-final-summary.json`` from the package dir
    and return chanever-shaped ``block`` / ``allow`` (or None on error)."""
    report = pkg_dir / "structured-final-summary.json"
    if not report.is_file():
        return None
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    verdict = (data.get("final_verdict") or "").lower()
    if verdict == "malicious":
        return "block"
    if verdict == "benign":
        return "allow"
    return None


# ─────────────────────────── per-case driver ───────────────────────────────

def _resolve_pkg_dir(case_cwd: Path) -> Path | None:
    """CHASE requires ``setup.py`` (its ``collect_entrypoint_sourcecodes``
    walker raises ``ValueError: min() iterable argument is empty`` when
    only ``pyproject.toml`` is present). The chanever bench's
    ``_datadog_scan_root`` descends to the dir owning setup.py or
    package.json, but for modern PyPI packages (django, fastapi, attrs,
    …) shipped pyproject.toml-only that resolution lands at
    ``<case>/artifact/`` — those packages fall outside CHASE's evaluation
    scope (paper confirms its dataset is filtered to packages that have
    both setup.py and __init__.py), so return None and let the caller
    classify it as "not applicable to CHASE".
    """
    if (case_cwd / "setup.py").is_file():
        return case_cwd
    for hit in case_cwd.rglob("setup.py"):
        return hit.parent
    return None


def run_case(case: dict, timeout_s: int, force: bool) -> dict:
    case_cwd = Path(case["cwd"]).resolve()
    pkg_dir = _resolve_pkg_dir(case_cwd)
    label = case["label"]

    if pkg_dir is None:
        return {**case, "decision": None, "outcome": "ERR",
                "elapsed_s": 0.0,
                "error": f"out of CHASE scope (no setup.py under {case_cwd}; "
                         f"likely pyproject.toml-only modern package)"}

    report = pkg_dir / "structured-final-summary.json"
    if not force and report.is_file():
        # already have a verdict for this case dir — skip the LLM run
        decision = parse_verdict(pkg_dir)
        outcome = _classify(label, decision)
        return {**case, "decision": decision, "outcome": outcome,
                "elapsed_s": 0.0, "cached": True}

    env = dict(os.environ)
    env["PATH"] = f"{DENO_BIN_DIR}:{env.get('PATH', '')}"

    t0 = time.monotonic()
    try:
        subprocess.run(
            [str(CHASE_PY), "run_chase.py",
             "--pkg-dirpath", str(pkg_dir),
             "--llm-runner", "anthropic"],
            cwd=str(CHASE_REPO),
            env=env,
            capture_output=True, text=True, timeout=timeout_s, check=False,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        return {**case, "decision": None, "outcome": "ERR",
                "elapsed_s": round(elapsed, 1),
                "error": f"timeout after {timeout_s}s"}
    elapsed = time.monotonic() - t0

    decision = parse_verdict(pkg_dir)
    outcome = _classify(label, decision)
    return {**case, "decision": decision, "outcome": outcome,
            "elapsed_s": round(elapsed, 1)}


def _classify(label: str, decision: str | None) -> str:
    if decision is None:
        return "ERR"
    if label == "malicious":
        return "TP" if decision != "allow" else "FN"
    return "TN" if decision == "allow" else "FP"


# ──────────────────────────────── main ─────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cap", type=int, default=3,
                        help="cases per family (0 = full; default 3 ≈ 6 cases).")
    parser.add_argument("--families", default="",
                        help="comma-separated subset of {datadog-pypi, benign-pypi}.")
    parser.add_argument("--out", default="/tmp/chase_bench/results.json")
    parser.add_argument("--timeout", type=int, default=900,
                        help="per-case timeout (s).")
    parser.add_argument("--force", action="store_true",
                        help="re-run CHASE even if a verdict report already exists "
                             "in the package dir.")
    parser.add_argument("--resume", action="store_true",
                        help="read --out if present, skip already-completed "
                             "(family, case) rows, checkpoint after each case.")
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    panels = build_panel(args.cap or None)
    if args.families:
        keep = {f.strip() for f in args.families.split(",") if f.strip()}
        panels = [p for p in panels if p["family"] in keep]

    rows: list[dict] = []
    if args.resume and out_path.is_file():
        try:
            rows = list(json.loads(out_path.read_text()).get("rows") or [])
        except (json.JSONDecodeError, OSError):
            rows = []
    done = {(r.get("family"), r.get("case")) for r in rows}
    panels = [p for p in panels if (p["family"], p["case"]) not in done]
    print(f"panel size: {len(panels)} pending ({len(rows)} already complete)\n")

    confusion: Counter = Counter(r.get("outcome", "ERR") for r in rows)
    for case in panels:
        row = run_case(case, args.timeout, args.force)
        rows.append(row)
        confusion[row["outcome"]] += 1
        mark = {"TP": "✓", "TN": "✓"}.get(row["outcome"], "✗")
        tag = "cache" if row.get("cached") else f"{row.get('elapsed_s','?')}s"
        print(f"  {mark} [{row['outcome']:3s}] {case['family']:18s}/{case['case'][:35]:35s} "
              f"→ {(row.get('decision') or 'ERR'):5s} [{tag}]")
        out_path.write_text(json.dumps(
            {"confusion": dict(confusion), "rows": rows},
            indent=2, default=str,
        ))

    print(f"\nConfusion: {dict(confusion)}")
    print(f"Details   → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
