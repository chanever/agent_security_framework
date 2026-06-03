#!/usr/bin/env python3
"""Drive ClawVet (Shaikh, github.com/MohibShaikh/clawvet) over the chanever
skill corpus so the two skill-vetting approaches can be compared on the
same input.

ClawVet is a 6-pass skill scanner for the OpenClaw / Claude-skill ecosystem
(YAML frontmatter parser → 54 regex pattern static analysis → metadata
validator → Claude AI semantic analysis → dependency checker → typosquat
detector). It emits a JSON verdict with ``riskScore``, ``riskGrade``
(A-F), and a per-finding severity breakdown.

This wrapper:

  1. Walks the chanever skill families chanever's ``framework_reliability``
     bench fires ``cat SKILL.md`` over (skill-inject, toolhijacker,
     benign-skills, benign-tools).
  2. Runs ``npx tsx packages/cli/src/index.ts scan <case_dir> --format json``
     per case.
  3. Maps the ClawVet verdict to block/allow using ClawVet's own
     ``--fail-on high`` default: any HIGH or CRITICAL finding → block,
     otherwise → allow.
  4. Compares against the chanever label and produces a chanever-shaped
     confusion + rows JSON so the two benches can be plotted side by side.

Per-case cost ≈ a few API calls inside ClawVet's semantic-analysis pass
(Pass 4) plus local regex/parser work; ~5-15s a case on a small SKILL.md.

Usage::

    ANTHROPIC_API_KEY="$(cat ~/.anthropic/api_key)" \\
    python bench/run_clawvet_bench.py --cap 0 \\
        --out /tmp/clawvet_bench/results.json
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
CLAWVET_REPO = Path("/home/user/clawvet")
CLI_ENTRY = CLAWVET_REPO / "packages/cli/src/index.ts"

sys.path.insert(0, str(CHANEVER))
from bench.framework_reliability import _label_by_prefix, _panel                # noqa: E402


def build_panel(cap: int | None) -> list[dict]:
    """Match the chanever bench's skill families verbatim."""
    return (
        _panel("skill-inject",   "malicious",       cap, "cat SKILL.md")
        + _panel("toolhijacker", _label_by_prefix,  cap, "cat SKILL.md")
        + _panel("benign-skills", "benign",         cap, "cat SKILL.md")
        + _panel("benign-tools",  "benign",         cap, "cat SKILL.md")
    )


def parse_verdict(stdout: str) -> tuple[str | None, dict | None]:
    """Read the JSON ClawVet emits on stdout and decide block/allow with the
    same ``--fail-on high`` default ClawVet's CI mode uses: any HIGH or
    CRITICAL severity finding triggers ``block``; otherwise ``allow``.
    """
    text = stdout.strip()
    if not text:
        return None, None
    # ClawVet may print banners before the JSON; locate the first ``{``.
    idx = text.find("{")
    if idx == -1:
        return None, None
    try:
        data = json.loads(text[idx:])
    except json.JSONDecodeError:
        return None, None
    counts = data.get("findingsCount") or {}
    high = int(counts.get("high") or 0)
    crit = int(counts.get("critical") or 0)
    decision = "block" if (high + crit) > 0 else "allow"
    return decision, data


def run_case(case: dict, timeout_s: int) -> dict:
    case_dir = Path(case["cwd"])
    label = case["label"]
    if not case_dir.is_dir() or not (case_dir / "SKILL.md").is_file():
        return {**case, "decision": None, "outcome": "ERR",
                "elapsed_s": 0.0, "error": f"no SKILL.md at {case_dir}"}

    env = dict(os.environ)
    env.setdefault("ANTHROPIC_API_KEY",
                   Path("/home/user/.anthropic/api_key").read_text().strip())

    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            ["npx", "tsx", str(CLI_ENTRY), "scan", str(case_dir),
             "--format", "json"],
            cwd=str(CLAWVET_REPO),
            env=env,
            capture_output=True, text=True,
            timeout=timeout_s, check=False,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        return {**case, "decision": None, "outcome": "ERR",
                "elapsed_s": round(elapsed, 1),
                "error": f"timeout after {timeout_s}s"}
    elapsed = time.monotonic() - t0

    decision, report = parse_verdict(proc.stdout)
    if decision is None:
        return {**case, "decision": None, "outcome": "ERR",
                "elapsed_s": round(elapsed, 1),
                "error": (proc.stderr or "no parseable JSON")[:200]}

    if label == "malicious":
        outcome = "TP" if decision != "allow" else "FN"
    else:
        outcome = "TN" if decision == "allow" else "FP"

    return {
        **case, "decision": decision, "outcome": outcome,
        "elapsed_s": round(elapsed, 1),
        "risk_score": (report or {}).get("riskScore"),
        "risk_grade": (report or {}).get("riskGrade"),
        "findings_count": (report or {}).get("findingsCount"),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cap", type=int, default=0,
                        help="cases per family (0 = all). ~79 total skill cases.")
    parser.add_argument("--families", default="",
                        help="comma-separated subset of {skill-inject, "
                             "toolhijacker, benign-skills, benign-tools}.")
    parser.add_argument("--out", default="/tmp/clawvet_bench/results.json")
    parser.add_argument("--timeout", type=int, default=120,
                        help="per-case timeout (s).")
    parser.add_argument("--resume", action="store_true",
                        help="read --out and skip already-completed (family, case).")
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    panel = build_panel(args.cap or None)
    if args.families:
        keep = {f.strip() for f in args.families.split(",") if f.strip()}
        panel = [p for p in panel if p["family"] in keep]

    rows: list[dict] = []
    if args.resume and out_path.is_file():
        try:
            rows = list(json.loads(out_path.read_text()).get("rows") or [])
        except (json.JSONDecodeError, OSError):
            rows = []
    done = {(r.get("family"), r.get("case")) for r in rows}
    panel = [p for p in panel if (p["family"], p["case"]) not in done]
    print(f"panel: {len(panel)} pending ({len(rows)} already complete)\n")

    confusion: Counter = Counter(r.get("outcome", "ERR") for r in rows)
    confusion_per_family: dict[str, Counter] = {}
    for r in rows:
        confusion_per_family.setdefault(r.get("family", ""), Counter())[r.get("outcome", "ERR")] += 1

    for case in panel:
        row = run_case(case, args.timeout)
        rows.append(row)
        confusion[row["outcome"]] += 1
        confusion_per_family.setdefault(row["family"], Counter())[row["outcome"]] += 1
        mark = {"TP": "✓", "TN": "✓"}.get(row["outcome"], "✗")
        grade = row.get("risk_grade") or "-"
        score = row.get("risk_score") if row.get("risk_score") is not None else "-"
        print(f"  {mark} [{row['outcome']:3s}] {case['family']:14s}/{case['case'][:35]:35s} "
              f"→ {(row.get('decision') or 'ERR'):5s} grade={grade} score={score} "
              f"[{row.get('elapsed_s','?')}s]")
        out_path.write_text(json.dumps({
            "confusion_total": dict(confusion),
            "confusion_per_family": {k: dict(v) for k, v in confusion_per_family.items()},
            "rows": rows,
        }, indent=2, default=str))

    print(f"\nConfusion: {dict(confusion)}")
    print(f"Per-family: {dict({k: dict(v) for k, v in confusion_per_family.items()})}")
    print(f"Details   → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
