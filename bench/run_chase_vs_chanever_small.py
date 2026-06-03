#!/usr/bin/env python3
"""Head-to-head bench: CHASE vs our chanever framework on the same
CHASE-paper-shaped benign corpus.

The original CHASE paper sampled 2,500 small newly-published PyPI
packages filtered to "must contain both setup.py and __init__.py". Our
top-PyPI benign corpus didn't match that distribution (popular libraries
ship pyproject.toml-only, and source trees are large enough to blow
through Anthropic Tier-1's 30k tokens/min limit during CHASE's
multi-agent traversal). ``build_chase_compatible_corpus.py`` walks
PyPI's recent-upload RSS feeds to assemble a corpus that matches the
paper's filter.

For each case we run both frameworks on the same unpacked package and
log the decision side by side. Output is one JSON file with the per-row
verdict from each framework plus an aggregate confusion summary.
"""

from __future__ import annotations

import argparse
import inspect as _i
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

CORPUS = CHANEVER / "bench/corpora/chase_compatible_ben"

sys.path.insert(0, str(CHANEVER))
from security_framework.config import SecurityFrameworkConfig                        # noqa: E402
from security_framework.safeguard.shadow_sandbox_safeguard import ShadowSandboxSafeguard  # noqa: E402


# ──────────────────────────── per-case helpers ──────────────────────────────

def _setup_py_dir(case_dir: Path) -> Path | None:
    """Locate the directory inside ``case_dir`` that holds setup.py — both
    CHASE and our scanner expect that as the scan root."""
    for setup in case_dir.rglob("setup.py"):
        return setup.parent
    return None


def _run_chase(pkg_dir: Path, timeout_s: int) -> tuple[str | None, float, str]:
    """Run CHASE on ``pkg_dir`` and parse its structured verdict.
    Returns ``(decision, elapsed, note)``. ``decision`` is ``block`` /
    ``allow`` / None."""
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
        return None, round(time.monotonic() - t0, 1), "timeout"
    elapsed = round(time.monotonic() - t0, 1)
    report = pkg_dir / "structured-final-summary.json"
    if not report.is_file():
        return None, elapsed, "no_verdict_file"
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None, elapsed, "verdict_unparseable"
    verdict = (data.get("final_verdict") or "").lower()
    if verdict == "malicious":
        return "block", elapsed, ""
    if verdict == "benign":
        return "allow", elapsed, ""
    return None, elapsed, f"unknown_verdict:{verdict!r}"


def _run_chanever(pkg_dir: Path, name: str, sg: ShadowSandboxSafeguard) -> tuple[str | None, float, dict]:
    """Run our framework's ``safeguard.inspect()`` with the same
    install-command shape ``framework_reliability.py`` uses, on the same
    setup.py directory. Returns ``(decision, elapsed, evidence_stage_status)``."""
    action = {
        "type": "command",
        "command": f"pip install {name}",
        "reason": "Install the requested package as a project dependency.",
    }
    context = {
        "cwd": str(pkg_dir),
        "history": [
            {"step": 0,
             "action": {"type": "command", "command": "ls", "reason": "list workspace"},
             "stdout": "<workspace files listed>",
             "exit_code": 0}
        ],
        "step": 1,
        "task": f"Install the {name} package for the current project.",
        "run_id": f"chasecompat_{name}",
    }
    t0 = time.monotonic()
    try:
        res = sg.inspect(action, context)
    except Exception as exc:                                                         # noqa: BLE001
        return None, round(time.monotonic() - t0, 1), {"error": f"{type(exc).__name__}: {exc}"[:200]}
    elapsed = round(time.monotonic() - t0, 1)
    decision = res.get("decision")
    stages = {
        "static_status": (((res or {}).get("evidence_package") or {}).get("external_interaction_analysis") or {}).get("static_analysis", {}).get("status") if False else None,
        "reason": str(res.get("reason", ""))[:160],
    }
    return decision, elapsed, stages


# ────────────────────────────────── main ────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/tmp/chase_vs_chanever_small.json")
    parser.add_argument("--timeout", type=int, default=900,
                        help="per-case CHASE subprocess timeout (s).")
    parser.add_argument("--resume", action="store_true",
                        help="skip cases already present in --out.")
    parser.add_argument("--skip-chase", action="store_true",
                        help="run our chanever framework only.")
    parser.add_argument("--skip-chanever", action="store_true",
                        help="run CHASE only.")
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    if args.resume and out_path.is_file():
        try:
            rows = list(json.loads(out_path.read_text()).get("rows") or [])
        except (json.JSONDecodeError, OSError):
            rows = []
    done = {r["case"] for r in rows}

    cases = sorted([p for p in CORPUS.iterdir() if p.is_dir()])
    pending = [p for p in cases if p.name not in done]
    print(f"corpus: {len(cases)} cases ({len(pending)} pending, {len(done)} cached)\n")

    cfg = SecurityFrameworkConfig.from_env()
    sg = ShadowSandboxSafeguard(cfg) if "config" in _i.signature(ShadowSandboxSafeguard.__init__).parameters else ShadowSandboxSafeguard()

    chase_conf: Counter = Counter()
    chanever_conf: Counter = Counter()
    for r in rows:
        if (r.get("chase") or {}).get("outcome"):
            chase_conf[r["chase"]["outcome"]] += 1
        if (r.get("chanever") or {}).get("outcome"):
            chanever_conf[r["chanever"]["outcome"]] += 1

    for case in pending:
        pkg_dir = _setup_py_dir(case)
        if pkg_dir is None:
            row = {"case": case.name, "skipped": "no setup.py"}
            rows.append(row)
            continue

        row: dict = {"case": case.name, "pkg_dir": str(pkg_dir)}

        # all corpus packages are sampled-benign by construction
        label = "benign"

        if not args.skip_chase:
            decision, elapsed, note = _run_chase(pkg_dir, args.timeout)
            outcome = ("TN" if decision == "allow" else "FP") if decision else "ERR"
            row["chase"] = {"decision": decision, "outcome": outcome,
                            "elapsed_s": elapsed, "note": note}
            chase_conf[outcome] += 1
            print(f"  [CHASE   {outcome:3s}] {case.name:36s} → {decision or 'ERR':5s} [{elapsed}s] {note}")

        if not args.skip_chanever:
            decision, elapsed, stages = _run_chanever(pkg_dir, case.name, sg)
            outcome = ("TN" if decision == "allow" else "FP") if decision else "ERR"
            row["chanever"] = {"decision": decision, "outcome": outcome,
                               "elapsed_s": elapsed, **stages}
            chanever_conf[outcome] += 1
            print(f"  [chanever {outcome:3s}] {case.name:36s} → {decision or 'ERR':5s} [{elapsed}s]")

        rows.append(row)
        out_path.write_text(json.dumps({
            "label": label,
            "chase_confusion": dict(chase_conf),
            "chanever_confusion": dict(chanever_conf),
            "rows": rows,
        }, indent=2, default=str))

    print(f"\nCHASE confusion:    {dict(chase_conf)}")
    print(f"chanever confusion: {dict(chanever_conf)}")
    print(f"Details → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
