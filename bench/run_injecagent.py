#!/usr/bin/env python3
"""Run a subset of InjecAgent through chanever's GLM verifier — recall only.

Every InjecAgent case is malicious by construction (tool returns containing
attacker-planted instructions). A correct verifier output is anything
non-ALLOW. Recall = (HOLD + BLOCK + ISOLATE + ALLOW_WITH_SANITIZATION) / N.

This is a verifier-only path — no sandbox runs. InjecAgent measures
content-level IPI detection, not runtime side effects.

Usage:
    python bench/run_injecagent.py --limit 50 --out /tmp/injecagent_results.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from security_framework.glm_verifier import verify as glm_verify  # noqa: E402
from bench.translators.injecagent import build_evidence_for_case, load_corpus  # noqa: E402


def _is_block(decision: str) -> bool:
    return decision in {"BLOCK", "HOLD", "ISOLATE", "ALLOW_WITH_SANITIZATION"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=50,
                        help="Cap total cases (default: 50)")
    parser.add_argument("--enhanced", action="store_true",
                        help="Use enhanced (more obfuscated) variant instead of base")
    parser.add_argument("--corpus-root", default="/tmp/InjecAgent/data")
    parser.add_argument("--out", default="/tmp/injecagent_results.json")
    args = parser.parse_args(argv)

    cases = load_corpus(
        base_path=Path(args.corpus_root),
        enhanced=args.enhanced,
        limit=args.limit,
    )
    print(f"loaded {len(cases)} InjecAgent cases (enhanced={args.enhanced})")

    decisions: Counter[str] = Counter()
    by_attack_type: dict[str, list[str]] = {}
    records: list[dict] = []
    detected = 0

    for i, case in enumerate(cases, start=1):
        t0 = time.monotonic()
        evidence = build_evidence_for_case(case)
        try:
            verdict = glm_verify(evidence)
            decision = verdict.get("decision", "ERROR")
        except Exception as exc:
            decision = f"ERROR:{type(exc).__name__}"
            verdict = {"reason": str(exc)[:200]}
        elapsed = time.monotonic() - t0
        blocked = _is_block(decision)
        if blocked:
            detected += 1
        decisions[decision] += 1
        by_attack_type.setdefault(case.attack_type, []).append(decision)
        marker = "✓" if blocked else "✗"
        print(f"  {marker} [{i}/{len(cases)}] {case.case_id}  {case.attack_type:25s} → {decision}  ({elapsed:.1f}s)")
        records.append({
            "case_id": case.case_id,
            "attack_type": case.attack_type,
            "user_tool": case.user_tool,
            "decision": decision,
            "blocked": blocked,
            "reason": (verdict.get("reason") or "")[:300],
            "elapsed_s": elapsed,
        })

    recall = detected / len(cases) if cases else 0.0
    by_attack_recall = {
        atype: sum(1 for d in ds if _is_block(d)) / len(ds)
        for atype, ds in by_attack_type.items()
    }

    print(f"\n=== InjecAgent Recall ===")
    print(f"  N={len(cases)}  detected={detected}  recall={recall:.2%}")
    print(f"  decisions: {dict(decisions)}")
    print(f"  by attack type:")
    for atype, r in sorted(by_attack_recall.items()):
        print(f"    {atype:30s}  {r:.0%}  (n={len(by_attack_type[atype])})")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "summary": {
            "N": len(cases),
            "detected": detected,
            "recall": recall,
            "decisions": dict(decisions),
            "by_attack_type_recall": by_attack_recall,
        },
        "records": records,
    }, indent=2))
    print(f"\nDetails → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
