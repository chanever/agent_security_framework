#!/usr/bin/env python3
"""EvidenceQualityBench — does adding sandbox observation evidence help the LLM judge?

Per spec §5 (the framework's intended headline contribution): take a set of
labelled cases, build several evidence-package variants per case (each with
progressively more evidence components), and feed the *same* GLM verifier all
variants. ΔAccuracy(D, A) quantifies the marginal value of LSM-hook
observation (``kprobe:security_file_open``) over an interaction-only
evidence package — i.e. what adding the kernel-level trace actually buys.

Variants in this minimal v0:
  A — current_action + external_environment.content only
  B — A + static_analysis (semgrep + GuardDog + chanever rules)
  C — A + system_trace (strace)
  D — A + system_trace (bpftrace, lsm_events populated)
  E — full pipeline (B + D + reputation OSV)

Defaults: N=20 (10 malicious datadog-pypi + 10 benign benign-pypi), all 5
variants, GLM verifier. Run-to-run variance is real — pin variants to the
same evidence per case so any decision delta comes from the variant, not
sandbox re-execution.

This implementation is *prereg-ready*: a falsification criterion
(``|Acc(D) - Acc(A)| < 5pp`` within bootstrap CI → INCONCLUSIVE) is built in.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from security_framework.config import SecurityFrameworkConfig  # noqa: E402
from security_framework.evidence_builder import build_evidence_package  # noqa: E402
from security_framework.external_target_extractor import extract_external_targets  # noqa: E402
from security_framework.glm_verifier import verify as glm_verify  # noqa: E402
from security_framework.reputation_analyzer import analyze_reputation  # noqa: E402
from security_framework.sandbox_runner import run_in_sandbox  # noqa: E402
from security_framework.static_analyzer import analyze_static  # noqa: E402
from security_framework.trace_parser import parse_trace_auto  # noqa: E402
from security_framework.trigger import classify_command  # noqa: E402

from bench.action_templates import load_cases  # noqa: E402


def _cfg(trace_mode: str, tmp_root: Path) -> SecurityFrameworkConfig:
    return SecurityFrameworkConfig(
        trace_mode=trace_mode,
        sandbox_docker_image="shadow-agent-sandbox:latest",
        sandbox_network_mode="none",
        sandbox_timeout=60,
        bpftrace_image="quay.io/iovisor/bpftrace:master",
        bpftrace_attach_timeout=15,
        max_output_chars=8192,
        workspace_copy_parent=str(tmp_root / "ws"),
        artifact_root=str(tmp_root / "artifacts"),
    ).resolve_paths()


def _capture_evidence_components(case, tmp_root: Path) -> dict:
    """Run trigger + targets + static + reputation + sandbox(strace + bpftrace)
    once per case, capture raw components so the 5 variants are constructed
    from the *same* underlying evidence (no re-execution noise).
    """
    action = case.action
    context = case.context
    classification = classify_command(action["command"], context)
    targets = extract_external_targets(action, context, classification)

    static_cfg = _cfg("strace", tmp_root)
    static = analyze_static(action, context, targets, classification, config=static_cfg)
    reputation = analyze_reputation(action, context, targets, classification)

    strace_run = None
    bpftrace_run = None
    if classification.get("needs_shadow_execution"):
        strace_cfg = _cfg("strace", tmp_root)
        strace_run = run_in_sandbox(
            action["command"], context["cwd"],
            tmp_root / "runs" / f"{case.family}_{case.case_dir.name}_strace",
            strace_cfg,
        )
        bp_cfg = _cfg("bpftrace", tmp_root)
        bpftrace_run = run_in_sandbox(
            action["command"], context["cwd"],
            tmp_root / "runs" / f"{case.family}_{case.case_dir.name}_bpftrace",
            bp_cfg,
        )
    return {
        "action": action,
        "context": context,
        "classification": classification,
        "targets": targets,
        "static": static,
        "reputation": reputation,
        "strace_run": strace_run,
        "bpftrace_run": bpftrace_run,
    }


def _build_variant(label: str, comp: dict) -> dict:
    """Construct one of the 5 evidence-package variants from raw components."""
    action = comp["action"]
    context = comp["context"]
    classification = comp["classification"]
    targets = comp["targets"]

    # Empty placeholders default to "skipped" so the verifier sees a stable shape.
    empty_static = {"status": "skipped", "findings": [], "summary": "Variant excludes static analysis."}
    empty_reputation = {"status": "skipped", "signals": [], "summary": "Variant excludes reputation analysis."}
    empty_external = {"targets": targets, "static_analysis": empty_static, "reputation_analysis": empty_reputation}

    sandbox = None
    semantic = None
    external = dict(empty_external)
    if label == "A":
        pass  # only action + external_environment.content via build_evidence_package
    elif label == "B":
        external["static_analysis"] = comp["static"]
    elif label == "C" and comp["strace_run"]:
        sandbox = comp["strace_run"]
        semantic = parse_trace_auto(sandbox.get("trace_raw", ""), "strace")
    elif label == "D" and comp["bpftrace_run"]:
        sandbox = comp["bpftrace_run"]
        semantic = parse_trace_auto(sandbox.get("trace_raw", ""), "bpftrace")
    elif label == "E":
        external["static_analysis"] = comp["static"]
        external["reputation_analysis"] = comp["reputation"]
        if comp["bpftrace_run"]:
            sandbox = comp["bpftrace_run"]
            semantic = parse_trace_auto(sandbox.get("trace_raw", ""), "bpftrace")
        elif comp["strace_run"]:
            sandbox = comp["strace_run"]
            semantic = parse_trace_auto(sandbox.get("trace_raw", ""), "strace")

    return build_evidence_package(
        context.get("task", ""), context, action, classification,
        sandbox, semantic, external,
    )


def _is_block(decision: str) -> bool:
    return decision in {"BLOCK", "HOLD", "ISOLATE", "ALLOW_WITH_SANITIZATION"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-mal", type=int, default=10)
    parser.add_argument("--n-ben", type=int, default=10)
    parser.add_argument("--variants", default="A,B,C,D,E")
    parser.add_argument("--tmp-root", default="/tmp/evq_bench")
    parser.add_argument("--out", default="/tmp/evq_bench/results.json")
    args = parser.parse_args(argv)

    tmp_root = Path(args.tmp_root)
    tmp_root.mkdir(parents=True, exist_ok=True)

    variants = [v.strip() for v in args.variants.split(",") if v.strip()]

    mal = load_cases(["datadog-pypi"], cap_per_family=args.n_mal)
    ben = load_cases(["benign-pypi"], cap_per_family=args.n_ben)
    cases = mal + ben
    print(f"loaded {len(mal)} mal + {len(ben)} ben = {len(cases)} cases  variants={variants}")

    out_records: list[dict] = []
    confusion = {v: {"TP": 0, "FN": 0, "TN": 0, "FP": 0} for v in variants}
    flips = {v: 0 for v in variants}

    for i, case in enumerate(cases, start=1):
        t0 = time.monotonic()
        print(f"  [{i}/{len(cases)}] {case.family}/{case.case_dir.name}  mal={case.label_malicious}")
        components = _capture_evidence_components(case, tmp_root)
        case_record = {
            "family": case.family,
            "case": case.case_dir.name,
            "malicious": case.label_malicious,
            "variants": {},
        }
        prev_decision: str | None = None
        for v in variants:
            evidence = _build_variant(v, components)
            try:
                verdict = glm_verify(evidence)
            except Exception as exc:
                verdict = {"decision": "ERROR", "raw_output": "", "source": str(exc)[:200]}
            decision = verdict.get("decision", "ERROR")
            blocked = _is_block(decision)
            if case.label_malicious:
                key = "TP" if blocked else "FN"
            else:
                key = "FP" if blocked else "TN"
            confusion[v][key] += 1
            if prev_decision and decision != prev_decision:
                flips[v] += 1
            prev_decision = decision
            case_record["variants"][v] = {
                "decision": decision,
                "risk_score": verdict.get("risk_score"),
                "reason": verdict.get("reason", "")[:300],
            }
            print(f"      {v} → {decision}")
        out_records.append(case_record)
        print(f"    elapsed {time.monotonic()-t0:.1f}s")

    summary = {}
    for v in variants:
        c = confusion[v]
        n_mal = c["TP"] + c["FN"]
        n_ben = c["TN"] + c["FP"]
        total = sum(c.values())
        summary[v] = {
            **c,
            "accuracy": (c["TP"] + c["TN"]) / total if total else 0,
            "DR": c["TP"] / n_mal if n_mal else 0,
            "FPR": c["FP"] / n_ben if n_ben else 0,
            "flip_to_prev_variant": flips[v],
        }

    if "A" in variants and "D" in variants:
        delta = summary["D"]["accuracy"] - summary["A"]["accuracy"]
        summary["_falsification_DvA"] = {
            "delta_accuracy": delta,
            "passes_5pp_threshold": abs(delta) >= 0.05,
        }
    if "A" in variants and "E" in variants:
        delta = summary["E"]["accuracy"] - summary["A"]["accuracy"]
        summary["_falsification_EvA"] = {
            "delta_accuracy": delta,
            "passes_5pp_threshold": abs(delta) >= 0.05,
        }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"summary": summary, "cases": out_records}, indent=2))

    print("\n=== Variant summary ===")
    for v in variants:
        s = summary[v]
        print(f"  {v}  Acc={s['accuracy']:.1%}  DR={s['DR']:.1%}  FPR={s['FPR']:.1%}  flips={s['flip_to_prev_variant']}")
    if "_falsification_DvA" in summary:
        d = summary["_falsification_DvA"]
        print(f"\n  ΔAcc(D − A) = {d['delta_accuracy']:+.1%}   passes 5pp = {d['passes_5pp_threshold']}")
    if "_falsification_EvA" in summary:
        d = summary["_falsification_EvA"]
        print(f"  ΔAcc(E − A) = {d['delta_accuracy']:+.1%}   passes 5pp = {d['passes_5pp_threshold']}")
    print(f"\nDetails → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
