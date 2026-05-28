#!/usr/bin/env python3
"""Framework-level reliability benchmark.

Drives the *full* safeguard pipeline (classification → external target
extraction → asset_kind classifier → static_analyzers → reputation → shadow
sandbox → evidence builder → Claude CLI verifier → decision) over the same
labelled corpora the static/reputation module benches use, and reports a
per-family confusion matrix on the safeguard's final ``decision``.

Reads cases from ``/home/user/agent-mds/eval/benchmarks/{family}`` and feeds
each one through ``ShadowSandboxSafeguard.inspect(action, context)``. Per-case
the script also records the evidence package's stage statuses so it is
visible *why* the framework decided as it did (asset_kind / static /
reputation / sandbox).

Outcome semantics (per case, vs label):
  * malicious / mixed-malicious → ``decision != "allow"`` → **TP** (the
    framework correctly stopped real execution); ``decision == "allow"`` → **FN**
  * benign / mixed-benign       → ``decision == "allow"`` → **TN**;
    anything else → **FP**
  * exception while running the pipeline → **ERR** (kept separate so infra
    failures do not pollute accuracy)

Time budget: roughly 60-80s per case (Claude CLI asset_kind + sandbox +
docker semgrep + reputation + Claude CLI verifier). Start with a small
``--cap`` and scale up — full 192 census is multi-hour.

Run with everything on (mirrors README ``전체 동작 흐름``)::

    SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \\
    SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \\
    VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \\
    CLAUDE_CLI_MAX_TURNS=12 \\
    python bench/framework_reliability.py --cap 3
"""
from __future__ import annotations

import argparse
import inspect as _i
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from security_framework.config import SecurityFrameworkConfig                       # noqa: E402
from security_framework.safeguard.shadow_sandbox_safeguard import ShadowSandboxSafeguard  # noqa: E402

BENCH = Path("/home/user/agent-mds/eval/benchmarks")


# ───────────── per-family agent-scenario templates ─────────────
# The README's `examples/` scenarios run vulnerable_cli_agent with --task and
# --workspace. To match that flow each case feeds the framework not just a
# raw command but a realistic (user_task + agent history + action reason)
# tuple — the same shape an agent receiving a user instruction would emit.
# Scenarios live as markdown files in ``bench/scenarios/<family>.md`` with a
# fenced ``json`` block carrying the structured payload.

SCENARIOS_DIR = HERE / "scenarios"
_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


def _load_scenarios(scenarios_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not scenarios_dir.is_dir():
        return out
    for md in sorted(scenarios_dir.glob("*.md")):
        m = _JSON_BLOCK_RE.search(md.read_text(encoding="utf-8"))
        if not m:
            continue
        data = json.loads(m.group(1))
        family = data.get("family")
        if family:
            out[family] = data
    return out


SCENARIOS: dict[str, dict] = _load_scenarios(SCENARIOS_DIR)


# ───────────────────────── per-family case resolvers ─────────────────────────


def _datadog_scan_root(case_dir: Path) -> Path:
    """Datadog cases keep the unpacked package under ``artifact/<...>/<pkg>/``.
    Descend to the first dir that contains ``setup.py`` or ``package.json``.
    """
    artifact = case_dir / "artifact"
    if artifact.is_dir():
        for sub in artifact.rglob("setup.py"):
            return sub.parent
        for sub in artifact.rglob("package.json"):
            return sub.parent
        return artifact
    return case_dir


def _label_by_prefix(name: str) -> str:
    """toolhijacker cases label themselves by name prefix (benign-*/malicious-*)."""
    return "malicious" if name.startswith("malicious") else "benign"


def _panel(family: str, label, limit: int | None, cmd: str, scan_resolver=None) -> list[dict]:
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
            "family": family,
            "label": case_label,
            "case": case_dir.name,
            "cwd": str(scan_root),
            "command": cmd,
        })
    return out


# ───────────────────────── outcome + evidence parsing ────────────────────────


def _classify_outcome(label: str, decision: str | None) -> str:
    if label == "benign":
        return "TN" if decision == "allow" else "FP"
    # malicious — anything that is not 'allow' counts as TP
    return "TP" if decision != "allow" else "FN"


def _read_stages(ep_path: str | None) -> dict:
    if not ep_path or not Path(ep_path).is_file():
        return {}
    try:
        ep = json.loads(Path(ep_path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    eia = ep.get("external_interaction_analysis") or {}
    return {
        "external_env":       (ep.get("current_action") or {}).get("external_env"),
        "asset_kind":         (eia.get("asset_kind") or {}).get("status"),
        "asset_kind_kind":    (eia.get("asset_kind") or {}).get("kind"),
        "static_status":      (eia.get("static_analysis") or {}).get("status"),
        "static_findings":    len((eia.get("static_analysis") or {}).get("findings", [])),
        "reputation_status":  (eia.get("reputation_analysis") or {}).get("status"),
        "reputation_signals": len((eia.get("reputation_analysis") or {}).get("signals", [])),
        "sandbox_status":     (ep.get("shadow_agent_execution") or {}).get("execution_status"),
    }


# ───────────────────────── metrics + chart rendering ────────────────────────

# Maps each bench family to the external source type the safeguard
# classifies (pypi/npm/repo/skill). The chart aggregates confusion by this
# axis so per-source-type DSR and benign/malicious discrimination are visible.
SOURCE_TYPE_OF_FAMILY = {
    "datadog-pypi":          "pypi",
    "benign-pypi":           "pypi",
    "benign-pypi-extended":  "pypi",
    "datadog-npm":           "npm",
    "benign-npm-extended":   "npm",
    "malicious-repos":       "repo",
    "benign-repo-extended":  "repo",
    "skill-inject":          "skill",
    "toolhijacker":          "skill",
    "benign-skills":         "skill",
    "benign-tools":          "skill",
    "benign-skill-extended": "skill",
}
SOURCE_TYPE_ORDER = ["pypi", "npm", "repo", "skill"]


def _compute_metrics(rows: list[dict]) -> dict:
    """Per-row outcomes → DSR / specificity / accuracy / precision / F1.

    DSR (Defense Success Rate) = recall on malicious = TP / (TP + FN). It is
    the headline metric: the fraction of malicious external sources the
    framework actually stopped from running.
    Specificity = TN / (TN + FP), the fraction of benign sources correctly
    allowed (proves the framework is not just a uniform blocker).
    """
    confusion: Counter = Counter(r["outcome"] for r in rows)
    tp = confusion.get("TP", 0)
    tn = confusion.get("TN", 0)
    fp = confusion.get("FP", 0)
    fn = confusion.get("FN", 0)
    err = confusion.get("ERR", 0)
    mal = tp + fn
    ben = tn + fp
    total = mal + ben
    return {
        "n": total, "errors": err, "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "dsr":         tp / mal if mal else 0.0,
        "specificity": tn / ben if ben else 0.0,
        "accuracy":    (tp + tn) / total if total else 0.0,
        "precision":   tp / (tp + fp) if (tp + fp) else 0.0,
        "f1":          (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0,
    }


def _per_source_type_metrics(rows: list[dict]) -> dict[str, dict]:
    """Group rows by external source type (pypi/npm/repo/skill) and compute
    confusion + DSR/specificity for each. Skips types with no rows."""
    by_type: dict[str, list[dict]] = {}
    for r in rows:
        st = SOURCE_TYPE_OF_FAMILY.get(r.get("family"))
        if st:
            by_type.setdefault(st, []).append(r)
    return {st: _compute_metrics(subset) for st, subset in by_type.items()}


def _baseline_metrics_from_labels(rows: list[dict]) -> dict:
    """Baseline = no framework — every install just runs. By construction
    every malicious case becomes FN (DSR=0) and every benign case becomes TN
    (specificity=1). No re-run needed; derived from corpus labels alone."""
    mal = sum(1 for r in rows if r["label"] == "malicious")
    ben = sum(1 for r in rows if r["label"] == "benign")
    total = mal + ben
    return {
        "n": total, "errors": 0, "TP": 0, "TN": ben, "FP": 0, "FN": mal,
        "dsr": 0.0,
        "specificity": 1.0 if ben else 0.0,
        "accuracy":    ben / total if total else 0.0,
        "precision":   0.0,
        "f1":          0.0,
    }


def _render_charts(framework: dict, baseline: dict,
                   per_family: dict[str, Counter],
                   per_source_type: dict[str, dict],
                   out_dsr: Path, out_discrim: Path) -> None:
    """Two PNGs, one question per chart, broken down by external source type
    (pypi / npm / repo / skill):

    * ``out_dsr``     — DSR per source type, framework OFF vs ON, plus overall.
      Answers "does the framework actually defend?" Baseline DSR is 0% by
      construction (no framework = no block = every malicious install runs).
    * ``out_discrim`` — discrimination on the ON-only run, per source type.
      Answers "does the framework distinguish benign from harmful, instead of
      blanket-blocking?" Two panels: per-source-type recall + specificity, and
      per-family confusion breakdown.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    types = [t for t in SOURCE_TYPE_ORDER if t in per_source_type]

    # ─────────── DSR chart (OFF vs ON, per source type + overall) ───────────
    # Only types with malicious cases produce a meaningful DSR.
    dsr_types = [t for t in types if (per_source_type[t]["TP"] + per_source_type[t]["FN"]) > 0]
    groups = dsr_types + ["overall"]
    fw_dsr = [per_source_type[t]["dsr"] * 100 for t in dsr_types] + [framework["dsr"] * 100]
    bl_dsr = [0.0] * len(groups)  # baseline = no framework → DSR = 0 everywhere
    n_per = [per_source_type[t]["TP"] + per_source_type[t]["FN"] for t in dsr_types]
    n_per.append(framework["TP"] + framework["FN"])
    labels = [f"{t}\n(n={n})" for t, n in zip(groups, n_per)]

    fig, ax = plt.subplots(figsize=(max(8, 1.6 * len(groups) + 2), 5.2))
    x = list(range(len(groups)))
    w = 0.35
    ax.bar([i - w / 2 for i in x], bl_dsr, w,
           label="Baseline (no framework)", color="#cccccc")
    ax.bar([i + w / 2 for i in x], fw_dsr, w,
           label="Framework ON", color="#3b82f6")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 110)
    ax.set_ylabel("Defense Success Rate (%)")
    ax.set_title("DSR on malicious external sources — per source type")
    ax.legend(loc="upper left", fontsize=9)
    for i, v in enumerate(fw_dsr):
        ax.text(i + w / 2, v + 2, f"{v:.1f}%", ha="center", fontsize=9)
        ax.text(i - w / 2, 2, "0%", ha="center", fontsize=9, color="#444")
    plt.tight_layout()
    plt.savefig(out_dsr, dpi=120)
    plt.close(fig)

    # ─── Discrimination chart (ON only) ───
    fig, axes = plt.subplots(1, 2, figsize=(15, 5.5))

    # Panel A: per-source-type recall (malicious blocked) + specificity (benign allowed)
    x = list(range(len(types)))
    w = 0.38
    recall_vals, spec_vals = [], []
    recall_xs, spec_xs = [], []
    for i, t in enumerate(types):
        m = per_source_type[t]
        nm = m["TP"] + m["FN"]
        nb = m["TN"] + m["FP"]
        if nm > 0:
            recall_vals.append(m["dsr"] * 100)
            recall_xs.append(i - w / 2)
        if nb > 0:
            spec_vals.append(m["specificity"] * 100)
            spec_xs.append(i + w / 2)
    axes[0].bar(recall_xs, recall_vals, w,
                label="malicious blocked (recall)", color="#22c55e")
    axes[0].bar(spec_xs, spec_vals, w,
                label="benign allowed (specificity)", color="#3b82f6")
    for xv, v in zip(recall_xs, recall_vals):
        axes[0].text(xv, v + 2, f"{v:.0f}%", ha="center", fontsize=9)
    for xv, v in zip(spec_xs, spec_vals):
        axes[0].text(xv, v + 2, f"{v:.0f}%", ha="center", fontsize=9)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels([
        f"{t}\n(mal={per_source_type[t]['TP'] + per_source_type[t]['FN']}, "
        f"ben={per_source_type[t]['TN'] + per_source_type[t]['FP']})"
        for t in types
    ], fontsize=9)
    axes[0].set_ylim(0, 110)
    axes[0].set_ylabel("%")
    axes[0].set_title(
        "Discrimination per source type "
        f"(overall acc={framework['accuracy'] * 100:.1f}%, "
        f"F1={framework['f1'] * 100:.1f}%)")
    axes[0].legend(loc="lower left", fontsize=8)

    # Panel B: per-family confusion stacked bars (granular view)
    fams = sorted(per_family.keys())
    tp_a  = [per_family[f].get("TP",  0) for f in fams]
    tn_a  = [per_family[f].get("TN",  0) for f in fams]
    fp_a  = [per_family[f].get("FP",  0) for f in fams]
    fn_a  = [per_family[f].get("FN",  0) for f in fams]
    err_a = [per_family[f].get("ERR", 0) for f in fams]
    xs = list(range(len(fams)))
    axes[1].bar(xs, tp_a, label="TP", color="#22c55e")
    bottom = list(tp_a)
    axes[1].bar(xs, tn_a, bottom=bottom, label="TN", color="#3b82f6")
    bottom = [a + b for a, b in zip(bottom, tn_a)]
    axes[1].bar(xs, fp_a, bottom=bottom, label="FP", color="#ef4444")
    bottom = [a + b for a, b in zip(bottom, fp_a)]
    axes[1].bar(xs, fn_a, bottom=bottom, label="FN", color="#f97316")
    bottom = [a + b for a, b in zip(bottom, fn_a)]
    axes[1].bar(xs, err_a, bottom=bottom, label="ERR", color="#9ca3af")
    axes[1].set_xticks(xs)
    axes[1].set_xticklabels(fams, rotation=30, ha="right", fontsize=9)
    axes[1].set_ylabel("cases")
    axes[1].set_title("Per-family confusion")
    axes[1].legend(loc="upper right", fontsize=8)

    plt.tight_layout()
    plt.savefig(out_discrim, dpi=120)
    plt.close(fig)


# ────────────────────────────────── main ─────────────────────────────────────


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cap", type=int, default=3,
                        help="cases per family (0 = full census, multi-hour)")
    parser.add_argument("--out", default="/tmp/framework_reliability.json")
    parser.add_argument("--families", default="",
                        help="comma-separated subset, e.g. 'datadog-pypi,benign-pypi'")
    parser.add_argument("--extra-benign-root", default="",
                        help="external dir with extra benign-pypi cases mirroring "
                             "<case>/artifact/<pkg-ver>/ layout. Each top-level subdir "
                             "becomes a benign-pypi-extended case (cmd: 'pip install pkg').")
    parser.add_argument("--extra-benign-npm-root", default="",
                        help="external dir with extra benign-npm cases → "
                             "benign-npm-extended (cmd: 'npm install pkg').")
    parser.add_argument("--extra-benign-repo-root", default="",
                        help="external dir with extra benign-repo cases (cloned repo "
                             "roots) → benign-repo-extended (cmd: 'pip install .').")
    parser.add_argument("--extra-benign-skill-root", default="",
                        help="external dir with extra benign-skill cases (skill dirs "
                             "containing SKILL.md) → benign-skill-extended (cmd: "
                             "'cat SKILL.md').")
    parser.add_argument("--chart-out", default="",
                        help="output PNG prefix; two files written: "
                             "<prefix>_dsr.png (OFF vs ON DSR) and "
                             "<prefix>_discrim.png (ON-only benign/malicious "
                             "discrimination + per-family confusion). "
                             "Default: derived from --out.")
    parser.add_argument("--no-chart", action="store_true",
                        help="skip chart rendering.")
    args = parser.parse_args(argv)
    cap = args.cap or None

    cfg = SecurityFrameworkConfig.from_env()
    if "config" in _i.signature(ShadowSandboxSafeguard.__init__).parameters:
        sg = ShadowSandboxSafeguard(cfg)
    else:
        sg = ShadowSandboxSafeguard()

    print(f"flags: static={cfg.static_analysis_enabled} "
          f"reputation={cfg.reputation_analysis_enabled} "
          f"sandbox={getattr(cfg, 'shadow_sandbox_enabled', '?')} "
          f"verifier={getattr(cfg, 'verifier_mode', '?')}  "
          f"sandbox_img={getattr(cfg, 'sandbox_docker_image', '?')}")

    # full panel — same structure as bench/static_analysis_reliability.py so
    # the framework bench is directly comparable to the static-only bench.
    panels = (
        _panel("datadog-pypi",    "malicious", cap, "pip install pkg",  _datadog_scan_root)
        + _panel("datadog-npm",   "malicious", cap, "npm install pkg",  _datadog_scan_root)
        + _panel("malicious-repos", "malicious", cap, "pip install .")
        + _panel("skill-inject",  "malicious", cap, "cat SKILL.md")
        + _panel("toolhijacker",  _label_by_prefix, cap, "cat SKILL.md")
        + _panel("benign-pypi",   "benign", cap, "pip install pkg")
        + _panel("benign-skills", "benign", cap, "cat SKILL.md")
        + _panel("benign-tools",  "benign", cap, "cat SKILL.md")
    )
    # Extra benign cases from external corpus roots (each ``<root>/<case>/`` is
    # one case, same flow as the matching base family).
    extras = [
        (args.extra_benign_root,       "benign-pypi-extended",  "pip install pkg"),
        (args.extra_benign_npm_root,   "benign-npm-extended",   "npm install pkg"),
        (args.extra_benign_repo_root,  "benign-repo-extended",  "pip install ."),
        (args.extra_benign_skill_root, "benign-skill-extended", "cat SKILL.md"),
    ]
    for root_arg, family_name, cmd in extras:
        if not root_arg:
            continue
        root = Path(root_arg)
        if not root.is_dir():
            continue
        extra_cases = sorted([p for p in root.iterdir() if p.is_dir()])
        if cap:
            extra_cases = extra_cases[:cap]
        for case_dir in extra_cases:
            panels.append({
                "family": family_name,
                "label": "benign",
                "case": case_dir.name,
                "cwd": str(case_dir),
                "command": cmd,
            })
    if args.families:
        keep = {f.strip() for f in args.families.split(",") if f.strip()}
        panels = [p for p in panels if p["family"] in keep]

    print(f"panel size: {len(panels)}\n")

    confusion_per_family: dict[str, Counter] = {}
    confusion_total: Counter = Counter()
    rows: list[dict] = []
    t_total = time.monotonic()
    for i, case in enumerate(panels, start=1):
        family = case["family"]
        case_name = case["case"]
        cmd = case["command"]
        sc = SCENARIOS.get(family, {})
        task = sc.get("task", "Run the requested action.").format(name=case_name)
        history = sc.get("history", [])
        reason = sc.get("action_reason", "Follow the user's instruction.")
        action = {"type": "command", "command": cmd, "reason": reason}
        # examples-style agent context: user task + plausible 1-step history +
        # workspace, mirroring vulnerable_cli_agent --task --workspace flow.
        context = {
            "cwd": case["cwd"],
            "history": history,
            "step": len(history),
            "task": task,
            "run_id": f"bench_{family}_{case_name}",
        }
        t0 = time.monotonic()
        try:
            res = sg.inspect(action, context)
            elapsed = time.monotonic() - t0
            decision = res.get("decision")
            outcome = _classify_outcome(case["label"], decision)
            stages = _read_stages(res.get("evidence_package_path"))
            row = {**case, "decision": decision, "outcome": outcome,
                   "elapsed_s": round(elapsed, 1),
                   "reason": str(res.get("reason", ""))[:160], **stages}
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            outcome = "ERR"
            row = {**case, "decision": None, "outcome": "ERR",
                   "elapsed_s": round(elapsed, 1),
                   "error": f"{type(exc).__name__}: {exc}"[:200]}

        rows.append(row)
        confusion_per_family.setdefault(family, Counter())[outcome] += 1
        confusion_total[outcome] += 1
        mark = {"TP": "✓", "TN": "✓"}.get(outcome, "✗")
        print(f"  {mark} [{outcome:3s}] {family:16s}/{case['case'][:30]:30s} "
              f"→ {row.get('decision') or 'ERR':5s}  "
              f"ak={row.get('asset_kind')} static={row.get('static_status')}"
              f"(f={row.get('static_findings', 0)}) rep={row.get('reputation_status')}"
              f"({row.get('reputation_signals', 0)}) sb={row.get('sandbox_status')} "
              f"[{elapsed:.0f}s]")

    elapsed_total = time.monotonic() - t_total

    print("\n=== Per-family confusion ===")
    for fam in sorted(confusion_per_family):
        print(f"  {fam:18s} {dict(confusion_per_family[fam])}")
    print(f"\n=== TOTAL ===\n  {dict(confusion_total)}  (n={sum(confusion_total.values())}, "
          f"elapsed={elapsed_total / 60:.1f} min)")

    # ── metrics: framework ON (measured) vs OFF (analytical baseline) ──
    framework = _compute_metrics(rows)
    baseline = _baseline_metrics_from_labels(rows)
    per_source_type = _per_source_type_metrics(rows)
    print("\n=== Metrics: Framework OFF (baseline) vs ON ===")
    print(f"  {'metric':14s} {'OFF':>8s} {'ON':>8s}")
    for k, lab in [("dsr", "DSR (recall)"), ("specificity", "specificity"),
                   ("accuracy", "accuracy"), ("precision", "precision"), ("f1", "F1")]:
        print(f"  {lab:14s} {baseline[k] * 100:>7.1f}% {framework[k] * 100:>7.1f}%")
    if per_source_type:
        print("\n=== Per source type (framework ON) ===")
        print(f"  {'type':6s} {'n_mal':>6s} {'n_ben':>6s} {'DSR':>7s} {'spec':>7s} {'acc':>7s}")
        for t in SOURCE_TYPE_ORDER:
            if t not in per_source_type:
                continue
            m = per_source_type[t]
            print(f"  {t:6s} {m['TP'] + m['FN']:>6d} {m['TN'] + m['FP']:>6d} "
                  f"{m['dsr'] * 100:>6.1f}% {m['specificity'] * 100:>6.1f}% "
                  f"{m['accuracy'] * 100:>6.1f}%")

    out = Path(args.out)
    out.write_text(json.dumps({
        "confusion_total": dict(confusion_total),
        "confusion_per_family": {k: dict(v) for k, v in confusion_per_family.items()},
        "metrics_framework_on": framework,
        "metrics_baseline_off": baseline,
        "metrics_per_source_type": per_source_type,
        "elapsed_min": round(elapsed_total / 60, 2),
        "rows": rows,
    }, indent=2, default=str))
    print(f"Details → {out}")

    if not args.no_chart:
        prefix = Path(args.chart_out) if args.chart_out else out.with_suffix("")
        out_dsr = prefix.with_name(prefix.name + "_dsr.png")
        out_discrim = prefix.with_name(prefix.name + "_discrim.png")
        try:
            _render_charts(framework, baseline, confusion_per_family,
                           per_source_type, out_dsr, out_discrim)
            print(f"DSR chart           → {out_dsr}")
            print(f"Discrimination chart → {out_discrim}")
        except Exception as exc:  # noqa: BLE001
            print(f"  chart render failed: {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
