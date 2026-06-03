#!/usr/bin/env python3
"""Run the chanever safeguard pipeline over CHASE's published evaluation
dataset (Toda & Mori, AIware 2025, arXiv:2601.06838) so the two
PyPI-malware approaches can be compared on identical input.

Malicious corpus: `lxyeternal/pypi_malregistry` — the public dataset CHASE
sampled 500 packages from (paper Sec V.A). Each entry is a sdist tarball
under ``<name>/<version>/<name>-<version>.tar.gz``. We unpack the tarball
once into a temp dir, descend to the directory that owns ``setup.py``,
build the same ``(task + history + install command)`` triple our
``framework_reliability.py`` bench uses, and call
``ShadowSandboxSafeguard.inspect()`` directly. Output is chanever-shaped
JSON (confusion + per-row decision + stage stages) so it can be plotted
with the same chart helpers.

Benign corpus: provide a separate root via ``--benign-root`` pointing at a
directory of unpacked PyPI packages (one dir per package). The matching
PyPI 2025-Q3 random sample CHASE used isn't publicly redistributed; for
the malicious-recall comparison the malicious side alone is enough, and
our framework's existing ``benign-pypi`` corpus (under
``bench/corpora/benign-pypi``) can be passed via ``--benign-root`` to
report specificity on the same axis.

Usage:

    SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \\
    SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \\
    VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \\
    CLAUDE_CLI_MAX_TURNS=12 \\
    python bench/run_chanever_on_chase_dataset.py \\
        --malregistry-root /home/user/pypi_malregistry \\
        --benign-root /home/user/agent_security_framework/bench/corpora/benign-pypi \\
        --n-mal 500 --n-ben 45 --out /tmp/chanever_on_chase/results.json

The script is idempotent + resumable: ``--out`` is checkpointed after each
case and ``--resume`` skips already-completed rows on rerun.
"""

from __future__ import annotations

import argparse
import inspect as _i
import json
import random
import shutil
import sys
import tarfile
import time
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from security_framework.config import SecurityFrameworkConfig                       # noqa: E402
from security_framework.safeguard.shadow_sandbox_safeguard import ShadowSandboxSafeguard  # noqa: E402

from bench.framework_reliability import (                                           # noqa: E402
    _baseline_metrics_from_labels, _classify_outcome, _compute_metrics,
    _per_source_type_metrics, _read_stages,
)


# ─────────────────────────── corpus enumeration ────────────────────────────

def _enumerate_malregistry(root: Path) -> list[dict]:
    """Walk ``<root>/<name>/<version>/<name>-<version>.tar.gz`` and return
    one entry per (name, version, tarball)."""
    out: list[dict] = []
    if not root.is_dir():
        return out
    for name_dir in sorted(root.iterdir()):
        if not name_dir.is_dir() or name_dir.name.startswith("."):
            continue
        for ver_dir in sorted(name_dir.iterdir()):
            if not ver_dir.is_dir():
                continue
            tarballs = list(ver_dir.glob("*.tar.gz"))
            if not tarballs:
                continue
            out.append({
                "family": "chase-mal",
                "label": "malicious",
                "case": f"{name_dir.name}-{ver_dir.name}",
                "name": name_dir.name,
                "version": ver_dir.name,
                "tarball": str(tarballs[0]),
            })
    return out


def _enumerate_benign(root: Path) -> list[dict]:
    """Walk ``<root>/<case_dir>/`` — one dir per benign package, already
    unpacked. ``--benign-root /home/user/agent_security_framework/bench/corpora/benign-pypi``
    fits this shape."""
    out: list[dict] = []
    if not root.is_dir():
        return out
    for case_dir in sorted(root.iterdir()):
        if not case_dir.is_dir() or case_dir.name.startswith("."):
            continue
        out.append({
            "family": "chase-ben",
            "label": "benign",
            "case": case_dir.name,
            "name": case_dir.name,
            "version": None,
            "unpacked_dir": str(case_dir),
        })
    return out


# ─────────────────────────── per-case driver ───────────────────────────────

def _unpack_tarball(tarball: Path, dest: Path) -> Path | None:
    """Extract a package archive and return the directory that owns source
    files. lxyeternal/pypi_malregistry stores both sdist tarballs and wheels
    under a ``.tar.gz`` extension — wheels start with the ZIP magic ``PK``
    rather than gzip, so we fall back to ``zipfile`` when ``tarfile`` rejects
    the file. Resolution order: dir with ``setup.py``; dir with ``__init__.py``
    or any ``*.py`` (wheels have no setup.py); first subdir; ``dest`` itself.
    """
    dest.mkdir(parents=True, exist_ok=True)
    extracted = False
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(dest)
        extracted = True
    except (tarfile.TarError, OSError):
        pass
    if not extracted:
        try:
            with zipfile.ZipFile(tarball) as zf:
                zf.extractall(dest)
            extracted = True
        except (zipfile.BadZipFile, OSError):
            return None
    for setup in dest.rglob("setup.py"):
        return setup.parent
    for init in dest.rglob("__init__.py"):
        return init.parent
    for pyfile in dest.rglob("*.py"):
        return pyfile.parent
    subs = [p for p in dest.iterdir() if p.is_dir()]
    return subs[0] if subs else dest


def _descend_to_setup_py(unpacked: Path) -> Path:
    """For pre-unpacked benign dirs, descend into ``artifact/<...>/``
    if setup.py sits one level deeper (matches our existing benign-pypi
    layout)."""
    if (unpacked / "setup.py").is_file():
        return unpacked
    for setup in unpacked.rglob("setup.py"):
        return setup.parent
    return unpacked


def _resolve_scan_root(case: dict, tmp_root: Path) -> Path | None:
    if "tarball" in case:
        return _unpack_tarball(Path(case["tarball"]), tmp_root / case["case"])
    return _descend_to_setup_py(Path(case["unpacked_dir"]))


def run_case(case: dict, sg: ShadowSandboxSafeguard, tmp_root: Path,
             max_extract_keep: int) -> dict:
    name = case["name"]
    scan_root = _resolve_scan_root(case, tmp_root)
    if scan_root is None or not scan_root.is_dir():
        return {**case, "decision": None, "outcome": "ERR",
                "elapsed_s": 0.0, "error": "scan_root not resolvable"}

    action = {
        "type": "command",
        "command": f"pip install {name}",
        "reason": "Install the requested package as a project dependency.",
    }
    context = {
        "cwd": str(scan_root),
        "history": [
            {"step": 0,
             "action": {"type": "command", "command": "ls", "reason": "list workspace"},
             "stdout": "<workspace files listed>",
             "exit_code": 0}
        ],
        "step": 1,
        "task": f"Install the {name} package for the current project.",
        "run_id": f"chasedataset_{case['case']}",
    }

    t0 = time.monotonic()
    try:
        res = sg.inspect(action, context)
    except Exception as exc:  # noqa: BLE001
        elapsed = time.monotonic() - t0
        return {**case, "decision": None, "outcome": "ERR",
                "elapsed_s": round(elapsed, 1),
                "error": f"{type(exc).__name__}: {exc}"[:200]}
    elapsed = time.monotonic() - t0

    decision = res.get("decision")
    outcome = _classify_outcome(case["label"], decision)
    stages = _read_stages(res.get("evidence_package_path"))

    # Free disk: extracted tarballs pile up over a 500-case run. Keep only
    # the most recent N extractions.
    if "tarball" in case and max_extract_keep > 0:
        extracted = sorted(tmp_root.iterdir(), key=lambda p: p.stat().st_mtime)
        for old in extracted[:-max_extract_keep]:
            shutil.rmtree(old, ignore_errors=True)

    return {**case, "decision": decision, "outcome": outcome,
            "elapsed_s": round(elapsed, 1),
            "reason": str(res.get("reason", ""))[:160],
            **stages}


# ──────────────────────────────── main ─────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--malregistry-root",
                        default="/home/user/pypi_malregistry",
                        help="root of the lxyeternal/pypi_malregistry clone "
                             "(layout: <name>/<version>/<name>-<version>.tar.gz).")
    parser.add_argument("--benign-root", default="",
                        help="root of unpacked benign PyPI packages, one dir "
                             "per package (e.g. bench/corpora/benign-pypi). "
                             "Empty → skip benign side.")
    parser.add_argument("--n-mal", type=int, default=500,
                        help="how many malicious cases to sample (0 = all). "
                             "CHASE paper used 500.")
    parser.add_argument("--n-ben", type=int, default=0,
                        help="how many benign cases (0 = all under --benign-root).")
    parser.add_argument("--seed", type=int, default=42,
                        help="random seed for sampling.")
    parser.add_argument("--out", default="/tmp/chanever_on_chase/results.json")
    parser.add_argument("--tmp", default="/tmp/chanever_on_chase/extracted",
                        help="where to unpack malicious tarballs.")
    parser.add_argument("--max-extract-keep", type=int, default=10,
                        help="how many recent extracted dirs to keep (0 = all).")
    parser.add_argument("--resume", action="store_true",
                        help="read --out if present and skip completed cases.")
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_root = Path(args.tmp)
    tmp_root.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)

    mal_panel = _enumerate_malregistry(Path(args.malregistry_root))
    if args.n_mal and len(mal_panel) > args.n_mal:
        mal_panel = rng.sample(mal_panel, args.n_mal)
        mal_panel.sort(key=lambda c: c["case"])

    ben_panel: list[dict] = []
    if args.benign_root:
        ben_panel = _enumerate_benign(Path(args.benign_root))
        if args.n_ben and len(ben_panel) > args.n_ben:
            ben_panel = rng.sample(ben_panel, args.n_ben)
            ben_panel.sort(key=lambda c: c["case"])

    panel = mal_panel + ben_panel
    print(f"panel: {len(mal_panel)} mal + {len(ben_panel)} ben = {len(panel)} cases")

    rows: list[dict] = []
    if args.resume and out_path.is_file():
        try:
            rows = list(json.loads(out_path.read_text()).get("rows") or [])
        except (json.JSONDecodeError, OSError):
            rows = []
    done = {(r.get("family"), r.get("case")) for r in rows}
    panel = [p for p in panel if (p["family"], p["case"]) not in done]
    print(f"pending: {len(panel)} ({len(rows)} already complete)\n")

    cfg = SecurityFrameworkConfig.from_env()
    if "config" in _i.signature(ShadowSandboxSafeguard.__init__).parameters:
        sg = ShadowSandboxSafeguard(cfg)
    else:
        sg = ShadowSandboxSafeguard()

    confusion: Counter = Counter(r.get("outcome", "ERR") for r in rows)
    confusion_per_family: dict[str, Counter] = {}
    for r in rows:
        confusion_per_family.setdefault(r.get("family", ""), Counter())[r.get("outcome", "ERR")] += 1

    t_total = time.monotonic()
    for case in panel:
        row = run_case(case, sg, tmp_root, args.max_extract_keep)
        rows.append(row)
        confusion[row["outcome"]] += 1
        confusion_per_family.setdefault(row["family"], Counter())[row["outcome"]] += 1
        mark = {"TP": "✓", "TN": "✓"}.get(row["outcome"], "✗")
        print(f"  {mark} [{row['outcome']:3s}] {row['family']:10s}/{row['case'][:40]:40s} "
              f"→ {(row.get('decision') or 'ERR'):5s}  "
              f"static={row.get('static_status')} rep={row.get('reputation_status')} "
              f"sb={row.get('sandbox_status')} [{row.get('elapsed_s','?')}s]")

        out_path.write_text(json.dumps({
            "confusion_total": dict(confusion),
            "confusion_per_family": {k: dict(v) for k, v in confusion_per_family.items()},
            "metrics_framework_on": _compute_metrics(rows),
            "metrics_baseline_off": _baseline_metrics_from_labels(rows),
            "metrics_per_source_type": _per_source_type_metrics(rows),
            "elapsed_min": round((time.monotonic() - t_total) / 60, 2),
            "rows": rows,
        }, indent=2, default=str))

    print(f"\nConfusion: {dict(confusion)}")
    print(f"Per-family: {dict({k: dict(v) for k, v in confusion_per_family.items()})}")
    print(f"Details   → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
