"""Locked action templates per benchmark family.

Phase 2 prerequisite called for by the analyst review — silently falling back
to ``ls`` when a fixture's expected file is missing inverts the ground truth
(the smoke ran into this for skill-inject ``cat skill.md`` lowercase
mismatch). This module owns the per-family action contract and validates
fixture pre-conditions at test time, not at execution time.

Each ``BenchmarkCase`` produced here carries:
- ``family``: the benchmark family slug
- ``case_dir``: the fixture directory
- ``label_malicious``: ground-truth label
- ``action``: the dict that goes into ``ShadowSandboxSafeguard.inspect()``
- ``context``: the dict that goes into ``ShadowSandboxSafeguard.inspect()``

``load_all_cases()`` returns the full set with optional per-family caps.
``load_cases(families=...)`` filters to specific families.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path


BENCH_ROOT = Path("/home/user/agent-mds/eval/benchmarks")


@dataclass
class BenchmarkCase:
    family: str
    case_dir: Path
    label_malicious: bool
    action: dict
    context: dict
    note: str = ""
    fixture_files: list[str] = field(default_factory=list)


def _read_manifest(case_dir: Path) -> dict:
    for name in ("agent_mds_benchmark.json", "benchmark.json", "manifest.json"):
        path = case_dir / name
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
    return {}


def _context(family: str, case_dir: Path, task_hint: str) -> dict:
    return {
        "task": task_hint or f"Work with {case_dir.name}",
        "cwd": str(case_dir),
        "history": [],
        "step": 0,
        "run_id": f"bench_{family}_{case_dir.name}",
    }


def _action(command: str, reason: str) -> dict:
    return {"type": "command", "command": command, "reason": reason}


def _require(case_dir: Path, filenames: list[str]) -> str | None:
    """Return the first existing filename from ``filenames``, or ``None``."""
    for fname in filenames:
        if (case_dir / fname).exists():
            return fname
    return None


# ─────────────────────────── per-family builders ───────────────────────────────


def _build_malicious_repo(case_dir: Path) -> BenchmarkCase | None:
    manifest = _read_manifest(case_dir)
    return BenchmarkCase(
        family="malicious-repos",
        case_dir=case_dir,
        label_malicious=bool(manifest.get("malicious", True)),
        action=_action("pip install .", f"install local package from {case_dir.name}"),
        context=_context("malicious-repos", case_dir, manifest.get("task", "")),
        note=manifest.get("threat", ""),
        fixture_files=[p.name for p in case_dir.iterdir() if p.is_file()],
    )


def _build_skill_inject(case_dir: Path) -> BenchmarkCase | None:
    skill_file = _require(case_dir, ["SKILL.md", "skill.md", "skill_inject.md"])
    if not skill_file:
        return None  # corpus integrity issue — caller will log
    manifest = _read_manifest(case_dir)
    return BenchmarkCase(
        family="skill-inject",
        case_dir=case_dir,
        label_malicious=bool(manifest.get("malicious", True)),
        action=_action(f"cat {skill_file}", "read skill description"),
        context=_context("skill-inject", case_dir, manifest.get("task", "")),
        fixture_files=[skill_file],
    )


def _build_benign_skill(case_dir: Path) -> BenchmarkCase | None:
    skill_file = _require(case_dir, ["SKILL.md", "skill.md"])
    if not skill_file:
        return None
    return BenchmarkCase(
        family="benign-skills",
        case_dir=case_dir,
        label_malicious=False,
        action=_action(f"cat {skill_file}", "read skill description"),
        context=_context("benign-skills", case_dir, "Read this skill."),
        fixture_files=[skill_file],
    )


def _build_datadog_pypi(case_dir: Path) -> BenchmarkCase | None:
    # Labels come from the dir-name prefix; there's no per-case manifest.
    name = case_dir.name
    if "malicious_intent" not in name:
        return None
    pkg = name.replace("datadog_pypi_malicious_intent_", "")
    return BenchmarkCase(
        family="datadog-pypi",
        case_dir=case_dir,
        label_malicious=True,
        action=_action(f"pip install {pkg}", f"install PyPI package {pkg}"),
        context=_context("datadog-pypi", case_dir, f"Install package {pkg}."),
        fixture_files=[p.name for p in case_dir.iterdir() if p.is_file()][:5],
    )


def _build_datadog_npm(case_dir: Path) -> BenchmarkCase | None:
    name = case_dir.name
    if "malicious_intent" not in name:
        return None
    pkg = name.replace("datadog_npm_malicious_intent_", "")
    return BenchmarkCase(
        family="datadog-npm",
        case_dir=case_dir,
        label_malicious=True,
        action=_action(f"npm install {pkg}", f"install npm package {pkg}"),
        context=_context("datadog-npm", case_dir, f"Install package {pkg}."),
    )


def _build_benign_pypi(case_dir: Path) -> BenchmarkCase | None:
    pkg = case_dir.name.replace("benign_pypi_", "")
    return BenchmarkCase(
        family="benign-pypi",
        case_dir=case_dir,
        label_malicious=False,
        action=_action(f"pip install {pkg}", f"install PyPI package {pkg}"),
        context=_context("benign-pypi", case_dir, f"Install package {pkg}."),
    )


def _build_toolhijacker(case_dir: Path) -> BenchmarkCase | None:
    # Label encoded in the dir name prefix.
    is_mal = case_dir.name.startswith("malicious-")
    is_ben = case_dir.name.startswith("benign-")
    if not (is_mal or is_ben):
        return None
    manifest = _read_manifest(case_dir)
    # Tool descriptions live in the manifest's "text" field or in tool.md.
    tool_file = _require(case_dir, ["tool.md", "TOOL.md", "description.md", "README.md"])
    cmd = f"cat {tool_file}" if tool_file else "ls"
    return BenchmarkCase(
        family="toolhijacker",
        case_dir=case_dir,
        label_malicious=is_mal,
        action=_action(cmd, "inspect tool description"),
        context=_context("toolhijacker", case_dir, manifest.get("task", "")),
    )


def _build_benign_tool(case_dir: Path) -> BenchmarkCase | None:
    tool_file = _require(case_dir, ["tool.md", "TOOL.md", "README.md", "description.md"])
    cmd = f"cat {tool_file}" if tool_file else "ls"
    manifest = _read_manifest(case_dir)
    return BenchmarkCase(
        family="benign-tools",
        case_dir=case_dir,
        label_malicious=False,
        action=_action(cmd, "inspect tool description"),
        context=_context("benign-tools", case_dir, manifest.get("task", "")),
    )


def _build_cloneguard(case_dir: Path) -> BenchmarkCase | None:
    manifest = _read_manifest(case_dir)
    return BenchmarkCase(
        family="cloneguard-repos",
        case_dir=case_dir,
        label_malicious=bool(manifest.get("malicious", True)),
        action=_action("pip install .", "install local clone"),
        context=_context("cloneguard-repos", case_dir, manifest.get("task", "")),
        note=manifest.get("threat", ""),
    )


_FAMILY_BUILDERS = {
    "malicious-repos": _build_malicious_repo,
    "skill-inject": _build_skill_inject,
    "benign-skills": _build_benign_skill,
    "datadog-pypi": _build_datadog_pypi,
    "datadog-npm": _build_datadog_npm,
    "benign-pypi": _build_benign_pypi,
    "toolhijacker": _build_toolhijacker,
    "benign-tools": _build_benign_tool,
    "cloneguard-repos": _build_cloneguard,
}


def load_cases(
    families: list[str] | None = None,
    cap_per_family: int | None = None,
    seed: int = 42,
) -> list[BenchmarkCase]:
    """Materialize the benchmark cases.

    ``families`` defaults to all known families. ``cap_per_family`` does a
    deterministic random sample (seeded) so a re-run produces the same subset.
    """
    families = families or list(_FAMILY_BUILDERS)
    rng = random.Random(seed)
    cases: list[BenchmarkCase] = []

    for family in families:
        builder = _FAMILY_BUILDERS.get(family)
        family_root = BENCH_ROOT / family
        if not builder or not family_root.exists():
            continue
        dirs = sorted(p for p in family_root.iterdir() if p.is_dir())
        if cap_per_family and len(dirs) > cap_per_family:
            dirs = sorted(rng.sample(dirs, cap_per_family))
        for case_dir in dirs:
            case = builder(case_dir)
            if case:
                cases.append(case)
    return cases


def assert_corpus_integrity(families: list[str] | None = None) -> dict:
    """Run a pre-flight check — every fixture either builds a BenchmarkCase or
    is reported as a corpus gap. Returns a report dict.
    """
    families = families or list(_FAMILY_BUILDERS)
    report = {"ok": [], "skipped": [], "missing_family_root": []}
    for family in families:
        builder = _FAMILY_BUILDERS[family]
        family_root = BENCH_ROOT / family
        if not family_root.exists():
            report["missing_family_root"].append(family)
            continue
        for case_dir in sorted(p for p in family_root.iterdir() if p.is_dir()):
            built = builder(case_dir)
            if built is None:
                report["skipped"].append(f"{family}/{case_dir.name}")
            else:
                report["ok"].append(f"{family}/{case_dir.name}")
    return report


if __name__ == "__main__":
    rep = assert_corpus_integrity()
    print(f"  ok={len(rep['ok'])}  skipped={len(rep['skipped'])}  missing_families={rep['missing_family_root']}")
    if rep["skipped"]:
        print("  first skipped:", rep["skipped"][:5])
