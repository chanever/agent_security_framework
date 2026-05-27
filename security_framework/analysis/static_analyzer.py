"""Semgrep-backed static analysis adapter.

When ``classification.external_env`` is set and at least one code-bearing target
is present (or the agent's workspace itself is available for scanning), this
module invokes a host-side ``semgrep`` docker container against the workspace
or target paths and normalizes the results.

Container invocation (no host install required):

    docker run --rm
      -v <scan_root>:/src:ro
      semgrep/semgrep:latest
      semgrep --json --config <rules> /src

Each Semgrep finding is mapped to:

    {
      "rule_id":   <semgrep check_id>,
      "severity":  CRITICAL | HIGH | MEDIUM | LOW | INFO,
      "path":      <repo-relative path>,
      "line":      <int>,
      "message":   <semgrep extra.message>,
      "source":    "semgrep"
    }

If docker or the semgrep image is unavailable, the adapter returns
``status='unavailable'`` so the verifier can degrade gracefully.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from security_framework.config import SecurityFrameworkConfig

# Vendored DataDog GuardDog supply-chain rules — 33 semgrep YAML files covering
# install hooks, exec-base64, exfiltrate-sensitive-data, etc. License: Apache-2.0.
# Source: https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer/sourcecode
GUARDDOG_RULES_DIR = Path(__file__).resolve().parent / "external_rules_guarddog"

# Same GuardDog rules with `paths.include` filters stripped so the patterns
# apply to any file in the workspace (not just `setup.py`/`__init__.py`).
# This catches agent_mds malicious-repos cases that plant payloads in
# `scripts/*.py` instead of the install entrypoint.
GUARDDOG_RULES_UNSCOPED_DIR = Path(__file__).resolve().parent / "external_rules_guarddog_unscoped"

# chanever-authored supply-chain rules — covers gaps GuardDog leaves open
# (e.g. `.env` reads, `subprocess.run(["python", "-c", ...])`).
CHANEVER_RULES_DIR = Path(__file__).resolve().parent / "external_rules_chanever"


_CODE_BEARING_TARGET_TYPES = {"local_package", "repo", "requirements_file"}
# Map semgrep's "extra.severity" vocabulary into the uppercase ladder used by
# the rest of the framework. INFO is treated as LOW for verifier purposes.
_SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def skipped_result(reason: str = "No external interaction or install/source action detected.") -> dict:
    return {
        "status": "skipped",
        "findings": [],
        "summary": reason,
    }


def _resolve_scan_root(action: dict, context: dict, targets: list[dict]) -> Path | None:
    """Pick the directory semgrep should scan.

    Priority order:
      1. Any ``local_package`` target — agent is installing from the local workspace.
      2. ``context['cwd']`` — the workspace the agent is operating in.

    Repo targets (``git clone <url>``) cannot be scanned until cloned; the
    sandbox does the clone, so they're irrelevant for *pre-execution* semgrep.
    """
    cwd = context.get("cwd") if context else None
    cwd_root: Path | None = None
    if cwd:
        try:
            cwd_root = Path(cwd).resolve()
        except OSError:
            cwd_root = None
    for target in targets or []:
        if target.get("type") == "local_package":
            candidate = Path(cwd or ".").joinpath(target.get("path", ".")).resolve()
            if not candidate.exists():
                continue
            if cwd_root is not None:
                try:
                    candidate.relative_to(cwd_root)
                except ValueError:
                    continue  # target path escaped the workspace — refuse to scan it
            return candidate
    if cwd_root is not None and cwd_root.exists():
        return cwd_root
    return None


def _normalize_finding(raw: dict, scan_root: Path) -> dict:
    extra = raw.get("extra") or {}
    severity_raw = (extra.get("severity") or "INFO").upper()
    severity = _SEMGREP_SEVERITY_MAP.get(severity_raw, "LOW")
    path = raw.get("path") or ""
    if path.startswith("/src/"):
        path = path[len("/src/"):]
    try:
        line = int((raw.get("start") or {}).get("line", 0))
    except (TypeError, ValueError):
        line = 0
    return {
        "rule_id": raw.get("check_id") or "semgrep.unknown",
        "severity": severity,
        "path": path,
        "line": line,
        "message": extra.get("message") or "",
        "source": "semgrep",
    }


def _summary(findings: list[dict]) -> str:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return (
        f"Semgrep found {len(findings)} findings "
        f"(CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, "
        f"MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']})"
    )


def _run_semgrep_docker(scan_root: Path, cfg: SecurityFrameworkConfig) -> dict:
    # Per-rule timeout inside semgrep ensures a single pathological pattern
    # doesn't hang the whole scan (observed on datadog-pypi EZBEAMER case
    # 2026-05-25 — semgrep-core-pr ran 10+ minutes on one rule). docker
    # --stop-timeout caps how long the daemon waits before SIGKILL after we
    # SIGTERM the client. Bounds the outer subprocess.run timeout.
    cmd = [
        "docker", "run", "--rm",
        "--stop-timeout", "10",
        "-v", f"{scan_root}:/src:ro",
    ]
    semgrep_args = [
        "semgrep", "--json",
        "--timeout", "30",        # per-rule timeout (seconds)
        "--timeout-threshold", "3",
        "--max-memory", "2048",   # MB
        "--config", cfg.semgrep_rules,
    ]
    if GUARDDOG_RULES_DIR.is_dir():
        cmd.extend(["-v", f"{GUARDDOG_RULES_DIR}:/guarddog_rules:ro"])
        semgrep_args.extend(["--config", "/guarddog_rules"])
    if GUARDDOG_RULES_UNSCOPED_DIR.is_dir():
        cmd.extend(["-v", f"{GUARDDOG_RULES_UNSCOPED_DIR}:/guarddog_unscoped:ro"])
        semgrep_args.extend(["--config", "/guarddog_unscoped"])
    if CHANEVER_RULES_DIR.is_dir():
        cmd.extend(["-v", f"{CHANEVER_RULES_DIR}:/chanever_rules:ro"])
        semgrep_args.extend(["--config", "/chanever_rules"])
    cmd.extend([cfg.semgrep_image, *semgrep_args, "/src"])
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=cfg.semgrep_timeout,
        check=False,
    )
    # Semgrep returns non-zero when findings are produced; the json payload is
    # still on stdout. Only an empty stdout indicates real failure.
    if not (completed.stdout or "").strip():
        raise RuntimeError(
            f"semgrep produced no stdout (rc={completed.returncode}, stderr={(completed.stderr or '').strip()[:300]})"
        )
    return json.loads(completed.stdout)


def analyze_static(
    action: dict,
    context: dict,
    targets: list[dict],
    classification: dict,
    asset_kind: dict | None = None,
) -> dict:
    """Run semgrep against the agent's workspace/local code targets.

    Returns ``status`` ∈ ``skipped`` | ``success`` | ``unavailable``. ``skipped``
    means the gating heuristics did not warrant a scan; ``unavailable`` means
    docker or the semgrep image could not run; ``success`` always has the
    normalized findings list (which may be empty).
    """
    if not classification.get("external_env"):
        return skipped_result()
    has_code_target = any(
        t.get("type") in _CODE_BEARING_TARGET_TYPES for t in (targets or [])
    )
    cwd_has_files = False
    cwd = (context or {}).get("cwd")
    if cwd:
        cwd_path = Path(cwd)
        cwd_has_files = cwd_path.exists() and any(cwd_path.iterdir()) if cwd_path.is_dir() else False
    if not has_code_target and not cwd_has_files:
        return skipped_result("No code-bearing targets and workspace is empty.")

    del asset_kind  # accepted for safeguard call-signature parity; not used here
    cfg = SecurityFrameworkConfig.from_env().resolve_paths()
    scan_root = _resolve_scan_root(action, context or {}, targets or [])
    if scan_root is None:
        return skipped_result("Could not resolve a scan root for semgrep.")

    # Dispatch via artifact_classifier when targets carry concrete types.
    # This gives per-type analyzer breakdown (skill / repo / pypi / npm) that
    # the verifier can use instead of a single undifferentiated findings list.
    from security_framework import artifact_classifier
    from security_framework import static_analyzers as _analyzers_pkg

    nodes = artifact_classifier.classify(targets or [], context=context or {})
    # Classifier contract: when a workspace exists it always emits at least
    # one node (local_directory minimum). We do not synthesise nodes here.

    per_artifact: list[dict] = []
    merged_findings: list[dict] = []
    for node in nodes:
        node_result = _analyzers_pkg.analyze_node(node, cfg)
        per_artifact.append({
            "artifact_type": node["artifact_type"],
            "detected_kinds": node["detected_kinds"],
            "source": node["source"],
            **node_result,
        })
        merged_findings.extend(node_result.get("findings") or [])

    statuses = {r["status"] for r in per_artifact}
    if "unavailable" in statuses and "success" not in statuses:
        overall = "unavailable"
        first_unavail = next(r for r in per_artifact if r["status"] == "unavailable")
        summary = first_unavail.get("summary") or "static analysis unavailable"
    elif statuses == {"skipped"}:
        overall = "skipped"
        summary = per_artifact[0].get("summary") or "static analysis skipped"
    else:
        overall = "success"
        summary = _summary(merged_findings)

    return {
        "status": overall,
        "findings": merged_findings,
        "summary": summary,
        "scan_root": str(scan_root),
        "rules": cfg.semgrep_rules,
        "per_artifact": per_artifact,
    }
