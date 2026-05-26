"""PyPI package static analyzer.

Runs semgrep with chanever's standard chain (p/security-audit + vendored
GuardDog Python rules + unscoped variant + chanever rules). When the
node has a local ``scan_root`` we scan it; otherwise we report
``skipped`` because OSV reputation is the rest of the signal for
registry-only packages.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


GUARDDOG_RULES_DIR = Path(__file__).resolve().parent.parent / "external_rules_guarddog"
GUARDDOG_UNSCOPED_DIR = Path(__file__).resolve().parent.parent / "external_rules_guarddog_unscoped"
CHANEVER_RULES_DIR = Path(__file__).resolve().parent.parent / "external_rules_chanever"

_SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def _normalize_finding(raw: dict) -> dict:
    extra = raw.get("extra") or {}
    sev = (extra.get("severity") or "INFO").upper()
    path = raw.get("path") or ""
    if path.startswith("/src/"):
        path = path[len("/src/"):]
    try:
        line = int((raw.get("start") or {}).get("line", 0))
    except (TypeError, ValueError):
        line = 0
    return {
        "rule_id": raw.get("check_id") or "semgrep.unknown",
        "severity": _SEMGREP_SEVERITY_MAP.get(sev, "LOW"),
        "path": path,
        "line": line,
        "message": extra.get("message") or "",
        "source": "semgrep",
    }


def _run_semgrep_docker(scan_root: Path, cfg) -> dict[str, Any]:
    cmd: list[str] = ["docker", "run", "--rm", "--stop-timeout", "10",
                       "-v", f"{scan_root}:/src:ro"]
    semgrep_args = [
        "semgrep", "--json",
        "--timeout", "30",
        "--timeout-threshold", "3",
        "--max-memory", "2048",
        "--config", cfg.semgrep_rules,
    ]
    if GUARDDOG_RULES_DIR.is_dir():
        cmd.extend(["-v", f"{GUARDDOG_RULES_DIR}:/guarddog_rules:ro"])
        semgrep_args.extend(["--config", "/guarddog_rules"])
    if GUARDDOG_UNSCOPED_DIR.is_dir():
        cmd.extend(["-v", f"{GUARDDOG_UNSCOPED_DIR}:/guarddog_unscoped:ro"])
        semgrep_args.extend(["--config", "/guarddog_unscoped"])
    if CHANEVER_RULES_DIR.is_dir():
        cmd.extend(["-v", f"{CHANEVER_RULES_DIR}:/chanever_rules:ro"])
        semgrep_args.extend(["--config", "/chanever_rules"])
    cmd.extend([cfg.semgrep_image, *semgrep_args, "/src"])

    completed = subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=cfg.semgrep_timeout, check=False,
    )
    if not (completed.stdout or "").strip():
        raise RuntimeError(
            f"semgrep produced no stdout "
            f"(rc={completed.returncode}, stderr={(completed.stderr or '').strip()[:300]})"
        )
    return json.loads(completed.stdout)


def _summary(findings: list[dict], rules_label: str) -> str:
    counts = {b: 0 for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return (
        f"{rules_label}: {len(findings)} findings "
        f"(CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, "
        f"MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']})"
    )


def analyze(node: dict, cfg) -> dict:
    scan_root_str = node.get("scan_root")
    if not scan_root_str:
        return {
            "status": "skipped",
            "findings": [],
            "summary": f"PyPI registry-only target {node.get('name')}; static scan deferred to reputation.",
            "analyzer": "pypi",
        }
    scan_root = Path(scan_root_str)
    try:
        payload = _run_semgrep_docker(scan_root, cfg)
    except FileNotFoundError:
        return {"status": "unavailable", "findings": [],
                "summary": "docker executable not found", "analyzer": "pypi"}
    except subprocess.TimeoutExpired:
        return {"status": "unavailable", "findings": [],
                "summary": f"semgrep timed out after {cfg.semgrep_timeout}s", "analyzer": "pypi"}
    except (RuntimeError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "findings": [],
                "summary": f"semgrep failed: {exc}", "analyzer": "pypi"}

    findings = [_normalize_finding(r) for r in (payload.get("results") or [])]
    return {
        "status": "success",
        "findings": findings,
        "summary": _summary(findings, "PyPI semgrep+GuardDog+chanever"),
        "analyzer": "pypi",
        "scan_root": str(scan_root),
    }
