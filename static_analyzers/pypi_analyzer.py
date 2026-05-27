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
import uuid
from pathlib import Path
from typing import Any

from ._obfuscation import scan_obfuscation, timeout_finding


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


def _force_remove_container(name: str) -> None:
    """Force-remove a named container.

    ``subprocess.run(timeout=)`` only kills the local ``docker run`` client; the
    container keeps executing detached and leaks (orphaned semgrep scans pile up
    and starve the daemon). Naming the run lets us actively reap it on timeout.
    """
    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                        text=True, timeout=15, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def _run_named(cmd: list[str], name: str, cfg) -> dict[str, Any]:
    """Run a docker semgrep command, reaping the container if it times out."""
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=cfg.semgrep_timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        _force_remove_container(name)
        raise
    if not (completed.stdout or "").strip():
        raise RuntimeError(
            f"semgrep produced no stdout "
            f"(rc={completed.returncode}, stderr={(completed.stderr or '').strip()[:300]})"
        )
    return json.loads(completed.stdout)


def _run_semgrep_docker(scan_root: Path, cfg) -> dict[str, Any]:
    name = f"chanever-semgrep-{uuid.uuid4().hex[:12]}"
    cmd: list[str] = ["docker", "run", "--rm", "--name", name,
                       "--stop-timeout", "10", "-v", f"{scan_root}:/src:ro"]
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
    return _run_named(cmd, name, cfg)


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
    # Local obfuscation heuristics run unconditionally — fast, deterministic,
    # and independent of semgrep. They catch packed/minified payloads that are
    # exactly the artifacts that make semgrep time out.
    obf_findings = scan_obfuscation(scan_root)

    try:
        payload = _run_semgrep_docker(scan_root, cfg)
    except subprocess.TimeoutExpired:
        # Timeout is not unavailability: the obfuscation pass completed and the
        # timeout itself is recorded as partial-analysis evidence.
        findings = obf_findings + [timeout_finding(scan_root, cfg.semgrep_timeout)]
        return {
            "status": "success",
            "findings": findings,
            "summary": (f"PyPI semgrep timed out after {cfg.semgrep_timeout}s; "
                        f"{len(obf_findings)} obfuscation finding(s) from local heuristics"),
            "analyzer": "pypi",
            "scan_root": str(scan_root),
        }
    except (FileNotFoundError, RuntimeError, json.JSONDecodeError) as exc:
        # Genuine infra failure (docker missing / bad output). Surface any
        # obfuscation findings we already have; only report unavailable if none.
        reason = "docker executable not found" if isinstance(exc, FileNotFoundError) else f"semgrep failed: {exc}"
        return {
            "status": "success" if obf_findings else "unavailable",
            "findings": obf_findings,
            "summary": f"{reason}; {len(obf_findings)} obfuscation finding(s) from local heuristics",
            "analyzer": "pypi",
            "scan_root": str(scan_root),
        }

    findings = [_normalize_finding(r) for r in (payload.get("results") or [])] + obf_findings
    return {
        "status": "success",
        "findings": findings,
        "summary": _summary(findings, "PyPI semgrep+GuardDog+chanever+obf"),
        "analyzer": "pypi",
        "scan_root": str(scan_root),
    }
