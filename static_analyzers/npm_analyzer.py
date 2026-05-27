"""npm package static analyzer.

Differentiated from ``pypi_analyzer`` by:

1. ``--lang=javascript`` flag on semgrep so only `.js`/`.ts`/`.jsx`/`.tsx`
   files contribute, matching the GuardDog ``npm-*.yml`` rules which all
   carry ``languages: [javascript, typescript]``.
2. Lighter chain — GuardDog's npm-specific rules (npm-install-script,
   npm-serialize-environment, npm-exec-base64,
   npm-silent-process-execution, etc.) carry the load; p/security-audit
   is dropped to reduce noise on Python files that happen to ship inside
   the same workspace.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from ._npm_manifest import scan_install_hooks
from ._obfuscation import scan_obfuscation, timeout_finding
from .pypi_analyzer import (
    CHANEVER_RULES_DIR,
    GUARDDOG_RULES_DIR,
    GUARDDOG_UNSCOPED_DIR,
    _normalize_finding,
    _run_named,
    _scan_error_findings,
)


def _run_semgrep_npm(scan_root: Path, cfg) -> dict[str, Any]:
    name = f"chanever-semgrep-npm-{uuid.uuid4().hex[:12]}"
    cmd = ["docker", "run", "--rm", "--name", name,
           "--stop-timeout", "10", "-v", f"{scan_root}:/src:ro"]
    # NOTE: do NOT pass --lang here. semgrep rejects -l/--lang unless an inline
    # -e/--pattern is given ("must both be specified"), so combining it with
    # --config rule dirs made every npm scan fail with rc=2. The GuardDog npm
    # rules already declare `languages: [javascript, typescript]`, so semgrep
    # auto-scopes them to JS/TS files without the flag.
    semgrep_args = [
        "semgrep", "--json",
        "--timeout", "30",
        "--timeout-threshold", "3",
        "--max-memory", "2048",
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


def analyze(node: dict, cfg) -> dict:
    scan_root_str = node.get("scan_root")
    if not scan_root_str:
        return {
            "status": "skipped",
            "findings": [],
            "summary": f"npm registry-only target {node.get('name')}; static scan deferred to reputation.",
            "analyzer": "npm",
        }
    scan_root = Path(scan_root_str)
    # Deterministic local heuristics — run unconditionally, independent of
    # semgrep: obfuscation/packing + package.json install-hook detection (the
    # dominant npm supply-chain vector semgrep's path-globbed rule misses).
    local_findings = scan_obfuscation(scan_root) + scan_install_hooks(scan_root)

    try:
        payload = _run_semgrep_npm(scan_root, cfg)
    except subprocess.TimeoutExpired:
        findings = local_findings + [timeout_finding(scan_root, cfg.semgrep_timeout)]
        return {
            "status": "success",
            "findings": findings,
            "summary": (f"npm semgrep timed out after {cfg.semgrep_timeout}s; "
                        f"{len(local_findings)} finding(s) from local heuristics"),
            "analyzer": "npm",
            "scan_root": str(scan_root),
        }
    except (FileNotFoundError, RuntimeError, json.JSONDecodeError) as exc:
        reason = "docker executable not found" if isinstance(exc, FileNotFoundError) else f"semgrep failed: {exc}"
        return {
            "status": "success" if local_findings else "unavailable",
            "findings": local_findings,
            "summary": f"{reason}; {len(local_findings)} finding(s) from local heuristics",
            "analyzer": "npm",
            "scan_root": str(scan_root),
        }

    findings = (
        [_normalize_finding(r) for r in (payload.get("results") or [])]
        + local_findings
        + _scan_error_findings(payload)
    )
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    return {
        "status": "success",
        "findings": findings,
        "summary": (
            f"npm semgrep+GuardDog+chanever+obf+manifest: {len(findings)} findings "
            f"(CRITICAL={sev_counts['CRITICAL']}, HIGH={sev_counts['HIGH']}, "
            f"MEDIUM={sev_counts['MEDIUM']}, LOW={sev_counts['LOW']})"
        ),
        "analyzer": "npm",
        "scan_root": str(scan_root),
    }
