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
from pathlib import Path
from typing import Any

from .pypi_analyzer import (
    CHANEVER_RULES_DIR,
    GUARDDOG_RULES_DIR,
    GUARDDOG_UNSCOPED_DIR,
    _normalize_finding,
)


def _run_semgrep_npm(scan_root: Path, cfg) -> dict[str, Any]:
    cmd = ["docker", "run", "--rm", "--stop-timeout", "10",
            "-v", f"{scan_root}:/src:ro"]
    semgrep_args = [
        "semgrep", "--json",
        "--timeout", "30",
        "--timeout-threshold", "3",
        "--max-memory", "2048",
        "--lang", "javascript",
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
            f"semgrep produced no stdout for npm scan "
            f"(rc={completed.returncode}, stderr={(completed.stderr or '').strip()[:200]})"
        )
    return json.loads(completed.stdout)


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
    try:
        payload = _run_semgrep_npm(scan_root, cfg)
    except FileNotFoundError:
        return {"status": "unavailable", "findings": [],
                "summary": "docker executable not found", "analyzer": "npm"}
    except subprocess.TimeoutExpired:
        return {"status": "unavailable", "findings": [],
                "summary": f"semgrep timed out after {cfg.semgrep_timeout}s", "analyzer": "npm"}
    except (RuntimeError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "findings": [],
                "summary": f"semgrep failed: {exc}", "analyzer": "npm"}

    findings = [_normalize_finding(r) for r in (payload.get("results") or [])]
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    return {
        "status": "success",
        "findings": findings,
        "summary": (
            f"npm semgrep --lang=javascript+GuardDog+chanever: {len(findings)} findings "
            f"(CRITICAL={sev_counts['CRITICAL']}, HIGH={sev_counts['HIGH']}, "
            f"MEDIUM={sev_counts['MEDIUM']}, LOW={sev_counts['LOW']})"
        ),
        "analyzer": "npm",
        "scan_root": str(scan_root),
    }
