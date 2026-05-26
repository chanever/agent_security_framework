"""Generic repo / mixed-artifact static analyzer.

A repo node gets two scans:

1. **Chained semgrep** (p/security-audit + GuardDog + GuardDog unscoped +
   chanever rules) — same chain pypi_analyzer uses, picks up
   language-agnostic patterns (eval/exec, base64, env reads, etc.).

2. **Gitleaks** (zricethezav/gitleaks docker image) — git-aware secret
   detection. Catches GitHub PATs, AWS keys, GCP service-account JSON,
   generic high-entropy strings. Output normalized into the same
   findings schema as semgrep.

Merging gives repo nodes a *different* result shape from a bare PyPI
package: a malicious repo with no install-hook patterns but a leaked
GitHub PAT in ``config.py`` would slip past pypi_analyzer alone but
gets caught by Gitleaks here.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import pypi_analyzer


GITLEAKS_IMAGE = "zricethezav/gitleaks:latest"
GITLEAKS_TIMEOUT = 60


def _run_gitleaks(scan_root: Path) -> list[dict]:
    """Run gitleaks dir scan and return normalized findings."""
    report = scan_root / ".gitleaks_report.json"
    if report.exists():
        report.unlink()
    cmd = [
        "docker", "run", "--rm",
        "--stop-timeout", "10",
        "-v", f"{scan_root}:/repo:rw",
        GITLEAKS_IMAGE, "dir", "/repo",
        "--report-format=json",
        "--report-path=/repo/.gitleaks_report.json",
        "--no-banner", "--redact",
        "--exit-code=0",
    ]
    try:
        subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=GITLEAKS_TIMEOUT, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if not report.exists():
        return []
    try:
        raw = json.loads(report.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    finally:
        try:
            report.unlink()
        except OSError:
            pass
    findings: list[dict] = []
    for hit in raw or []:
        path = (hit.get("File") or "").lstrip("/")
        if path.startswith("repo/"):
            path = path[len("repo/"):]
        findings.append({
            "rule_id": f"gitleaks.{hit.get('RuleID','unknown')}",
            "severity": "HIGH",  # leaked secret = always high
            "path": path,
            "line": int(hit.get("StartLine") or 0),
            "message": hit.get("Description") or "Gitleaks secret detection",
            "source": "gitleaks",
        })
    return findings


def analyze(node: dict, cfg) -> dict:
    semgrep_result = pypi_analyzer.analyze(node, cfg)
    findings: list[dict] = list(semgrep_result.get("findings") or [])
    gitleaks_finding_count = 0

    scan_root_str = node.get("scan_root")
    if scan_root_str and Path(scan_root_str).is_dir():
        gl = _run_gitleaks(Path(scan_root_str))
        findings.extend(gl)
        gitleaks_finding_count = len(gl)

    semgrep_status = semgrep_result.get("status", "skipped")
    if semgrep_status in {"success", "skipped"}:
        status = "success" if findings else semgrep_status
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        summary = (
            f"repo: {len(findings)} findings "
            f"(CRITICAL={sev_counts['CRITICAL']}, HIGH={sev_counts['HIGH']}, "
            f"MEDIUM={sev_counts['MEDIUM']}, LOW={sev_counts['LOW']}); "
            f"gitleaks contributed {gitleaks_finding_count}"
        )
    else:
        # semgrep upstream told us why (docker missing / timed out); keep
        # that diagnostic instead of burying it.
        status = semgrep_status
        summary = semgrep_result.get("summary") or f"repo analyzer {semgrep_status}"

    return {
        "status": status,
        "findings": findings,
        "summary": summary,
        "analyzer": "repo",
        "gitleaks_finding_count": gitleaks_finding_count,
    }
