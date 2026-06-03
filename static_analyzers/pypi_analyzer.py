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

# Files whose contents execute as a side effect of the install action the
# agent is being scrutinised for. setup.py runs during ``pip install``;
# __init__.py runs at first import (which most install-driven exploits trigger
# right after); package.json carries the npm pre/post-install hook scripts.
_INSTALL_TIME_BASENAMES = {
    "setup.py", "setup.cfg", "pyproject.toml",
    "__init__.py",
    "package.json", "package-lock.json",
}


def categorize_finding(path: str, rule_id: str) -> str:
    """Bucket findings by threat-model relevance to the install action.

    * ``install_time`` — code that runs when the agent executes ``pip
      install`` / ``npm install``. Direct threat to the user's machine.
    * ``use_time`` — security-audit patterns elsewhere in the package
      source (handler functions, runtime helpers). Only matter if the
      package is later *used* incorrectly; installing it alone does not
      expose the user. Popular OSS libraries accumulate many such hits,
      so the bucket lets the verifier weight them down.

    The GuardDog / chanever rule packs target install-hook patterns by
    design — they get the install_time tag regardless of file path. The
    p/security-audit rule pack is general code-quality and gets
    classified by file location.
    """
    if rule_id.startswith("guarddog_rules.") or rule_id.startswith("chanever_rules."):
        return "install_time"
    import os.path
    if os.path.basename(path or "") in _INSTALL_TIME_BASENAMES:
        return "install_time"
    return "use_time"


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
    rule_id = raw.get("check_id") or "semgrep.unknown"
    return {
        "rule_id": rule_id,
        "severity": _SEMGREP_SEVERITY_MAP.get(sev, "LOW"),
        "path": path,
        "line": line,
        "message": extra.get("message") or "",
        "source": "semgrep",
        "category": categorize_finding(path, rule_id),
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


def _scan_error_findings(payload: dict) -> list[dict]:
    """Surface semgrep rule-load / parse errors so a clean-looking result can't
    silently mask a broken scan.

    Until now we read only ``payload["results"]`` and ignored ``errors``, so a
    rule pack that failed to load (the scan-abort and npm ``--lang`` bugs were
    exactly this) returned ``success`` with 0 findings — indistinguishable from
    a genuinely clean artifact. Per-rule Timeouts are expected on packed inputs
    (handled by the obfuscation heuristic) and are NOT flagged here.
    """
    errors = payload.get("errors") or []
    hard = []
    for e in errors:
        if not isinstance(e, dict):
            continue
        if e.get("level") != "error" and e.get("code") != 2:
            continue
        etype = e.get("type")
        etypes = etype if isinstance(etype, list) else [etype]
        if any("timeout" in str(t).lower() for t in etypes):
            continue  # expected on packed/obfuscated inputs
        hard.append(e)
    if not hard:
        return []
    types = sorted({str((e.get("type") if not isinstance(e.get("type"), list)
                         else (e.get("type") or ["unknown"])[0]) or "unknown") for e in hard})
    detail = "; ".join(str(e.get("message", ""))[:120] for e in hard[:3])
    return [{
        "rule_id": "static.scan-error",
        "severity": "MEDIUM",
        "path": "",
        "line": 0,
        "message": (f"semgrep reported {len(hard)} non-timeout error(s) "
                    f"({', '.join(types)}) — static analysis may be partial, "
                    f"not a clean result: {detail}"),
        "source": "semgrep-meta",
    }]


def _summary(findings: list[dict], rules_label: str) -> str:
    counts = {b: 0 for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    install_time = 0
    use_time = 0
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        if f.get("category") == "install_time":
            install_time += 1
        elif f.get("category") == "use_time":
            use_time += 1
    return (
        f"{rules_label}: {len(findings)} findings "
        f"(CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, "
        f"MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}; "
        f"install_time={install_time}, use_time={use_time})"
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

    findings = (
        [_normalize_finding(r) for r in (payload.get("results") or [])]
        + obf_findings
        + _scan_error_findings(payload)
    )
    return {
        "status": "success",
        "findings": findings,
        "summary": _summary(findings, "PyPI semgrep+GuardDog+chanever+obf"),
        "analyzer": "pypi",
        "scan_root": str(scan_root),
    }
