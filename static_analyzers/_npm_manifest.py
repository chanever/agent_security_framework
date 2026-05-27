"""npm manifest (package.json) install-hook heuristics.

The single most common npm supply-chain pattern is a lifecycle install hook
(``preinstall`` / ``install`` / ``postinstall``) that runs code the moment the
package is installed — typically ``node index.js`` where index.js does recon
and exfiltration (the DataDog malicious-intent npm corpus is full of these).

GuardDog ships an ``npm-install-script`` semgrep rule for this, but it relies on
``languages: [json]`` + ``paths.include: ["*/package.json"]`` — and the path
glob does not match a ``package.json`` at the scan root (where it lives once a
package is unpacked and mounted as ``/src``). So semgrep silently filters it
out. We detect it locally instead: deterministic, mount-layout-independent, no
docker, milliseconds.

Findings:

- ``npm.install-hook-runs-script`` (HIGH) — an install hook executes a bundled
  local script (``node index.js``, ``./setup.sh`` ...) or a shell payload.
  Install-time code execution from package-local files is the canonical recon
  vector.
- ``npm.install-hook`` (MEDIUM) — a non-allowlisted install hook that is not
  obviously running a bundled script. Still a risk surface for the verifier.

Known build-tool hooks (node-gyp, prebuild, husky, patch-package, prisma
generate ...) are allowlisted — mirrors GuardDog's own npm-install-script
allowlist — so legitimate native-build packages are not flagged.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_LIFECYCLE = ("preinstall", "install", "postinstall")

# Commands that legitimately run at install time. Mirrors the negative-lookahead
# allowlist in GuardDog's npm-install-script.yml plus common native builders.
_BENIGN_HOOK_RE = re.compile(
    r"^\s*(?:"
    r"node-gyp(?:\s|$)|node-gyp-build|prebuild|prebuild-install|electron-rebuild|"
    r"husky(?:\s+install)?|patch-package|npx\s+patch-package|nuxt\s+prepare|"
    r"npx\s+only-allow\s+pnpm|prisma\s+generate|ibmtelemetry\b|"
    r"tsc(?:\s*\|\|\s*exit\s*0)?|echo\b|true\b|:\s*$"
    r")",
    re.IGNORECASE,
)

# Hook that runs a package-local script or a shell payload (the malicious shape).
_RUNS_SCRIPT_RE = re.compile(
    r"(?:\bnode\b|\bnode\s|\bts-node\b|\bbash\b|\bsh\b|\bpython3?\b|"
    r"\./|\.\\|curl\b|wget\b|\beval\b|\|\s*(?:bash|sh)\b)",
    re.IGNORECASE,
)


def _finding(rule_id: str, severity: str, path: str, message: str) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "path": path,
        "line": 0,
        "message": message,
        "source": "npm-manifest-heuristic",
    }


def scan_install_hooks(scan_root: Path) -> list[dict]:
    """Walk for package.json files and flag risky install hooks. Local, fast."""
    findings: list[dict] = []
    if not scan_root.is_dir():
        return findings
    for pj in scan_root.rglob("package.json"):
        if "node_modules" in pj.parts:
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
        rel = str(pj.relative_to(scan_root))
        for hook in _LIFECYCLE:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            if _BENIGN_HOOK_RE.match(cmd):
                continue
            if _RUNS_SCRIPT_RE.search(cmd):
                findings.append(_finding(
                    "npm.install-hook-runs-script", "HIGH", rel,
                    f"{hook!r} lifecycle hook runs code at install time: {cmd!r} — "
                    f"package-local install-time execution is the canonical npm "
                    f"supply-chain recon/exfil vector.",
                ))
            else:
                findings.append(_finding(
                    "npm.install-hook", "MEDIUM", rel,
                    f"{hook!r} lifecycle hook present (non build-tool): {cmd!r} — "
                    f"runs automatically on install; weigh as a risk surface.",
                ))
    return findings
