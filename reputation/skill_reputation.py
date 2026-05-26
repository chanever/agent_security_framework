"""Agent-skill reputation — heuristic only.

No central skill registry exists today (gptlog §3000-3028), so this module
emits a *manifest-derived* heuristic signal rather than calling out to a
remote service. The verifier reads:

- ``declared_author``        — author / publisher field in manifest.json
- ``declared_purpose``       — SKILL.md frontmatter description
- ``signature_present``      — boolean: is there a *.sig file alongside the manifest?
- ``manifest_files``         — list of manifest paths actually present in the workspace
- ``trust_bucket``           — ``unsigned-unknown-author`` | ``unsigned-known-author`` |
                                ``signed-known-author``

This is a placeholder for a future registry-backed signal. For paper
purposes the field is reported honestly as "heuristic" so the verifier and
reader can treat it accordingly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


_FRONTMATTER_RE = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)


def _read_frontmatter(text: str) -> dict[str, str]:
    m = _FRONTMATTER_RE.search(text)
    if not m:
        return {}
    out: dict[str, str] = {}
    for line in m.group("body").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _bucket(signed: bool, author_known: bool) -> str:
    if signed and author_known:
        return "signed-known-author"
    if author_known:
        return "unsigned-known-author"
    return "unsigned-unknown-author"


def lookup(node: dict, *, timeout: int = 10) -> dict | None:
    scan_root_str = node.get("scan_root")
    if not scan_root_str:
        return {
            "source": "skill-heuristic",
            "target_type": "skill",
            "target_name": node.get("name", ""),
            "status": "skipped",
            "summary": "Remote skill — heuristic reputation not applicable.",
        }
    scan_root = Path(scan_root_str)
    declared_author = ""
    declared_purpose = ""
    signature_present = False
    manifest_files: list[str] = []

    for surface in node.get("instruction_surfaces") or []:
        p = scan_root / surface
        if not p.is_file():
            continue
        manifest_files.append(surface)
        if surface.lower().endswith("skill.md"):
            text = p.read_text(encoding="utf-8", errors="replace")
            fm = _read_frontmatter(text)
            declared_author = fm.get("author", "") or fm.get("publisher", "")
            declared_purpose = fm.get("description", "") or fm.get("purpose", "")
        elif surface.lower().endswith("manifest.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                declared_author = declared_author or str(data.get("author") or data.get("publisher") or "")
                declared_purpose = declared_purpose or str(data.get("description") or data.get("purpose") or "")
            except (json.JSONDecodeError, OSError):
                pass

    # Detect a signature file alongside any manifest.
    for ext in (".sig", ".asc", ".sigstore"):
        if any((scan_root / f).exists() for f in (f"SKILL.md{ext}", f"manifest.json{ext}", f"skill.md{ext}")):
            signature_present = True
            break

    return {
        "source": "skill-heuristic",
        "target_type": "skill",
        "target_name": node.get("name", ""),
        "status": "success",
        "declared_author": declared_author,
        "declared_purpose": declared_purpose[:200],
        "signature_present": signature_present,
        "manifest_files": manifest_files[:10],
        "trust_bucket": _bucket(signature_present, bool(declared_author)),
        "summary": (
            f"Skill heuristic: author={declared_author!r} signed={signature_present} "
            f"→ trust_bucket={_bucket(signature_present, bool(declared_author))}"
        ),
    }
