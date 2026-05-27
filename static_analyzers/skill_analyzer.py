"""Agent skill static analyzer.

GPT MDS design (gptlog §2979-3028 + §3373-3438): skill artifacts have
**instruction surfaces** (SKILL.md, manifest.json, README) carrying natural
language for the agent, and **execution surfaces** (scripts/*.py, install.sh)
carrying actual code. The split-attack pattern is "SKILL.md looks normal,
scripts/extract.py exfiltrates" — neither file alone trips a single-axis
detector but together they form a composite finding.

What this analyzer produces:

1. **Phrase findings** — chanever ``SUSPICIOUS_INSTRUCTION_PHRASES`` matched
   against every instruction surface (not truncated to 2000 chars; full file
   up to 12k). Captures contextual injection that substring matching can
   reach.
2. **Capability extraction** — declared_capabilities from SKILL.md YAML
   frontmatter (when present). Used by the verifier to compare against
   actual observed capabilities from sandbox runs.
3. **Cross-file reference walk** — every relative file path mentioned in
   instruction surfaces (``ooxml/scripts/unpack.py``, ``scripts/install.sh``
   etc.) gets *also* read into the evidence so the verifier sees what the
   SKILL.md was pointing at. The smoke run found that ``obvious_injections
   1–3`` plant the payload in ``ooxml.md`` rather than ``SKILL.md`` itself —
   without ref-walking we miss those entirely.
4. **Semgrep on execution surfaces** — same chained rule stack as
   pypi_analyzer.
"""

from __future__ import annotations

import re
from pathlib import Path

from security_framework.evidence.evidence_builder import _safe_excerpt, extract_suspicious_instructions
from security_framework.evidence.policy import WEAK_INSTRUCTION_PHRASES

from . import pypi_analyzer


def _cross_file_tier(matched: list[str]) -> tuple[str, str, list[str], list[str]]:
    """Tier a referenced file's phrase matches.

    A lone generic phrase (e.g. "send to" in a benign agent-creation doc) is
    weak evidence → MEDIUM. A strong marker, or >=2 distinct weak phrases
    co-occurring (the credential-exfil combo), is a real cross-file split
    attack → HIGH.
    """
    strong = [p for p in matched if p not in WEAK_INSTRUCTION_PHRASES]
    weak = [p for p in matched if p in WEAK_INSTRUCTION_PHRASES]
    if strong or len(set(weak)) >= 2:
        return "HIGH", "chanever-skill-cross-file-split", strong, weak
    return "MEDIUM", "chanever-skill-cross-file-mention", strong, weak


# capture leading "key: value" lines from a YAML frontmatter block.
_FRONTMATTER_RE = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)
_REF_PATH_RE = re.compile(r"`([\w./\-]+\.(?:py|sh|md|yml|yaml|json|toml))`")


def _read_frontmatter(text: str) -> dict[str, str]:
    m = _FRONTMATTER_RE.search(text)
    if not m:
        return {}
    fm: dict[str, str] = {}
    for line in m.group("body").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        fm[k.strip()] = v.strip().strip('"').strip("'")
    return fm


def _walk_referenced_files(text: str, scan_root: Path, max_files: int = 10) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for ref in set(_REF_PATH_RE.findall(text)):
        candidate = (scan_root / ref).resolve()
        try:
            candidate.relative_to(scan_root.resolve())
        except ValueError:
            continue  # escapes workspace; refuse
        if candidate.is_file():
            out.append((ref, _safe_excerpt(candidate)))
            if len(out) >= max_files:
                break
    return out


def analyze(node: dict, cfg) -> dict:
    scan_root_str = node.get("scan_root")
    if not scan_root_str:
        return {
            "status": "skipped",
            "findings": [],
            "summary": "Skill node has no local scan_root.",
            "analyzer": "skill",
        }
    scan_root = Path(scan_root_str)
    findings: list[dict] = []
    declared_capabilities: list[str] = []
    declared_purpose = ""
    walked_refs: list[dict] = []
    phrase_hits_by_path: dict[str, list[str]] = {}

    # 1) Instruction surfaces — phrase scan + frontmatter
    for surface in node.get("instruction_surfaces") or []:
        path = scan_root / surface
        if not path.is_file():
            continue
        text = _safe_excerpt(path)
        # Phrase scan
        matched = extract_suspicious_instructions(text)
        if matched:
            phrase_hits_by_path[surface] = matched
            for phrase in matched:
                findings.append({
                    "rule_id": "chanever-skill-phrase-match",
                    "severity": "MEDIUM",
                    "path": surface,
                    "line": 0,
                    "message": f"Instruction surface mentions suspicious phrase {phrase!r}",
                    "source": "chanever-skill",
                })
        # Frontmatter for SKILL.md
        if surface.lower().endswith("skill.md"):
            fm = _read_frontmatter(text)
            declared_purpose = fm.get("description", "") or fm.get("purpose", "")
            cap = fm.get("capabilities") or fm.get("allowed", "")
            if cap:
                declared_capabilities = [c.strip() for c in cap.split(",") if c.strip()]
        # Walk references — the cross-file split attack lives here.
        for ref_path, ref_excerpt in _walk_referenced_files(text, scan_root):
            ref_matched = extract_suspicious_instructions(ref_excerpt)
            walked_refs.append({
                "ref_path": ref_path,
                "ref_excerpt": ref_excerpt[:600],
                "phrase_matches": ref_matched,
                "referenced_from": surface,
            })
            if ref_matched:
                severity, rule_id, strong, weak = _cross_file_tier(ref_matched)
                if severity == "HIGH":
                    why = (f"strong marker(s) {strong!r}" if strong
                           else f"{len(set(weak))} co-occurring sensitive terms {sorted(set(weak))!r}")
                    detail = f"— possible cross-file split attack ({why})"
                else:
                    detail = "— weak signal (single generic term in referenced file)"
                for phrase in ref_matched:
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "path": ref_path,
                        "line": 0,
                        "message": (
                            f"File {ref_path!r} referenced by {surface!r} contains suspicious "
                            f"phrase {phrase!r} {detail}"
                        ),
                        "source": "chanever-skill",
                    })

    # 2) Execution surfaces — run semgrep chain on whole scan_root
    pypi_result = pypi_analyzer.analyze(node, cfg)
    if pypi_result.get("status") == "success":
        findings.extend(pypi_result["findings"])

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
    summary = (
        f"Skill analyzer: {len(findings)} findings "
        f"(CRITICAL={severity_counts['CRITICAL']}, HIGH={severity_counts['HIGH']}, "
        f"MEDIUM={severity_counts['MEDIUM']}, LOW={severity_counts['LOW']}); "
        f"refs walked: {len(walked_refs)}"
    )
    return {
        "status": "success",
        "findings": findings,
        "summary": summary,
        "analyzer": "skill",
        "declared_purpose": declared_purpose,
        "declared_capabilities": declared_capabilities,
        "walked_references": walked_refs[:10],
        "phrase_hits_by_path": phrase_hits_by_path,
    }
