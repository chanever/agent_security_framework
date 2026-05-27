"""Obfuscation / analysis-resistance heuristics.

Insight: benign packages are quick to analyze; malicious packages routinely
obfuscate (giant single-file payloads, base64/hex blobs, minified one-liners)
to defeat static analysis. So *analysis resistance is itself a signal*. These
heuristics run locally (no docker, milliseconds) and produce findings even
when semgrep times out or skips a file.

Findings produced (each in the standard analyzer schema):

- ``obf.packed-source-file``     — a source file that is large AND has a very
  high bytes-per-line ratio. Raw file size alone false-positives on legit
  mature modules (click's ``core.py`` is 137 KB of readable multi-line code);
  the discriminator is packing density. Benign source averages ~30–80
  bytes/line; packed/minified blobs are thousands. HIGH.
- ``obf.long-single-line``       — a single line exceeds the minified/packed
  threshold (legit source rarely has 2000-char lines). MEDIUM.
- ``obf.analysis-timeout``       — emitted by the caller when semgrep did not
  finish within the timeout. MEDIUM, because a large benign package can also
  be slow; it is context for the verifier (static results are partial), while
  the deterministic packed/long-line findings above carry the real signal.

Note on Shannon entropy: we tested per-file byte entropy as an
encoded-payload signal and found it unreliable for this corpus — benign
source averages 5.0–5.6 bits/byte (varied identifiers, unicode tables, test
fixtures) while the real packed payload (EZBEAMER's 151 KB ``__init__.py``)
measured only 3.02 because it is repetitive. Entropy both false-positived on
benign and missed the actual malware, so it was dropped in favour of packing
density, which separated the classes cleanly with zero benign false positives.
"""

from __future__ import annotations

from pathlib import Path

# Thresholds — tuned so normal source passes and obfuscated payloads trip.
# Raw file size alone is a poor signal: legit mature modules are large but
# multi-line (click's core.py is 137 KB across ~3500 lines, ~40 bytes/line).
# Packed payloads cram everything onto few lines (EZBEAMER's __init__.py is
# 151 KB across ~25 lines, ~6000 bytes/line). So we require oversize AND a
# high bytes-per-line density before flagging.
OVERSIZED_BYTES = 50_000          # floor: only consider large files
PACKED_BYTES_PER_LINE = 500       # >500 avg bytes/line ⇒ packed, not source
LONG_LINE_CHARS = 2_000           # minified/packed one-liner
SOURCE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".rb", ".go", ".sh"}
MAX_FILES_SCANNED = 200           # bound the walk on pathological trees


def _finding(rule_id: str, severity: str, path: str, line: int, message: str) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "path": path,
        "line": line,
        "message": message,
        "source": "obfuscation-heuristic",
    }


def scan_obfuscation(scan_root: Path) -> list[dict]:
    """Walk ``scan_root`` and emit obfuscation findings. Local, fast, no docker."""
    findings: list[dict] = []
    if not scan_root.is_dir():
        return findings

    scanned = 0
    for path in scan_root.rglob("*"):
        if scanned >= MAX_FILES_SCANNED:
            break
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        scanned += 1
        rel = str(path.relative_to(scan_root))
        try:
            data = path.read_bytes()
        except OSError:
            continue

        size = len(data)
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines() or [""]
        bytes_per_line = size / len(lines)

        # Packed source: large AND dense. Both conditions required so that
        # legit large multi-line modules (high size, low density) don't trip.
        if size >= OVERSIZED_BYTES and bytes_per_line >= PACKED_BYTES_PER_LINE:
            findings.append(_finding(
                "obf.packed-source-file", "HIGH", rel, 0,
                f"Source file is {size:,} bytes across {len(lines):,} lines "
                f"({bytes_per_line:,.0f} bytes/line) — packing density far above "
                f"hand-written code; common obfuscation pattern.",
            ))

        # Long single line — minified/packed one-liner.
        for i, ln in enumerate(lines, start=1):
            if len(ln) >= LONG_LINE_CHARS:
                findings.append(_finding(
                    "obf.long-single-line", "MEDIUM", rel, i,
                    f"Line {i} is {len(ln):,} chars — minified/packed blob, "
                    f"resists static analysis.",
                ))
                break  # one per file is enough signal

    return findings


def timeout_finding(scan_root: Path, timeout_seconds: int | None = None) -> dict:
    """Finding emitted when semgrep did not finish within the timeout.

    Honest framing: static results are partial. A large benign package can be
    slow too, so this is MEDIUM context for the verifier, not a verdict. The
    deterministic packed/long-line findings (if any) carry the real signal.
    """
    secs = f" after {timeout_seconds}s" if timeout_seconds else ""
    return _finding(
        "obf.analysis-timeout", "MEDIUM", str(scan_root), 0,
        f"semgrep did not finish{secs}; static analysis of this artifact is "
        "partial. Analysis-resistant artifacts (very large/packed files) are "
        "a known evasion pattern, so weigh this alongside the heuristic "
        "findings rather than as proof of safety.",
    )
