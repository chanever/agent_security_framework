#!/usr/bin/env python3
"""Build a CHASE-paper-shaped benign corpus: 30 small PyPI packages with
setup.py (matching the paper's sampling filter "must contain both setup.py
and __init__.py"). Reuses recently-uploaded packages from PyPI's RSS feed
so we approximate the paper's "random new releases" distribution as
closely as the public APIs allow.
"""

from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

OUT_ROOT = Path("/home/user/agent_security_framework/bench/corpora/chase_compatible_ben")
SDIST_MAX_BYTES = 200_000   # paper's distribution: small new releases
N_TARGET = 30

RSS_URLS = [
    "https://pypi.org/rss/packages.xml",  # newly-registered projects
    "https://pypi.org/rss/updates.xml",   # recent uploads (any project)
]


def fetch_candidate_names() -> list[str]:
    """Walk both PyPI RSS feeds and dedup the package names that appear."""
    names: list[str] = []
    seen: set[str] = set()
    for url in RSS_URLS:
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                xml_bytes = resp.read()
        except Exception:
            continue
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            continue
        for item in root.iter("item"):
            title = (item.findtext("title") or "").strip()
            # RSS titles look like "0wneg added to PyPI" or "1.0.0 of foo added to PyPI"
            # Pull the package name out: it's either the first token (new projects feed)
            # or the token immediately after "of" (updates feed).
            tokens = title.split()
            if "of" in tokens:
                idx = tokens.index("of")
                if idx + 1 < len(tokens):
                    name = tokens[idx + 1]
                else:
                    continue
            else:
                name = tokens[0] if tokens else ""
            name = name.strip()
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return names


def fetch_sdist_url(pkg: str) -> tuple[str, int] | None:
    """Get the sdist URL + size for the latest release of ``pkg`` from PyPI
    JSON API. None if no sdist (wheel-only releases) or fetch failure."""
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    for entry in data.get("urls") or []:
        if entry.get("packagetype") == "sdist":
            return entry["url"], int(entry.get("size") or 0)
    return None


def has_setup_py(tarball: Path) -> Path | None:
    """Extract ``tarball`` to a fresh temp dir, descend to the directory
    that owns setup.py, and return that path (or None if no setup.py)."""
    workdir = Path(tempfile.mkdtemp(prefix="chase_check_"))
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            tf.extractall(workdir)
    except (tarfile.TarError, OSError):
        shutil.rmtree(workdir, ignore_errors=True)
        return None
    for setup in workdir.rglob("setup.py"):
        # also require __init__.py somewhere — paper's filter
        if any(workdir.rglob("__init__.py")):
            return setup.parent
        break
    shutil.rmtree(workdir, ignore_errors=True)
    return None


def install_case(pkg: str, tarball: Path, src_dir: Path) -> None:
    """Move ``src_dir`` (the dir owning setup.py) into the corpus tree as
    ``<OUT_ROOT>/<pkg>/artifact/<pkg-ver>/...``."""
    case_dir = OUT_ROOT / pkg / "artifact"
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src_dir), str(case_dir / src_dir.name))


def main() -> int:
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    existing = {p.name for p in OUT_ROOT.iterdir() if p.is_dir()}
    print(f"start: {len(existing)} cases already in {OUT_ROOT}")

    candidates = fetch_candidate_names()
    print(f"RSS candidates: {len(candidates)} unique package names")

    kept = 0
    for pkg in candidates:
        if len(existing) >= N_TARGET:
            break
        if pkg in existing:
            continue

        sdist = fetch_sdist_url(pkg)
        if sdist is None:
            continue
        url, size = sdist
        if size > SDIST_MAX_BYTES:
            continue

        workdir = Path(tempfile.mkdtemp(prefix="chase_dl_"))
        tarball = workdir / f"{pkg}.tar.gz"
        try:
            urllib.request.urlretrieve(url, tarball)
        except Exception:
            shutil.rmtree(workdir, ignore_errors=True)
            continue

        pkg_dir = has_setup_py(tarball)
        if pkg_dir is None:
            shutil.rmtree(workdir, ignore_errors=True)
            continue

        install_case(pkg, tarball, pkg_dir)
        existing.add(pkg)
        kept += 1
        print(f"  ok ({len(existing):2d}/{N_TARGET}) {pkg:30s} ({size:>6d} B)")
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"done: {len(existing)} cases total ({kept} new)")
    return 0 if len(existing) >= N_TARGET else 1


if __name__ == "__main__":
    raise SystemExit(main())
