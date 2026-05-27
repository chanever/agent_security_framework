"""OSSF malicious-packages — second primary source for known-malicious lists.

Source: https://github.com/ossf/malicious-packages
License: Apache-2.0
Maintainer: OpenSSF Foundation
Layout: ``osv/malicious/<ecosystem>/<package-name>/MAL-YYYY-NNNN.json``

Operates side-by-side with the DataDog corpus (``_known_bad.load_known_bad_*``)
so we can report **two independent primary sources** when both flag the
same package — a stronger reliability claim than relying on a single
source.

Acquisition: ``gh api`` subprocess against the per-ecosystem subtree.
Authenticated requests get 5000/hr (vs anonymous 60/hr), and a single
subtree call returns up to 100k entries non-truncated — enough for every
ecosystem (npm has the most at ~200k, but we cap at 100k per fetch and
the npm subtree happens to fit when queried recursively; if it ever
exceeds the cap we'll need to switch to a clone-based loader).

Prerequisites: ``gh auth status`` showing a logged-in account. We do not
read the token directly; we shell out to ``gh api`` so its credential
resolution (keychain / env var / config file) stays the single source.
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache


SUBTREE_PATH_FMT = "repos/ossf/malicious-packages/git/trees/main:osv/malicious/{ecosystem}"


@lru_cache(maxsize=8)
def load_ossf_malicious(ecosystem: str, *, timeout: int = 30) -> frozenset[str]:
    """Confirmed-malicious package names for ``ecosystem``.

    Returns an empty frozenset if ``gh`` is not installed / authenticated
    or the subtree fetch fails. The caller still has the DataDog signal in
    that case, so a missing OSSF response degrades to single-source.
    """
    try:
        proc = subprocess.run(
            ["gh", "api", SUBTREE_PATH_FMT.format(ecosystem=ecosystem)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return frozenset()
    if proc.returncode != 0 or not proc.stdout.strip():
        return frozenset()
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return frozenset()
    if payload.get("truncated"):
        # Honest report — log to stderr for the operator. Caller still
        # gets whatever we did receive, but the caller should know it is
        # incomplete.
        print(
            f"[ossf-malicious] WARN: {ecosystem} subtree truncated; "
            f"received {len(payload.get('tree') or [])} entries",
            flush=True,
        )
    return frozenset(
        e["path"].lower()
        for e in (payload.get("tree") or [])
        if isinstance(e, dict) and e.get("type") == "tree" and e.get("path")
    )


def is_ossf_malicious(name: str, ecosystem: str) -> bool:
    return name.lower() in load_ossf_malicious(ecosystem)
