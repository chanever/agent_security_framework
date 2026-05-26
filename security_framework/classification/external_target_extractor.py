"""Extract external analysis targets from actions.

This module intentionally keeps the extraction lightweight. The actual
reputation/static analyzers can use these targets when they are implemented.
"""

from __future__ import annotations

import re
import shlex


URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def _shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _package_target(ecosystem: str, name: str, source: str) -> dict:
    return {
        "type": "package",
        "ecosystem": ecosystem,
        "name": name,
        "version": None,
        "source": source,
    }


def extract_external_targets(action: dict, context: dict | None = None, classification: dict | None = None) -> list[dict]:
    """Return package, repo, URL, or container image targets for later analysis."""
    del context, classification
    if action.get("type") != "command":
        return []

    command = action.get("command", "")
    lowered = command.lower()
    words = _shell_words(command)
    targets: list[dict] = []

    for url in URL_RE.findall(command):
        targets.append({"type": "url", "url": url, "source": command})

    if len(words) >= 3 and words[0] == "git" and words[1] == "clone":
        targets.append({"type": "repo", "url": words[2], "source": command})

    if len(words) >= 3 and words[0] in {"pip", "pip3"} and words[1] == "install":
        skip_next = False
        for name in words[2:]:
            if skip_next:
                targets.append({"type": "requirements_file", "path": name, "source": command})
                skip_next = False
                continue
            if name in {"-r", "--requirement"}:
                skip_next = True
                continue
            if name.startswith("-"):
                continue
            if name in {".", "./"}:
                targets.append({"type": "local_package", "path": name, "source": command})
                continue
            targets.append(_package_target("pypi", name, command))

    if len(words) >= 3 and words[0] == "npm" and words[1] in {"install", "i", "add"}:
        for name in words[2:]:
            if name.startswith("-"):
                continue
            targets.append(_package_target("npm", name, command))

    if len(words) >= 3 and words[0] == "yarn" and words[1] == "add":
        for name in words[2:]:
            if name.startswith("-"):
                continue
            targets.append(_package_target("npm", name, command))

    if "apt install" in lowered or "apt-get install" in lowered:
        for name in words[2:]:
            if name.startswith("-"):
                continue
            targets.append(_package_target("apt", name, command))

    if len(words) >= 3 and words[0] == "docker" and words[1] == "pull":
        targets.append({"type": "container_image", "name": words[2], "source": command})

    seen = set()
    unique_targets = []
    for target in targets:
        key = tuple(sorted(target.items()))
        if key in seen:
            continue
        seen.add(key)
        unique_targets.append(target)
    return unique_targets
