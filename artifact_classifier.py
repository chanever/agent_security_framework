"""Classify a proposed external interaction into an ``artifact_graph``.

Per the GPT MDS architecture design (gptlog §3034-3112): a single action
can resolve to multiple artifact nodes, not one — a ``git clone`` target
may simultaneously be a *repo* AND a *python_package* AND a *skill*. The
classifier therefore returns a list of artifact nodes, each with its own
``artifact_type`` + ``detected_kinds`` + scan-target paths, so the per-type
static / reputation analyzers downstream can dispatch correctly.

Returned shape (one entry per node):

    {
      "artifact_type": "github_repo" | "pypi_package" | "npm_package" |
                       "skill" | "mcp_server" | "container_image" | "url" |
                       "requirements_file",
      "detected_kinds": [...],                # secondary classifications
      "source": "<url or local path>",
      "scan_root": "<absolute path to scan, or None for remote-only>",
      "ecosystem": "pypi" | "npm" | "apt" | None,
      "name": "<package name when ecosystem applies>",
      "manifests": ["pyproject.toml", "setup.py", ...],
      "instruction_surfaces": ["SKILL.md", "README.md", ...],
      "execution_surfaces": ["scripts/install.sh", "setup.py", ...],
    }

The classifier *does not* download or execute anything. Remote artifacts
(git URLs, package names without a local extracted tree) get a minimal
node with the URL/name only — the per-type analyzer decides whether to
fetch (always read-only) or skip.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# File-name → which artifact kind it indicates living in this workspace.
_KIND_SIGNATURES: dict[str, list[str]] = {
    "pyproject.toml":   ["python_project"],
    "setup.py":         ["python_project"],
    "setup.cfg":        ["python_project"],
    "requirements.txt": ["python_project"],
    "package.json":     ["nodejs_project"],
    "package-lock.json": ["nodejs_project"],
    "yarn.lock":        ["nodejs_project"],
    "pnpm-lock.yaml":   ["nodejs_project"],
    "Dockerfile":       ["dockerized_tool"],
    "docker-compose.yml": ["dockerized_tool"],
    "Cargo.toml":       ["rust_project"],
    "go.mod":           ["go_project"],
    "Gemfile":          ["ruby_project"],
    "SKILL.md":         ["agent_skill"],
    "skill.md":         ["agent_skill"],
    "skill_inject.md":  ["agent_skill"],
    "manifest.json":    ["agent_tool"],
    "mcp.json":         ["mcp_server"],
    "tool.json":        ["agent_tool"],
    "action.yml":       ["github_action"],
    ".github/workflows": ["github_action"],
}

_INSTRUCTION_SURFACES = {
    "SKILL.md", "skill.md", "README.md", "readme.md",
    "manifest.json", "tool.json", "mcp.json",
    "action.yml", "workflow.yml",
}

_EXECUTION_SURFACES = {
    "setup.py", "install.sh", "postinstall.sh", "preinstall.sh",
    "Dockerfile",
}


def _scan_local_workspace(scan_root: Path) -> dict[str, Any]:
    """Probe a workspace dir to detect kinds + manifests + surfaces.

    No execution, no recursion past two levels — just stats + filename
    matching. Cheap and safe to run on any untrusted local tree.
    """
    detected_kinds: set[str] = set()
    manifests: list[str] = []
    instruction_surfaces: list[str] = []
    execution_surfaces: list[str] = []

    if not scan_root.exists() or not scan_root.is_dir():
        return {
            "detected_kinds": [],
            "manifests": [],
            "instruction_surfaces": [],
            "execution_surfaces": [],
        }

    # Bounded BFS — depth 3, skip vendored / build / cache dirs entirely.
    SKIP_DIRS = {
        "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
        "dist", "build", ".pytest_cache", ".mypy_cache", "target",
        ".tox", "site-packages", "vendor", ".cache",
    }
    seen_names: set[str] = set()
    stack: list[tuple[Path, int]] = [(scan_root, 0)]
    while stack:
        cur, depth = stack.pop()
        try:
            entries = list(cur.iterdir())
        except (PermissionError, OSError):
            continue
        for path in entries:
            if path.is_dir():
                if path.name in SKIP_DIRS:
                    continue
                if depth < 3:
                    stack.append((path, depth + 1))
                continue
            rel = path.relative_to(scan_root)
            name = path.name
            if name in seen_names and len(seen_names) > 200:
                continue
            seen_names.add(name)
            if name in _KIND_SIGNATURES:
                detected_kinds.update(_KIND_SIGNATURES[name])
                manifests.append(str(rel))
            if name in _INSTRUCTION_SURFACES:
                instruction_surfaces.append(str(rel))
            if name in _EXECUTION_SURFACES:
                execution_surfaces.append(str(rel))
            if name.endswith(".bt") and "probe" in name.lower():
                detected_kinds.add("ebpf_probe")

    # .github/workflows/*.yml is a github_action signal — direct dir check,
    # no rglob.
    workflows_dir = scan_root / ".github" / "workflows"
    if workflows_dir.is_dir():
        try:
            if any(
                p.is_file() and p.suffix in {".yml", ".yaml"}
                for p in workflows_dir.iterdir()
            ):
                detected_kinds.add("github_action")
        except (PermissionError, OSError):
            pass

    return {
        "detected_kinds": sorted(detected_kinds),
        "manifests": sorted(set(manifests))[:30],
        "instruction_surfaces": sorted(set(instruction_surfaces))[:30],
        "execution_surfaces": sorted(set(execution_surfaces))[:30],
    }


def _node_for_local_package(target: dict, scan_root: Path) -> dict:
    """A `.` or `./` target points at the agent's current workspace."""
    probe = _scan_local_workspace(scan_root)
    kinds = probe["detected_kinds"]
    if "agent_skill" in kinds:
        artifact_type = "skill"
    elif "github_action" in kinds:
        artifact_type = "github_action"
    elif "nodejs_project" in kinds:
        artifact_type = "npm_package"
    elif "python_project" in kinds:
        artifact_type = "pypi_package"
    else:
        artifact_type = "local_directory"
    return {
        "artifact_type": artifact_type,
        "detected_kinds": kinds,
        "source": str(scan_root),
        "scan_root": str(scan_root),
        "ecosystem": "pypi" if artifact_type == "pypi_package" else
                     "npm" if artifact_type == "npm_package" else None,
        "name": scan_root.name,
        **{k: probe[k] for k in ("manifests", "instruction_surfaces", "execution_surfaces")},
    }


def _node_for_package(target: dict) -> dict:
    """A registry package (no local tree available yet)."""
    return {
        "artifact_type": "pypi_package" if target.get("ecosystem") == "pypi"
                         else "npm_package" if target.get("ecosystem") == "npm"
                         else f"{target.get('ecosystem','unknown')}_package",
        "detected_kinds": [],
        "source": f"{target.get('ecosystem','?')}:{target.get('name','?')}",
        "scan_root": None,
        "ecosystem": target.get("ecosystem"),
        "name": target.get("name"),
        "manifests": [],
        "instruction_surfaces": [],
        "execution_surfaces": [],
    }


def _node_for_repo(target: dict) -> dict:
    return {
        "artifact_type": "github_repo",
        "detected_kinds": [],
        "source": target.get("url", ""),
        "scan_root": None,
        "ecosystem": None,
        "name": (target.get("url") or "").rstrip("/").split("/")[-1],
        "manifests": [],
        "instruction_surfaces": [],
        "execution_surfaces": [],
    }


def _node_for_url(target: dict) -> dict:
    return {
        "artifact_type": "url",
        "detected_kinds": [],
        "source": target.get("url", ""),
        "scan_root": None,
        "ecosystem": None,
        "name": target.get("url", ""),
        "manifests": [],
        "instruction_surfaces": [],
        "execution_surfaces": [],
    }


def _node_for_container(target: dict) -> dict:
    return {
        "artifact_type": "container_image",
        "detected_kinds": [],
        "source": target.get("name", ""),
        "scan_root": None,
        "ecosystem": None,
        "name": target.get("name", ""),
        "manifests": [],
        "instruction_surfaces": [],
        "execution_surfaces": [],
    }


def _node_for_requirements_file(target: dict, scan_root: Path | None) -> dict:
    return {
        "artifact_type": "requirements_file",
        "detected_kinds": ["python_project"],
        "source": target.get("path", ""),
        "scan_root": str(scan_root) if scan_root else None,
        "ecosystem": "pypi",
        "name": target.get("path", ""),
        "manifests": [target.get("path", "")],
        "instruction_surfaces": [],
        "execution_surfaces": [],
    }


def classify(targets: list[dict], context: dict | None = None) -> list[dict]:
    """Convert the ``extract_external_targets`` output into an artifact graph.

    A single workspace can yield multiple nodes — a clone of a Python
    project that ALSO ships a ``SKILL.md`` produces both a ``pypi_package``
    node and a ``skill`` node so each gets its own per-type analyzer run.
    """
    ctx = context or {}
    cwd = ctx.get("cwd")
    workspace_root = Path(cwd).resolve() if cwd else None
    nodes: list[dict] = []

    has_local_package = False
    for t in targets:
        ttype = t.get("type")
        if ttype == "local_package":
            has_local_package = True
        elif ttype == "package":
            nodes.append(_node_for_package(t))
        elif ttype == "repo":
            nodes.append(_node_for_repo(t))
        elif ttype == "url":
            nodes.append(_node_for_url(t))
        elif ttype == "container_image":
            nodes.append(_node_for_container(t))
        elif ttype == "requirements_file":
            nodes.append(_node_for_requirements_file(t, workspace_root))

    # local_package + workspace → potentially MULTIPLE artifact nodes.
    # Probe once, emit a node per kind we detect.
    if workspace_root and workspace_root.exists() and workspace_root.is_dir():
        probe = _scan_local_workspace(workspace_root)
        kinds = probe["detected_kinds"]
        emitted_for_kinds: set[str] = set()

        def _push(artifact_type: str, ecosystem: str | None) -> None:
            if artifact_type in emitted_for_kinds:
                return
            emitted_for_kinds.add(artifact_type)
            nodes.append({
                "artifact_type": artifact_type,
                "detected_kinds": kinds,
                "source": str(workspace_root),
                "scan_root": str(workspace_root),
                "ecosystem": ecosystem,
                "name": workspace_root.name,
                **{k: probe[k] for k in ("manifests", "instruction_surfaces", "execution_surfaces")},
            })

        if "agent_skill" in kinds:
            _push("skill", None)
        if "github_action" in kinds:
            _push("github_action", None)
        if "nodejs_project" in kinds:
            _push("npm_package", "npm")
        if "python_project" in kinds:
            _push("pypi_package", "pypi")
        if "mcp_server" in kinds:
            _push("mcp_server", None)
        if "dockerized_tool" in kinds:
            _push("container_image", None)

        # Contract: any non-empty workspace yields at least one node so
        # downstream dispatchers always have a scan_root.
        if not emitted_for_kinds:
            _push("local_directory", None)

    return nodes
