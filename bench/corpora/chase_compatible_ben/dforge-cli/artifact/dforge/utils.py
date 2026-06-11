"""
DForge Utilities - Shared helpers used across all modules.
"""

from __future__ import annotations
import json
import shutil
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()




CONFIG_FILE = Path.cwd() / ".dforge.json"


def save_recent_folder(folder: str):
    try:
        data = {"recent_folder": folder}

        CONFIG_FILE.write_text(
            json.dumps(data, indent=4)
        )


    except Exception as e:
        print("ERROR:", e)


def load_recent_folder():
    if not CONFIG_FILE.exists():
        return None

    try:
        return json.loads(
            CONFIG_FILE.read_text()
        ).get("recent_folder")
    except Exception:
        return None
# ---------------------------------------------------------------------------
# Output path helpers
# ---------------------------------------------------------------------------

def resolve_output(
    input_path: Path,
    output: Optional[str],
    suffix: str,
    ext: Optional[str] = None,
) -> Path:
    """
    Resolve where to write the output file.

    If `output` is given -> use it.
    Otherwise derive a name from the input path + suffix + optional new extension.

    Example:
        resolve_output(Path("doc.pdf"), None, "_merged", ".pdf")
        -> Path("doc_merged.pdf")
    """
    if output:
        return Path(output)
    src = Path(input_path)
    new_ext = ext if ext is not None else src.suffix
    return src.with_name(src.stem + suffix + new_ext)


def ensure_parent(path: Path) -> None:
    """Create parent directories for path if they don't exist."""
    path.parent.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

def require_tool(tool: str, install_hint: str = "") -> None:
    """Abort with a helpful message if an external tool is not on PATH."""
    if shutil.which(tool) is None:
        msg = f"[bold red]Missing dependency:[/bold red] '{tool}' was not found on PATH."
        if install_hint:
            msg += f"\n[dim]{install_hint}[/dim]"
        console.print(Panel(msg, title="[red]Dependency Error[/red]", border_style="red"))
        sys.exit(1)


def require_tesseract() -> None:
    require_tool(
        "tesseract",
        "Install Tesseract: https://tesseract-ocr.github.io/tessdoc/Installation.html",
    )


def require_ghostscript() -> None:
    for candidate in ("gs", "gswin64c", "gswin32c"):
        if shutil.which(candidate):
            return
    console.print(
        Panel(
            "[bold red]Missing dependency:[/bold red] 'Ghostscript' was not found on PATH.\n"
            "[dim]Install from https://ghostscript.com/releases/gsdnld.html[/dim]",
            title="[red]Dependency Error[/red]",
            border_style="red",
        )
    )
    sys.exit(1)


def require_pandoc() -> None:
    require_tool(
        "pandoc",
        "Install Pandoc: https://pandoc.org/installing.html",
    )


def ghostscript_bin() -> str:
    """Return the first available Ghostscript binary name."""
    for candidate in ("gs", "gswin64c", "gswin32c"):
        if shutil.which(candidate):
            return candidate
    return "gs"  # fallback (will fail gracefully)


# ---------------------------------------------------------------------------
# Pretty printing helpers
# ---------------------------------------------------------------------------

def success(msg: str) -> None:
    console.print(f"[bold green]OK[/bold green]  {msg}")


def info(msg: str) -> None:
    console.print(f"[bold cyan]INFO[/bold cyan]  {msg}")


def warn(msg: str) -> None:
    console.print(f"[bold yellow]WARN[/bold yellow]  {msg}")


def error(msg: str) -> None:
    console.print(f"[bold red]ERROR[/bold red]  {msg}")


def abort(msg: str) -> None:
    error(msg)
    sys.exit(1)


# ---------------------------------------------------------------------------
# File collection helpers
# ---------------------------------------------------------------------------

def collect_files(
    directory: Path,
    extensions: set[str],
    recursive: bool = True,
) -> List[Path]:
    """Collect all files with the given extensions from a directory."""
    pattern = "**/*" if recursive else "*"
    files = []
    for ext in extensions:
        files.extend(directory.glob(f"{pattern}{ext}"))
    return sorted(set(files))
