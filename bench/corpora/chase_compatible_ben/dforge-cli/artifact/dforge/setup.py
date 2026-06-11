import subprocess
from shutil import which

from rich.console import Console

from dforge.config_manager import set_tool_path
from pathlib import Path

console = Console()


def setup_dependencies():

    packages = [
    ("Poppler", "oschwartz10612.Poppler"),
    ("Pandoc", "JohnMacFarlane.Pandoc"),
    ("MiKTeX", "MiKTeX.MiKTeX"),
    ]

    for name, package_id in packages:

        console.print(
            f"[cyan]Installing {name}...[/cyan]"
        )

        subprocess.run(
            [
                "winget",
                "install",
                "--id",
                package_id,
                "-e",
            ]
        )

    # Save discovered tools

    pdfinfo = find_pdfinfo()
    pandoc = find_pandoc()
    tesseract = which("tesseract")
    xelatex = find_xelatex()
    ghostscript = (
        which("gswin64c")
        or which("gswin32c")
        or which("gs")
    )

    if pdfinfo:
        set_tool_path("poppler", pdfinfo)

    if pandoc:
        set_tool_path("pandoc", pandoc)
    if xelatex:
        set_tool_path("xelatex", xelatex)
    if tesseract:
        set_tool_path("tesseract", tesseract)

    if ghostscript:
        set_tool_path("ghostscript", ghostscript)

    console.print(
        "\n[bold green]Setup complete.[/bold green]"
    )
def find_pdfinfo():
    roots = [
        Path.home() / "AppData/Local/Microsoft/WinGet/Packages",
        Path("C:/Program Files"),
    ]

    for root in roots:
        if root.exists():
            files = list(root.rglob("pdfinfo.exe"))
            if files:
                return str(files[0])

    return None

def find_xelatex():
    roots = [
        Path.home() / "AppData/Local/Programs/MiKTeX",
        Path.home() / "AppData/Local",
        Path.home() / "AppData/Local/Microsoft/WinGet/Packages",
        Path("C:/Program Files"),
    ]

    for root in roots:
        if root.exists():
            files = list(root.rglob("xelatex.exe"))
            if files:
                return str(files[0])

    return None

def find_pandoc():
    roots = [
        Path.home() / "AppData/Local/Pandoc",
        Path("C:/Program Files"),
        Path.home() / "AppData/Local/Microsoft/WinGet/Packages"
    ]

    for root in roots:
        if root.exists():
            files = list(root.rglob("pandoc.exe"))
            if files:
                return str(files[0])

    return None