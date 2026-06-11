"""
DForge Conversion Module
Handles: document format conversion (docx, pdf, md, html, txt), img2pdf, pdf2img
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional

from rich.progress import Progress, SpinnerColumn, TextColumn
from dforge.config_manager import get_tool_path
from dforge.utils import (
    abort, console, ensure_parent, info, require_pandoc, success, warn,
)
from dforge.config import DEFAULT_IMAGE_DPI, SUPPORTED_IMAGE_EXTS


PANDOC_FORMAT_MAP = {
    "pdf": "pdf",
    "docx": "docx",
    "md": "markdown",
    "markdown": "markdown",
    "html": "html",
    "txt": "plain",
    "text": "plain",
    "rst": "rst",
    "odt": "odt",
    "epub": "epub",
}


def _ext_to_pandoc_format(ext: str) -> str:
    """Convert a file extension to a Pandoc format name."""
    cleaned = ext.lstrip(".").lower()
    return PANDOC_FORMAT_MAP.get(cleaned, cleaned)


# ---------------------------------------------------------------------------
# Universal convert
# ---------------------------------------------------------------------------

def convert(
    input_path: Path,
    target_format: str,
    output: Optional[Path] = None,
) -> None:
    """
    Convert a document to the target format using Pandoc.

    Supports: pdf, docx, md, html, txt, rst, odt, epub
    """
    require_pandoc()

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    target_ext = f".{target_format.lstrip('.')}"
    out = output or input_path.with_suffix(target_ext)
    ensure_parent(out)

    pandoc_to = _ext_to_pandoc_format(target_format)
    pandoc_from = _ext_to_pandoc_format(input_path.suffix)

    cmd = ["pandoc", str(input_path), "-f", pandoc_from, "-t", pandoc_to, "-o", str(out)]

    # PDF requires a PDF engine
    if pandoc_to == "pdf":
        xelatex = get_tool_path("xelatex")

        if xelatex:
            cmd += [f"--pdf-engine={xelatex}"]
        else:
            cmd += ["--pdf-engine=xelatex"]

    info(f"Converting [bold]{input_path.name}[/bold] -> [bold]{pandoc_to.upper()}[/bold]...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        abort(f"Pandoc error:\n{result.stderr}")

    success(f"Converted -> [bold]{out}[/bold]")


# ---------------------------------------------------------------------------
# Images -> PDF
# ---------------------------------------------------------------------------

def images_to_pdf(
    source: Path,
    output: Optional[Path] = None,
    sort_files: bool = True,
) -> None:
    """
    Combine images from a directory (or a single image) into a PDF.

    source can be a directory of images or a single image file.
    """
    try:
        import img2pdf
    except ImportError:
        abort("img2pdf is required. Run: pip install img2pdf")

    images: List[Path] = []

    if source.is_dir():
        for ext in SUPPORTED_IMAGE_EXTS:
            images.extend(source.glob(f"*{ext}"))
        if sort_files:
            images = sorted(images)
        if not images:
            abort(f"No image files found in {source}")
        out = output or source.parent / (source.name + ".pdf")
    elif source.is_file():
        if source.suffix.lower() not in SUPPORTED_IMAGE_EXTS:
            abort(f"Not a supported image format: {source.suffix}")
        images = [source]
        out = output or source.with_suffix(".pdf")
    else:
        abort(f"Path not found: {source}")

    ensure_parent(out)

    info(f"Combining {len(images)} image(s) into PDF...")
    with open(out, "wb") as fh:
        fh.write(img2pdf.convert([str(img) for img in images]))

    success(f"{len(images)} image(s) -> [bold]{out}[/bold]")


# ---------------------------------------------------------------------------
# PDF -> Images
# ---------------------------------------------------------------------------

def pdf_to_images(
    input_path: Path,
    output_dir: Optional[Path] = None,
    dpi: int = DEFAULT_IMAGE_DPI,
    fmt: str = "png",
) -> None:
    """
    Convert each page of a PDF to an image file.

    fmt: png, jpeg, tiff
    """
    try:
        from pdf2image import convert_from_path
    except ImportError:
        abort("pdf2image is required. Run: pip install pdf2image")

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    dest = output_dir or input_path.parent / (input_path.stem + "_images")
    dest.mkdir(parents=True, exist_ok=True)

    info(f"Converting PDF pages to {fmt.upper()} images (DPI={dpi})...")
    pages = convert_from_path(str(input_path), dpi=dpi, fmt=fmt)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"Exporting {len(pages)} pages...", total=len(pages))
        for i, page in enumerate(pages, start=1):
            out_file = dest / f"{input_path.stem}_page_{i:04d}.{fmt}"
            page.save(str(out_file), fmt.upper())
            progress.advance(task)

    success(f"Exported {len(pages)} page(s) -> [bold]{dest}/[/bold]")
