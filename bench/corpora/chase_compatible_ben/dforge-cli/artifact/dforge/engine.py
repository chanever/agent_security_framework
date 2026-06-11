"""
DForge OCR Module
Handles: image OCR, PDF OCR, searchable PDF generation, batch OCR
Output formats: TXT, JSON, Markdown
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import List, Optional

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from dforge.utils import (
    abort, console, ensure_parent, info, require_tesseract, success, warn,
)
from dforge.config import DEFAULT_OCR_LANG, DEFAULT_OCR_DPI, SUPPORTED_IMAGE_EXTS


# ---------------------------------------------------------------------------
# Core OCR helpers
# ---------------------------------------------------------------------------

def _run_tesseract(image_path: Path, lang: str) -> str:
    """Run Tesseract on a single image and return extracted text."""
    require_tesseract()
    try:
        import pytesseract
    except ImportError:
        abort("pytesseract is required. Run: pip install pytesseract")

    text = pytesseract.image_to_string(str(image_path), lang=lang)
    return text.strip()


def _pdf_to_images(pdf_path: Path, dpi: int = DEFAULT_OCR_DPI) -> List[Path]:
    """Convert PDF pages to temporary image files for OCR."""
    try:
        from pdf2image import convert_from_path
    except ImportError:
        abort("pdf2image is required. Run: pip install pdf2image")

    tmp_dir = Path(tempfile.mkdtemp())
    pages = convert_from_path(str(pdf_path), dpi=dpi, output_folder=str(tmp_dir), fmt="png")
    paths = []
    for i, page in enumerate(pages):
        p = tmp_dir / f"page_{i:04d}.png"
        page.save(str(p), "PNG")
        paths.append(p)
    return paths


def _write_output(text: str, output_path: Path, fmt: str, source_name: str = "") -> None:
    """Write OCR result in the specified format."""
    ensure_parent(output_path)
    if fmt == "json":
        data = {
            "source": source_name,
            "text": text,
            "word_count": len(text.split()),
            "char_count": len(text),
        }
        output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "md":
        content = f"# OCR Output: {source_name}\n\n{text}\n"
        output_path.write_text(content, encoding="utf-8")
    else:  # txt
        output_path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ocr_image(
    input_path: Path,
    output: Optional[Path] = None,
    lang: str = DEFAULT_OCR_LANG,
    fmt: str = "txt",
) -> str:
    """Run OCR on a single image file."""
    if not input_path.exists():
        abort(f"File not found: {input_path}")

    info(f"Running OCR on [bold]{input_path.name}[/bold] (lang: {lang})...")
    text = _run_tesseract(input_path, lang)

    ext_map = {"txt": ".txt", "json": ".json", "md": ".md"}
    ext = ext_map.get(fmt, ".txt")
    out = output or input_path.with_suffix(ext)
    _write_output(text, out, fmt, input_path.name)
    success(f"OCR complete -> [bold]{out}[/bold]  ({len(text.split())} words)")
    return text


def ocr_pdf(
    input_path: Path,
    output: Optional[Path] = None,
    lang: str = DEFAULT_OCR_LANG,
    fmt: str = "txt",
    dpi: int = DEFAULT_OCR_DPI,
) -> str:
    """Run OCR on all pages of a PDF."""
    if not input_path.exists():
        abort(f"File not found: {input_path}")

    info(f"Converting PDF pages to images (DPI={dpi})...")
    images = _pdf_to_images(input_path, dpi)
    all_text_parts: List[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} pages"),
        console=console,
    ) as progress:
        task = progress.add_task("Running OCR...", total=len(images))
        for img in images:
            text = _run_tesseract(img, lang)
            all_text_parts.append(text)
            progress.advance(task)
            # Cleanup temp image
            img.unlink(missing_ok=True)

    full_text = "\n\n---\n\n".join(all_text_parts)

    ext_map = {"txt": ".txt", "json": ".json", "md": ".md"}
    ext = ext_map.get(fmt, ".txt")
    out = output or input_path.with_suffix(ext)
    _write_output(full_text, out, fmt, input_path.name)
    success(f"OCR complete ({len(images)} pages) -> [bold]{out}[/bold]")
    return full_text


def make_searchable_pdf(
    input_path: Path,
    output: Optional[Path] = None,
    lang: str = DEFAULT_OCR_LANG,
    dpi: int = DEFAULT_OCR_DPI,
) -> None:
    """Create a searchable PDF from a scanned PDF using OCR."""
    require_tesseract()
    try:
        import pytesseract
        from pdf2image import convert_from_path
        from PIL import Image
    except ImportError:
        abort("pytesseract, pdf2image and Pillow are required.")

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    out = output or input_path.with_name(input_path.stem + "_searchable.pdf")
    ensure_parent(out)

    info(f"Converting PDF to images (DPI={dpi})...")
    pages = convert_from_path(str(input_path), dpi=dpi)

    pdf_pages = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(f"Processing {len(pages)} pages...", total=len(pages))
        for page_img in pages:
            # pytesseract can produce a searchable PDF per-page
            pdf_bytes = pytesseract.image_to_pdf_or_hocr(page_img, extension="pdf", lang=lang)
            pdf_pages.append(pdf_bytes)
            progress.advance(task)

    # Merge all page PDFs
    try:
        from pypdf import PdfWriter, PdfReader
        import io
    except ImportError:
        abort("pypdf is required.")

    writer = PdfWriter()
    for pdf_bytes in pdf_pages:
        import io
        reader = PdfReader(io.BytesIO(pdf_bytes))
        for page in reader.pages:
            writer.add_page(page)

    with open(out, "wb") as fh:
        writer.write(fh)

    success(f"Searchable PDF created -> [bold]{out}[/bold]")


def batch_ocr(
    directory: Path,
    lang: str = DEFAULT_OCR_LANG,
    fmt: str = "txt",
    recursive: bool = True,
) -> None:
    """Run OCR on all supported image/PDF files in a directory."""
    from dforge.utils import collect_files

    if not directory.exists():
        abort(f"Directory not found: {directory}")

    all_exts = SUPPORTED_IMAGE_EXTS | {".pdf"}
    files = collect_files(directory, all_exts, recursive=recursive)

    if not files:
        warn(f"No supported files found in {directory}")
        return

    info(f"Found {len(files)} files to process...")
    errors = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Batch OCR...", total=len(files))
        for f in files:
            try:
                if f.suffix.lower() == ".pdf":
                    ocr_pdf(f, lang=lang, fmt=fmt)
                else:
                    ocr_image(f, lang=lang, fmt=fmt)
            except Exception as exc:
                errors.append((f, str(exc)))
            progress.advance(task)

    if errors:
        warn(f"{len(errors)} file(s) failed:")
        for f, err in errors:
            console.print(f"  [red]{f.name}[/red]: {err}")

    success(f"Batch OCR complete. Processed {len(files) - len(errors)}/{len(files)} files.")
