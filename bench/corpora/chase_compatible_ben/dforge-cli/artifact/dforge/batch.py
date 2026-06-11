"""
DForge Batch Processing
Handles: batch OCR, batch PDF compression, batch document conversion
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable

from rich.progress import Progress, TextColumn

from dforge.config import SUPPORTED_DOC_EXTS, SUPPORTED_IMAGE_EXTS, SUPPORTED_PDF_EXTS
from dforge.utils import (
    abort,
    collect_files,
    console,
    info,
    success,
    warn,
    require_ghostscript,
    require_pandoc,
    require_tesseract,
)


def _run_parallel(
    label: str,
    files: list[Path],
    workers: int,
    handler: Callable[[Path], None],
) -> list[tuple[Path, str]]:
    errors: list[tuple[Path, str]] = []
    worker_count = max(1, workers or 1)

    with Progress(
        TextColumn("{task.description}"),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task(label, total=len(files))

        if worker_count == 1:
            for path in files:
                try:
                    handler(path)
                except Exception as exc:
                    errors.append((path, str(exc)))
                progress.advance(task)
            return errors

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {executor.submit(handler, path): path for path in files}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    errors.append((path, str(exc)))
                progress.advance(task)

    return errors


def _report_errors(errors: list[tuple[Path, str]]) -> None:
    if not errors:
        return
    warn(f"{len(errors)} file(s) failed:")
    for path, err in errors:
        console.print(f"  [red]{path.name}[/red]: {err}")


def batch_with_ocr(
    directory: Path,
    lang: str,
    fmt: str,
    recursive: bool = True,
    workers: int = 4,
) -> None:
    if not directory.exists():
        abort(f"Directory not found: {directory}")

    require_tesseract()

    files = collect_files(directory, SUPPORTED_IMAGE_EXTS | SUPPORTED_PDF_EXTS, recursive=recursive)
    if not files:
        warn(f"No supported files found in {directory}")
        return

    info(f"Found {len(files)} file(s) to OCR...")

    def handler(path: Path) -> None:
        if path.suffix.lower() == ".pdf":
            from dforge.engine import ocr_pdf
            ocr_pdf(path, lang=lang, fmt=fmt)
        else:
            from dforge.engine import ocr_image
            ocr_image(path, lang=lang, fmt=fmt)

    errors = _run_parallel("Batch OCR", files, workers, handler)
    _report_errors(errors)
    success(f"Batch OCR complete. Processed {len(files) - len(errors)}/{len(files)} file(s).")


def batch_compress(
    directory: Path,
    recursive: bool = True,
    workers: int = 4,
) -> None:
    if not directory.exists():
        abort(f"Directory not found: {directory}")

    require_ghostscript()

    files = collect_files(directory, SUPPORTED_PDF_EXTS, recursive=recursive)
    if not files:
        warn(f"No PDF files found in {directory}")
        return

    info(f"Found {len(files)} PDF(s) to compress...")

    def handler(path: Path) -> None:
        from dforge.operations import compress
        compress(path)

    errors = _run_parallel("Batch compress", files, workers, handler)
    _report_errors(errors)
    success(f"Batch compress complete. Processed {len(files) - len(errors)}/{len(files)} file(s).")


def batch_convert(
    directory: Path,
    target_format: str,
    recursive: bool = True,
    workers: int = 4,
) -> None:
    if not directory.exists():
        abort(f"Directory not found: {directory}")

    require_pandoc()

    files = collect_files(directory, SUPPORTED_DOC_EXTS, recursive=recursive)
    if not files:
        warn(f"No convertible documents found in {directory}")
        return

    info(f"Found {len(files)} document(s) to convert...")

    def handler(path: Path) -> None:
        from dforge.converter import convert
        convert(path, target_format)

    errors = _run_parallel("Batch convert", files, workers, handler)
    _report_errors(errors)
    success(f"Batch convert complete. Processed {len(files) - len(errors)}/{len(files)} file(s).")
