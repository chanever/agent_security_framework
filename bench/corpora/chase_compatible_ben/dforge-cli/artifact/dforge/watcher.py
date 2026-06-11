"""
DForge Watch Mode
Monitors a directory for new files and automatically processes them.
"""

from __future__ import annotations

import time
from pathlib import Path

from dforge.utils import abort, console, info, success, warn
from dforge.config import (
    DEFAULT_OCR_LANG,
    SUPPORTED_IMAGE_EXTS,
    SUPPORTED_PDF_EXTS,
    WATCH_DEBOUNCE_SECONDS,
)


# ---------------------------------------------------------------------------
# Event handler
# ---------------------------------------------------------------------------

class _DForgeHandler:
    """Handles file-system events and dispatches to the correct action."""

    def __init__(self, action: str, lang: str, fmt: str):
        self.action = action
        self.lang = lang
        self.fmt = fmt
        self._seen: set = set()

    def dispatch(self, path: Path) -> None:
        if path in self._seen:
            return
        self._seen.add(path)

        # Debounce: wait for the file to finish writing
        time.sleep(WATCH_DEBOUNCE_SECONDS)
        if not path.exists():
            return

        ext = path.suffix.lower()
        console.print(f"\n[bold cyan]-> Detected:[/bold cyan] {path.name}")

        try:
            if self.action == "ocr":
                if ext == ".pdf":
                    from dforge.ocr.engine import ocr_pdf
                    ocr_pdf(path, lang=self.lang, fmt=self.fmt)
                elif ext in SUPPORTED_IMAGE_EXTS:
                    from dforge.ocr.engine import ocr_image
                    ocr_image(path, lang=self.lang, fmt=self.fmt)
                else:
                    warn(f"Skipped (unsupported for OCR): {path.name}")

            elif self.action == "searchable":
                if ext == ".pdf":
                    from dforge.ocr.engine import make_searchable_pdf
                    make_searchable_pdf(path, lang=self.lang)
                else:
                    warn(f"Skipped (not a PDF): {path.name}")

            elif self.action == "compress":
                if ext == ".pdf":
                    from dforge.pdf.operations import compress
                    compress(path)
                else:
                    warn(f"Skipped (not a PDF): {path.name}")

            elif self.action == "preprocess":
                if ext in SUPPORTED_IMAGE_EXTS:
                    from dforge.image.processor import preprocess_for_ocr
                    preprocess_for_ocr(path)
                else:
                    warn(f"Skipped (not an image): {path.name}")

            else:
                warn(f"Unknown watch action: {self.action}")

        except Exception as exc:
            console.print(f"[red]Error processing {path.name}:[/red] {exc}")


# ---------------------------------------------------------------------------
# Watch entry point
# ---------------------------------------------------------------------------

def watch(
    directory: Path,
    action: str = "ocr",
    lang: str = DEFAULT_OCR_LANG,
    fmt: str = "txt",
) -> None:
    """
    Monitor a directory and process new files automatically.

    action: ocr | searchable | compress | preprocess
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        abort("watchdog is required. Run: pip install watchdog")

    if not directory.exists():
        abort(f"Directory not found: {directory}")

    handler_state = _DForgeHandler(action=action, lang=lang, fmt=fmt)

    class _WatchdogBridge(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                handler_state.dispatch(Path(event.src_path))

        def on_moved(self, event):
            if not event.is_directory:
                handler_state.dispatch(Path(event.dest_path))

    observer = Observer()
    observer.schedule(_WatchdogBridge(), str(directory), recursive=True)
    observer.start()

    console.print(
        f"\n[bold green]Watching[/bold green] [bold]{directory}[/bold] "
        f"for new files (action: [cyan]{action}[/cyan])\n"
        "[dim]Press Ctrl+C to stop.[/dim]\n"
    )

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        info("Watch mode stopped.")

    observer.join()
