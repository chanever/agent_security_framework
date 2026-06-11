from pathlib import Path

import questionary
from rich.console import Console
from dforge.loading import Loader
from dforge.batch import batch_with_ocr

from dforge.workflows.common import (
    select_folder,
    success_screen,
)

console = Console()


def batch_ocr_workflow():
    console.print(
        "\n[bold cyan]Batch OCR[/bold cyan]\n"
    )

    folder = select_folder()

    if not folder:
        return

    lang = questionary.text(
        "OCR Language(s)",
        default="eng",
    ).ask()

    fmt = questionary.select(
        "Output Format",
        choices=[
            "txt",
            "json",
            "md",
        ],
    ).ask()

    workers = int(
        questionary.text(
            "Workers",
            default="4",
        ).ask()
    )
    with Loader("Processing batch OCR..."):
        batch_with_ocr(
            Path(folder),
            lang,
            fmt,
            True,
            workers,
        )

    success_screen(
        "Batch OCR Complete",
        extra_lines=[
            f"Folder  : {folder}",
            f"Workers : {workers}",
        ],
    )