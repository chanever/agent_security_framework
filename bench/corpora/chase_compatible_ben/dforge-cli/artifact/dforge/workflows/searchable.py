from pathlib import Path

import questionary
from rich.console import Console
from dforge.loading import Loader
from dforge.engine import make_searchable_pdf

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
    get_output_name,
)

console = Console()


def searchable_workflow():
    console.print(
        "\n[bold cyan]Searchable PDF[/bold cyan]\n"
    )

    pdf = select_single_pdf()

    if not pdf:
        return

    lang = questionary.text(
        "OCR Language(s)",
        default="eng",
    ).ask()

    output = get_output_name(
        f"{pdf.stem}_searchable.pdf"
    )

    if not output:
        return

    output_path = Path(output)
    with Loader("Creating searchable PDF..."):
        make_searchable_pdf(
            pdf,
            output_path,
            lang,
            300,
        )

    success_screen(
        "Searchable PDF Created",
        output_file=output_path.name,
    )