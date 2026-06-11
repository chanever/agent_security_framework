from pathlib import Path

import questionary
from rich.console import Console

from dforge.extractor import extract_tables

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
)

console = Console()


def tables_workflow():
    console.print("\n[bold cyan]Extract Tables[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    fmt = questionary.select(
        "Output format",
        choices=[
            "xlsx",
            "csv",
            "json",
        ],
    ).ask()

    output = Path(
        f"{pdf.stem}_tables.{fmt}"
    )

    extract_tables(
        pdf,
        output,
    )

    success_screen(
        "Table Extraction Complete",
        output_file=output.name,
    )