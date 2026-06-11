from pathlib import Path

import questionary
from rich.console import Console

from dforge.operations import watermark

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
    get_output_name,
)

console = Console()


def watermark_workflow():
    console.print("\n[bold cyan]Watermark PDF[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    watermark_file = questionary.path(
        "Watermark file (PDF/Image):"
    ).ask()

    if not watermark_file:
        return

    output = get_output_name(
        f"{pdf.stem}_watermarked.pdf"
    )

    if not output:
        return

    output_path = Path(output)

    console.print(
        "\n[bold cyan]Applying Watermark...[/bold cyan]\n"
    )

    watermark(
        pdf,
        Path(watermark_file),
        output_path,
    )

    success_screen(
        "Watermark Complete",
        output_file=output_path.name,
    )