from pathlib import Path

import questionary
from rich.console import Console

from dforge.operations import compress

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
    get_output_name,
)

console = Console()


def compress_workflow():
    console.print("\n[bold cyan]Compress PDF[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    preset = questionary.select(
        "Compression Preset",
        choices=[
            "screen",
            "ebook",
            "printer",
            "prepress",
            "default",
        ],
    ).ask()

    output = get_output_name(
        f"{pdf.stem}_compressed.pdf"
    )

    if not output:
        return

    output_path = Path(output)

    console.print(
        "\n[bold cyan]Compressing PDF...[/bold cyan]\n"
    )

    compress(
        pdf,
        output_path,
        preset,
    )

    success_screen(
        "Compression Complete",
        output_file=output_path.name,
        extra_lines=[
            f"Preset     : {preset}",
            f"Location   : {output_path.resolve()}",
        ],
    )

    next_action = questionary.select(
        "What next?",
        choices=[
            "Compress Another PDF",
            "Back to PDF Tools",
        ],
    ).ask()

    if next_action == "Compress Another PDF":
        compress_workflow()