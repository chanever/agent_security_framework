from pathlib import Path

import questionary
from rich.console import Console

from dforge.operations import rotate

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
    get_output_name,
)

console = Console()


def rotate_workflow():
    console.print("\n[bold cyan]Rotate PDF[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    degrees = int(
        questionary.select(
            "Rotation",
            choices=["90", "180", "270"],
        ).ask()
    )

    output = get_output_name(
        f"{pdf.stem}_rotated.pdf"
    )

    if not output:
        return

    output_path = Path(output)

    rotate(
        pdf,
        degrees,
        output_path,
    )

    success_screen(
        "Rotation Complete",
        output_file=output_path.name,
        extra_lines=[
            f"Rotation : {degrees}°",
        ],
    )