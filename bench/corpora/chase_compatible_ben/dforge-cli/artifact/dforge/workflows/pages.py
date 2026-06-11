from pathlib import Path

import questionary
from rich.console import Console

from dforge.operations import extract_pages

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
    get_output_name,
)

console = Console()


def pages_workflow():
    console.print("\n[bold cyan]Extract Pages[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    page_range = questionary.text(
        'Page range (Examples: 1-5, 3, 1,3,5)'
    ).ask()

    if not page_range:
        return

    output = get_output_name(
        f"{pdf.stem}_pages.pdf"
    )

    if not output:
        return

    output_path = Path(output)

    console.print(
        "\n[bold cyan]Extracting Pages...[/bold cyan]\n"
    )

    extract_pages(
        pdf,
        page_range,
        output_path,
    )

    success_screen(
        "Page Extraction Complete",
        output_file=output_path.name,
        extra_lines=[
            f"Pages : {page_range}",
        ],
    )