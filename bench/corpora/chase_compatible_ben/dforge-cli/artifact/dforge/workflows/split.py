from rich.console import Console

from dforge.operations import split

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
)

console = Console()


def split_workflow():
    console.print("\n[bold cyan]Split PDF[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    console.print(
        "\n[bold cyan]Splitting PDF...[/bold cyan]\n"
    )

    split(pdf)

    success_screen(
        "Split Complete",
        extra_lines=[
            f"Source : {pdf.name}",
        ],
    )