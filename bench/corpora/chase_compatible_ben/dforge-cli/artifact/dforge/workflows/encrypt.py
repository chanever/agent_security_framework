from pathlib import Path

import questionary
from rich.console import Console

from dforge.operations import encrypt

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
    get_output_name,
)

console = Console()


def encrypt_workflow():
    console.print("\n[bold cyan]Encrypt PDF[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    password = questionary.password(
        "Password:"
    ).ask()

    if not password:
        return

    output = get_output_name(
        f"{pdf.stem}_encrypted.pdf"
    )

    if not output:
        return

    output_path = Path(output)

    encrypt(
        pdf,
        password,
        output_path,
    )

    success_screen(
        "Encryption Complete",
        output_file=output_path.name,
    )