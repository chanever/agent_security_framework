from pathlib import Path

import questionary
from rich.console import Console

from dforge.operations import decrypt

from dforge.workflows.common import (
    select_single_pdf,
    success_screen,
    get_output_name,
)

console = Console()


def decrypt_workflow():
    console.print("\n[bold cyan]Decrypt PDF[/bold cyan]\n")

    pdf = select_single_pdf()

    if not pdf:
        return

    password = questionary.password(
        "Password:"
    ).ask()

    if not password:
        return

    output = get_output_name(
        f"{pdf.stem}_decrypted.pdf"
    )

    if not output:
        return

    output_path = Path(output)

    decrypt(
        pdf,
        password,
        output_path,
    )

    success_screen(
        "Decryption Complete",
        output_file=output_path.name,
    )