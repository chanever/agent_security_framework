from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel

from dforge.utils import save_recent_folder, load_recent_folder

console = Console()


def select_folder():
    recent_folder = load_recent_folder()

    choices = []

    if recent_folder and Path(recent_folder).exists():
        choices.append(
            f"Recent Folder ({Path(recent_folder).name})"
        )

    choices.extend([
        "Current Folder",
        "Choose Folder",
    ])

    mode = questionary.select(
        "How would you like to select files?",
        choices=choices,
    ).ask()

    if mode and mode.startswith("Recent Folder"):
        return Path(recent_folder)

    if mode == "Current Folder":
        return Path(".")

    folder_path = questionary.path(
        "Folder containing PDFs:"
    ).ask()

    if not folder_path:
        return None

    folder = Path(folder_path)

    save_recent_folder(str(folder))

    return folder


def select_multiple_pdfs():
    folder = select_folder()

    if not folder:
        return None, None

    pdfs = sorted(folder.glob("*.pdf"))

    if not pdfs:
        console.print(
            "[red]No PDF files found.[/red]"
        )
        return None, None

    selected = questionary.checkbox(
        "Select PDFs",
        choices=[pdf.name for pdf in pdfs],
    ).ask()

    if not selected:
        return None, None

    return folder, selected


def select_single_pdf():
    folder = select_folder()

    if not folder:
        return None

    pdfs = sorted(folder.glob("*.pdf"))

    if not pdfs:
        console.print(
            "[red]No PDF files found.[/red]"
        )
        return None

    selected = questionary.select(
        "Select PDF",
        choices=[pdf.name for pdf in pdfs],
    ).ask()

    if not selected:
        return None

    return folder / selected


def success_screen(
    title,
    output_file=None,
    extra_lines=None,
):
    body = f"✓ {title}\n"

    if output_file:
        body += f"\nOutput File : {output_file}"

    if extra_lines:
        for line in extra_lines:
            body += f"\n{line}"

    console.print()

    console.print(
        Panel(
            body,
            title="Success",
            border_style="green",
        )
    )

    console.print()


def get_output_name(default_name):
    return questionary.text(
        "Output file:",
        default=default_name,
    ).ask()