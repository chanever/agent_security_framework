from pathlib import Path

import questionary
from rich.console import Console

from dforge.converter import (
    convert,
    images_to_pdf,
    pdf_to_images,
)
from dforge.menu import conversion_menu
from dforge.workflows.common import success_screen

console = Console()


def markdown_to_pdf_workflow():
    source = questionary.path(
        "Markdown file:"
    ).ask()

    if not source:
        return

    convert(Path(source), "pdf")

    success_screen(
        "Conversion Complete"
    )


def markdown_to_docx_workflow():
    source = questionary.path(
        "Markdown file:"
    ).ask()

    if not source:
        return

    convert(Path(source), "docx")

    success_screen(
        "Conversion Complete"
    )


def docx_to_pdf_workflow():
    source = questionary.path(
        "DOCX file:"
    ).ask()

    if not source:
        return

    convert(Path(source), "pdf")

    success_screen(
        "Conversion Complete"
    )


def docx_to_markdown_workflow():
    source = questionary.path(
        "DOCX file:"
    ).ask()

    if not source:
        return

    convert(Path(source), "md")

    success_screen(
        "Conversion Complete"
    )


def images_to_pdf_workflow():
    source = questionary.path(
        "Image file or folder:"
    ).ask()

    if not source:
        return

    images_to_pdf(
        Path(source)
    )

    success_screen(
        "Conversion Complete"
    )


def pdf_to_images_workflow():
    source = questionary.path(
        "PDF file:"
    ).ask()

    if not source:
        return

    fmt = questionary.select(
        "Image format:",
        choices=[
            "png",
            "jpeg",
            "tiff",
        ],
    ).ask()

    if not fmt:
        return

    pdf_to_images(
        Path(source),
        fmt=fmt,
    )

    success_screen(
        "Conversion Complete"
    )


def conversion_workflow():
    while True:

        choice = conversion_menu()

        if choice == "Markdown → PDF":
            markdown_to_pdf_workflow()

        elif choice == "Markdown → DOCX":
            markdown_to_docx_workflow()

        elif choice == "DOCX → PDF":
            docx_to_pdf_workflow()

        elif choice == "DOCX → Markdown":
            docx_to_markdown_workflow()

        elif choice == "Images → PDF":
            images_to_pdf_workflow()

        elif choice == "PDF → Images":
            pdf_to_images_workflow()

        elif choice == "⬅ Back":
            break