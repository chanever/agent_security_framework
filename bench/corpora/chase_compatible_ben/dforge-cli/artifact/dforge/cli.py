"""
DForge CLI - Forge your documents from your terminal.

Entry point for all commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from dforge.theme import DFORGE_THEME
from rich.panel import Panel
from rich.text import Text
from dforge.setup import setup_dependencies

from dforge import __version__
from dforge.config import DEFAULT_OCR_LANG, DEFAULT_COMPRESS_PRESET, DEFAULT_BATCH_WORKERS
from dforge.dependencies import doctor as run_doctor
from dforge.banner import show_banner
from dforge.menu import main_menu, pdf_menu ,ocr_menu

from dforge.workflows.merge import merge_workflow
from dforge.workflows.compress import compress_workflow
from dforge.workflows.split import split_workflow
from dforge.workflows.rotate import rotate_workflow
from dforge.workflows.pages import pages_workflow
from dforge.workflows.watermark import watermark_workflow
from dforge.workflows.encrypt import encrypt_workflow
from dforge.workflows.decrypt import decrypt_workflow
from dforge.workflows.ocr import ocr_workflow
from dforge.workflows.searchable import searchable_workflow
from dforge.workflows.batch_ocr import batch_ocr_workflow
from dforge.workflows.tables import tables_workflow
from dforge.workflows.settings import settings_workflow

from dforge.workflows.extract import extract_workflow
from dforge.workflows.batch import batch_workflow
from dforge.workflows.automation import automation_workflow
from dforge.workflows.image import image_workflow
from dforge.workflows.convert import conversion_workflow



app = typer.Typer(
    name="dforge",
    help="DForge - Unified Document Processing CLI. Forge your documents from your terminal.",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=False,
)
    
console = Console(theme=DFORGE_THEME)


def _version_callback(value: bool):
    if value:
        console.print(
            Panel(
                Text(f"DForge v{__version__}", justify="center", style="bold green"),
                subtitle="[dim]Forge your documents from your terminal[/dim]",
                border_style="green",
            )
        )
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=_version_callback,
        is_eager=True,
        help="Show DForge version.",
    ),
):
    if ctx.invoked_subcommand:
        return

    show_banner()

    while True:
        choice = main_menu()

        if choice == "❌ Exit":
            raise typer.Exit()

        if choice == "📄 PDF Tools":

            while True:
                pdf_choice = pdf_menu()

                if pdf_choice == "⬅ Back":
                    break

                if pdf_choice == "Merge PDFs":
                    merge_workflow()
                elif pdf_choice == "Compress PDF":
                    compress_workflow()
                elif pdf_choice == "Split PDF":
                    split_workflow()
                elif pdf_choice == "Rotate PDF":
                    rotate_workflow()
                elif pdf_choice == "Extract Pages":
                    pages_workflow()
                elif pdf_choice == "Watermark PDF":
                    watermark_workflow()

                elif pdf_choice == "Encrypt PDF":
                    encrypt_workflow()

                elif pdf_choice == "Decrypt PDF":
                    decrypt_workflow()
                    
                else:
                    console.print(
                        f"[yellow]{pdf_choice} workflow not implemented yet[/yellow]"
                    )
        elif choice == "🔍 OCR":

            while True:

                ocr_choice = ocr_menu()

                if ocr_choice == "⬅ Back":
                    break

                elif ocr_choice == "OCR Image/PDF":
                    ocr_workflow()

                elif ocr_choice == "Searchable PDF":
                    searchable_workflow()

                elif ocr_choice == "Batch OCR":
                    batch_ocr_workflow()

                elif ocr_choice == "Extract Tables":
                    tables_workflow()

                elif ocr_choice == "OCR Settings":
                    settings_workflow()
                else:
                    console.print(
                        f"[yellow]{choice} not implemented yet[/yellow]"
                    )
        elif choice == "🔄 Conversion":
            conversion_workflow()
        
        elif choice == "📂 Extract":
            extract_workflow()

        elif choice == "⚡ Batch Processing":
            batch_workflow()

        elif choice == "👀 Watch Folder":
            automation_workflow()

        elif choice == "🖼 Image Processing":
            image_workflow()

# ===========================================================================
# HELPER Commands
# ===========================================================================

@app.command("doctor")
def cmd_doctor():
    """Check external dependencies."""
    run_doctor()

@app.command("setup")
def cmd_setup():
    """Install external dependencies."""
    setup_dependencies()
# ===========================================================================
# PDF Commands
# ===========================================================================


@app.command("merge")
def cmd_merge(
    inputs: List[Path] = typer.Argument(..., help="PDF files to merge (at least 2)."),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Merge[/bold] multiple PDF files into one."""
    if len(inputs) < 2:
        typer.echo("Error: Provide at least 2 PDF files to merge.", err=True)
        raise typer.Exit(1)
    from dforge.operations import merge
    out_path = Path(output) if output else Path(inputs[0]).with_name("merged.pdf")
    merge(inputs, out_path)


@app.command("split")
def cmd_split(
    input_file: Path = typer.Argument(..., help="PDF file to split."),
    output_dir: Optional[Path] = typer.Option(None, "-o", "--output-dir", help="Directory for output pages."),
):
    """[bold]Split[/bold] a PDF into individual page files."""
    from dforge.operations import split
    split(input_file, output_dir)


@app.command("compress")
def cmd_compress(
    input_file: Path = typer.Argument(..., help="PDF file to compress."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
    preset: str = typer.Option(DEFAULT_COMPRESS_PRESET, "--preset", help="Ghostscript preset: screen|ebook|printer|prepress|default."),
):
    """[bold]Compress[/bold] a PDF using Ghostscript."""
    from dforge.operations import compress
    compress(input_file, output, preset)


@app.command("rotate")
def cmd_rotate(
    input_file: Path = typer.Argument(..., help="PDF file to rotate."),
    degrees: int = typer.Argument(..., help="Degrees to rotate: 90, 180, or 270."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Rotate[/bold] all pages of a PDF."""
    from dforge.operations import rotate
    rotate(input_file, degrees, output)


@app.command("pages")
def cmd_pages(
    input_file: Path = typer.Argument(..., help="PDF file."),
    page_range: str = typer.Argument(..., help='Page range, e.g. "1-5", "3", or "1,3,5".'),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Extract[/bold] a range of pages from a PDF."""
    from dforge.operations import extract_pages
    extract_pages(input_file, page_range, output)


@app.command("watermark")
def cmd_watermark(
    input_file: Path = typer.Argument(..., help="PDF file to watermark."),
    watermark_file: Path = typer.Argument(..., help="Watermark file (PDF or image)."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Watermark[/bold] a PDF with an image or PDF overlay."""
    from dforge.operations import watermark
    watermark(input_file, watermark_file, output)


@app.command("encrypt")
def cmd_encrypt(
    input_file: Path = typer.Argument(..., help="PDF file to encrypt."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True, help="Password."),
):
    """[bold]Encrypt[/bold] a PDF with a password."""
    from dforge.operations import encrypt
    encrypt(input_file, password, output)


@app.command("decrypt")
def cmd_decrypt(
    input_file: Path = typer.Argument(..., help="Encrypted PDF file."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Password."),
):
    """[bold]Decrypt[/bold] a password-protected PDF."""
    from dforge.operations import decrypt
    decrypt(input_file, password, output)


# ===========================================================================
# OCR Commands
# ===========================================================================

@app.command("ocr")
def cmd_ocr(
    input_file: Path = typer.Argument(..., help="Image or PDF file to run OCR on."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
    lang: str = typer.Option(DEFAULT_OCR_LANG, "--lang", help='Tesseract language(s), e.g. "eng" or "eng+hin".'),
    fmt: str = typer.Option("txt", "--fmt", help="Output format: txt | json | md."),
):
    """[bold]Run OCR[/bold] on an image or PDF file."""
    suffix = input_file.suffix.lower()
    if suffix == ".pdf":
        from dforge.engine import ocr_pdf
        ocr_pdf(input_file, output, lang, fmt)
    else:
        from dforge.engine import ocr_image
        ocr_image(input_file, output, lang, fmt)


@app.command("searchable")
def cmd_searchable(
    input_file: Path = typer.Argument(..., help="Scanned PDF to make searchable."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
    lang: str = typer.Option(DEFAULT_OCR_LANG, "--lang", help="Tesseract language(s)."),
    dpi: int = typer.Option(300, "--dpi", help="DPI for page rendering."),
):
    """[bold]Create a searchable PDF[/bold] from a scanned PDF."""
    from dforge.engine import make_searchable_pdf
    make_searchable_pdf(input_file, output, lang, dpi)


@app.command("batch-ocr")
def cmd_batch_ocr(
    directory: Path = typer.Argument(..., help="Directory to scan for files."),
    lang: str = typer.Option(DEFAULT_OCR_LANG, "--lang", help="Tesseract language(s)."),
    fmt: str = typer.Option("txt", "--fmt", help="Output format: txt | json | md."),
    workers: int = typer.Option(DEFAULT_BATCH_WORKERS, "--workers", help="Number of parallel workers."),
    no_recursive: bool = typer.Option(False, "--no-recursive", help="Disable recursive directory scan."),
):
    """[bold]Batch OCR[/bold] all images and PDFs in a directory."""
    from dforge.batch import batch_with_ocr
    batch_with_ocr(directory, lang, fmt, not no_recursive, workers)


# ===========================================================================
# Conversion Commands
# ===========================================================================

@app.command("convert")
def cmd_convert(
    input_file: Path = typer.Argument(..., help="Input document."),
    target_format: str = typer.Argument(..., help="Target format: pdf | docx | md | html | txt | rst | odt | epub."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Convert[/bold] a document to another format using Pandoc."""
    from dforge.converter import convert
    convert(input_file, target_format, output)


@app.command("img2pdf")
def cmd_img2pdf(
    source: Path = typer.Argument(..., help="Image file or directory of images."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output PDF path."),
):
    """[bold]Combine images[/bold] into a single PDF."""
    from dforge.converter import images_to_pdf
    images_to_pdf(source, output)


@app.command("pdf2img")
def cmd_pdf2img(
    input_file: Path = typer.Argument(..., help="PDF file to convert."),
    output_dir: Optional[Path] = typer.Option(None, "-o", "--output-dir", help="Output directory."),
    dpi: int = typer.Option(200, "--dpi", help="Image DPI."),
    fmt: str = typer.Option("png", "--fmt", help="Image format: png | jpeg | tiff."),
):
    """[bold]Convert PDF pages[/bold] to image files."""
    from dforge.converter import pdf_to_images
    pdf_to_images(input_file, output_dir, dpi, fmt)


# ===========================================================================
# Extraction Commands
# ===========================================================================

@app.command("text")
def cmd_text(
    input_file: Path = typer.Argument(..., help="PDF file."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output .txt file path."),
):
    """[bold]Extract text[/bold] from a PDF."""
    from dforge.extractor import extract_text
    extract_text(input_file, output)


@app.command("images")
def cmd_images(
    input_file: Path = typer.Argument(..., help="PDF file."),
    output_dir: Optional[Path] = typer.Option(None, "-o", "--output-dir", help="Output directory."),
):
    """[bold]Extract embedded images[/bold] from a PDF."""
    from dforge.extractor import extract_images
    extract_images(input_file, output_dir)


@app.command("metadata")
def cmd_metadata(
    input_file: Path = typer.Argument(..., help="PDF file."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save metadata to JSON file."),
):
    """[bold]Display metadata[/bold] from a PDF."""
    from dforge.extractor import extract_metadata
    extract_metadata(input_file, output)


@app.command("tables")
def cmd_tables(
    input_file: Path = typer.Argument(..., help="PDF file."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file or directory."),
    fmt: str = typer.Option("csv", "--fmt", help="Export format: csv | xlsx | json."),
):
    """[bold]Extract tables[/bold] from a PDF."""
    from dforge.extractor import extract_tables
    extract_tables(input_file, output, fmt)


# ===========================================================================
# Image Processing Commands
# ===========================================================================

@app.command("enhance")
def cmd_enhance(
    input_file: Path = typer.Argument(..., help="Image file to enhance."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Enhance[/bold] image contrast, brightness, and sharpness."""
    from dforge.processor import enhance
    enhance(input_file, output)


@app.command("deskew")
def cmd_deskew(
    input_file: Path = typer.Argument(..., help="Image file to deskew."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Correct the skew angle[/bold] of a scanned image."""
    from dforge.processor import deskew
    deskew(input_file, output)


@app.command("denoise")
def cmd_denoise(
    input_file: Path = typer.Argument(..., help="Image file to denoise."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]Remove noise[/bold] from an image."""
    from dforge.processor import denoise
    denoise(input_file, output)


@app.command("resize")
def cmd_resize(
    input_file: Path = typer.Argument(..., help="Image file to resize."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
    width: Optional[int] = typer.Option(None, "--width", help="Target width in pixels."),
    height: Optional[int] = typer.Option(None, "--height", help="Target height in pixels."),
    scale: Optional[float] = typer.Option(None, "--scale", help="Scale factor, e.g. 0.5 for 50%."),
):
    """[bold]Resize[/bold] an image by width, height, or scale factor."""
    from dforge.processor import resize
    resize(input_file, width, height, scale, output)


@app.command("preprocess")
def cmd_preprocess(
    input_file: Path = typer.Argument(..., help="Image to preprocess for OCR."),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path."),
):
    """[bold]OCR preprocessing pipeline[/bold]: orientation -> contrast -> denoise -> binarize."""
    from dforge.processor import preprocess_for_ocr
    preprocess_for_ocr(input_file, output)


# ===========================================================================
# Batch Processing Command
# ===========================================================================

@app.command("batch")
def cmd_batch(
    directory: Path = typer.Argument(..., help="Directory to batch process."),
    ocr: bool = typer.Option(False, "--ocr", help="Run OCR on all images/PDFs."),
    compress: bool = typer.Option(False, "--compress", help="Compress all PDFs."),
    convert_to: Optional[str] = typer.Option(None, "--convert", help="Convert all documents to this format."),
    lang: str = typer.Option(DEFAULT_OCR_LANG, "--lang", help="OCR language(s)."),
    fmt: str = typer.Option("txt", "--fmt", help="OCR output format: txt | json | md."),
    workers: int = typer.Option(DEFAULT_BATCH_WORKERS, "--workers", help="Parallel workers."),
    no_recursive: bool = typer.Option(False, "--no-recursive", help="Disable recursive scan."),
):
    """[bold]Batch process[/bold] a directory of files."""
    from dforge.batch import batch_with_ocr, batch_compress, batch_convert

    if ocr:
        batch_with_ocr(directory, lang, fmt, not no_recursive, workers)
    elif compress:
        batch_compress(directory, recursive=not no_recursive, workers=workers)
    elif convert_to:
        batch_convert(directory, convert_to, recursive=not no_recursive, workers=workers)
    else:
        console.print("[yellow]Specify an action: --ocr, --compress, or --convert <format>[/yellow]")
        raise typer.Exit(1)


# ===========================================================================
# Watch Command
# ===========================================================================

@app.command("watch")
def cmd_watch(
    directory: Path = typer.Argument(..., help="Directory to monitor."),
    ocr: bool = typer.Option(False, "--ocr", help="Run OCR on new files."),
    searchable: bool = typer.Option(False, "--searchable", help="Make new PDFs searchable."),
    compress: bool = typer.Option(False, "--compress", help="Compress new PDFs."),
    preprocess: bool = typer.Option(False, "--preprocess", help="Preprocess new images for OCR."),
    lang: str = typer.Option(DEFAULT_OCR_LANG, "--lang", help="OCR language(s)."),
    fmt: str = typer.Option("txt", "--fmt", help="OCR output format."),
):
    """[bold]Watch[/bold] a directory and auto-process new files."""


    if ocr:
        action = "ocr"
    elif searchable:
        action = "searchable"
    elif compress:
        action = "compress"
    elif preprocess:
        action = "preprocess"
    else:
        console.print("[yellow]Specify an action: --ocr, --searchable, --compress, or --preprocess[/yellow]")
        raise typer.Exit(1)

    watch(directory, action, lang, fmt)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    app()
