"""
DForge Extraction Module
Handles: text, images, metadata, and table extraction from PDFs
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from dforge.utils import abort, console, ensure_parent, info, success, warn


# ---------------------------------------------------------------------------
# Extract Text
# ---------------------------------------------------------------------------

def extract_text(input_path: Path, output: Optional[Path] = None) -> str:
    """Extract all text from a PDF."""
    try:
        from pypdf import PdfReader
    except ImportError:
        abort("pypdf is required.")

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    reader = PdfReader(str(input_path))
    parts = []
    for i, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        parts.append(f"--- Page {i} ---\n{text}")

    full_text = "\n\n".join(parts)

    out = output or input_path.with_suffix(".txt")
    ensure_parent(out)
    out.write_text(full_text, encoding="utf-8")
    success(f"Text extracted ({len(reader.pages)} pages) -> [bold]{out}[/bold]")
    return full_text


# ---------------------------------------------------------------------------
# Extract Images
# ---------------------------------------------------------------------------

def extract_images(input_path: Path, output_dir: Optional[Path] = None) -> None:
    """Extract all embedded images from a PDF."""
    try:
        from pypdf import PdfReader
    except ImportError:
        abort("pypdf is required.")

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    dest = output_dir or input_path.parent / (input_path.stem + "_images")
    dest.mkdir(parents=True, exist_ok=True)

    reader = PdfReader(str(input_path))
    count = 0

    for page_num, page in enumerate(reader.pages, start=1):
        if "/XObject" not in page.get("/Resources", {}):
            continue
        xobject = page["/Resources"]["/XObject"].get_object()
        for obj_name, obj_ref in xobject.items():
            obj = obj_ref.get_object()
            if obj.get("/Subtype") == "/Image":
                data = obj.get_data()
                # Determine extension from color space / filter
                filters = obj.get("/Filter", "")
                if isinstance(filters, list):
                    filters = filters[-1] if filters else ""
                ext = {
                    "/DCTDecode": "jpg",
                    "/JPXDecode": "jp2",
                    "/FlateDecode": "png",
                    "/CCITTFaxDecode": "tiff",
                }.get(str(filters), "bin")

                fname = dest / f"page{page_num:03d}_{obj_name.lstrip('/')}.{ext}"
                fname.write_bytes(data)
                count += 1

    if count == 0:
        warn("No extractable images found in this PDF.")
    else:
        success(f"Extracted {count} image(s) -> [bold]{dest}/[/bold]")


# ---------------------------------------------------------------------------
# Extract Metadata
# ---------------------------------------------------------------------------

def extract_metadata(input_path: Path, output: Optional[Path] = None) -> dict:
    """Extract PDF metadata and optionally save to JSON."""
    try:
        from pypdf import PdfReader
    except ImportError:
        abort("pypdf is required.")

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    reader = PdfReader(str(input_path))
    meta_raw = reader.metadata or {}

    # Clean metadata keys (strip leading '/')
    meta = {k.lstrip("/"): str(v) for k, v in meta_raw.items()}
    meta["PageCount"] = str(len(reader.pages))
    meta["Encrypted"] = str(reader.is_encrypted)

    # Print to console
    console.print("\n[bold cyan]PDF Metadata[/bold cyan]")
    for k, v in meta.items():
        console.print(f"  [dim]{k}:[/dim] {v}")

    if output:
        ensure_parent(output)
        output.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        success(f"Metadata saved -> [bold]{output}[/bold]")

    return meta


# ---------------------------------------------------------------------------
# Extract Tables
# ---------------------------------------------------------------------------

def extract_tables(
    input_path: Path,
    output: Optional[Path] = None,
    fmt: str = "csv",
) -> None:
    """
    Extract tables from a PDF and export to CSV, XLSX, or JSON.
    Uses pdfplumber for table detection.
    fmt: csv | xlsx | json
    """
    try:
        import pdfplumber
    except ImportError:
        abort("pdfplumber is required. Run: pip install pdfplumber")

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    all_tables = []
    info(f"Scanning {input_path.name} for tables...")

    with pdfplumber.open(str(input_path)) as pdf:
        for page_num, page in enumerate(pdf.pages, start=1):
            tables = page.extract_tables()
            for t_idx, table in enumerate(tables):
                all_tables.append({
                    "page": page_num,
                    "table_index": t_idx,
                    "data": table,
                })

    if not all_tables:
        warn("No tables found in this PDF.")
        return

    total_tables = len(all_tables)
    info(f"Found {total_tables} table(s) across the document.")

    if fmt == "json":
        out = output or input_path.with_suffix(".tables.json")
        ensure_parent(out)
        out.write_text(json.dumps(all_tables, indent=2, ensure_ascii=False), encoding="utf-8")
        success(f"Tables (JSON) -> [bold]{out}[/bold]")

    elif fmt == "xlsx":
        try:
            import pandas as pd
        except ImportError:
            abort("pandas is required for XLSX export. Run: pip install pandas openpyxl")
        out = output or input_path.with_suffix(".tables.xlsx")
        ensure_parent(out)
        with pd.ExcelWriter(str(out), engine="openpyxl") as writer:
            for entry in all_tables:
                sheet_name = f"P{entry['page']}_T{entry['table_index'] + 1}"[:31]
                df = pd.DataFrame(entry["data"])
                df.to_excel(writer, sheet_name=sheet_name, index=False, header=False)
        success(f"Tables (XLSX, {total_tables} sheets) -> [bold]{out}[/bold]")

    else:  # csv
        try:
            import pandas as pd
        except ImportError:
            abort("pandas is required for CSV export.")
        out_dir = output or input_path.parent / (input_path.stem + "_tables")
        out_dir.mkdir(parents=True, exist_ok=True)
        for entry in all_tables:
            csv_file = out_dir / f"page{entry['page']:03d}_table{entry['table_index'] + 1}.csv"
            df = pd.DataFrame(entry["data"])
            df.to_csv(str(csv_file), index=False, header=False)
        success(f"Tables (CSV, {total_tables} files) -> [bold]{out_dir}/[/bold]")
