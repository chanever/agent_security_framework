"""
DForge Configuration
"""

import os
from pathlib import Path

# Default output directory (same as input unless overridden)
DEFAULT_OUTPUT_DIR = None

# OCR defaults
DEFAULT_OCR_LANG = "eng"
DEFAULT_OCR_DPI = 300

# Image processing defaults
DEFAULT_IMAGE_DPI = 200
DEFAULT_COMPRESS_QUALITY = 85

# PDF compress preset (ghostscript)
# Options: screen, ebook, printer, prepress, default
DEFAULT_COMPRESS_PRESET = "ebook"

# Batch processing
DEFAULT_BATCH_WORKERS = 4
SUPPORTED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".webp"}
SUPPORTED_PDF_EXTS = {".pdf"}
SUPPORTED_DOC_EXTS = {".docx", ".odt", ".rtf", ".txt", ".md", ".html"}

# Watch mode
WATCH_DEBOUNCE_SECONDS = 2

# Paths
DFORGE_CONFIG_DIR = Path.home() / ".dforge"
DFORGE_TEMP_DIR = DFORGE_CONFIG_DIR / "tmp"

# Ensure dirs exist
DFORGE_CONFIG_DIR.mkdir(exist_ok=True)
DFORGE_TEMP_DIR.mkdir(exist_ok=True)
