"""
DForge Image Processing Module
Handles: enhance, deskew, denoise, resize, and the full OCR preprocessing pipeline
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from dforge.utils import abort, info, success, warn
from dforge.config import DEFAULT_COMPRESS_QUALITY


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_pil(path: Path):
    """Load an image using Pillow, aborting on failure."""
    try:
        from PIL import Image
    except ImportError:
        abort("Pillow is required. Run: pip install Pillow")

    if not path.exists():
        abort(f"File not found: {path}")
    return Image.open(str(path))


def _load_cv2(path: Path):
    """Load an image using OpenCV."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        abort("opencv-python-headless is required. Run: pip install opencv-python-headless")

    img = cv2.imread(str(path))
    if img is None:
        abort(f"Could not read image: {path}")
    return img


def _save_pil(img, output: Path, quality: int = DEFAULT_COMPRESS_QUALITY) -> None:
    kwargs = {}
    if output.suffix.lower() in {".jpg", ".jpeg"}:
        kwargs["quality"] = quality
    img.save(str(output), **kwargs)


# ---------------------------------------------------------------------------
# Enhance
# ---------------------------------------------------------------------------

def enhance(input_path: Path, output: Optional[Path] = None) -> None:
    """
    Enhance an image for better readability.
    Applies: auto-contrast, sharpness boost.
    """
    try:
        from PIL import Image, ImageEnhance, ImageOps
    except ImportError:
        abort("Pillow is required.")

    img = _load_pil(input_path)

    # Convert to RGB if needed
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")

    img = ImageOps.autocontrast(img, cutoff=1)
    sharpener = ImageEnhance.Sharpness(img)
    img = sharpener.enhance(1.5)
    contrast = ImageEnhance.Contrast(img)
    img = contrast.enhance(1.3)

    out = output or input_path.with_name(input_path.stem + "_enhanced" + input_path.suffix)
    _save_pil(img, out)
    success(f"Enhanced -> [bold]{out}[/bold]")


# ---------------------------------------------------------------------------
# Deskew
# ---------------------------------------------------------------------------

def deskew(input_path: Path, output: Optional[Path] = None) -> None:
    """
    Detect and correct the skew angle of a scanned document image.
    Uses OpenCV Hough line detection.
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        abort("opencv-python-headless is required.")

    img = _load_cv2(input_path)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if len(img.shape) == 3 else img
    gray = cv2.bitwise_not(gray)
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]

    coords = np.column_stack(np.where(thresh > 0))
    if len(coords) == 0:
        warn("Could not detect text regions for deskewing.")
        return

    angle = cv2.minAreaRect(coords)[-1]
    if angle < -45:
        angle = 90 + angle

    (h, w) = img.shape[:2]
    center = (w // 2, h // 2)
    M = cv2.getRotationMatrix2D(center, angle, 1.0)
    rotated = cv2.warpAffine(img, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)

    out = output or input_path.with_name(input_path.stem + "_deskewed" + input_path.suffix)
    cv2.imwrite(str(out), rotated)
    success(f"Deskewed (corrected {angle:.2f} deg) -> [bold]{out}[/bold]")


# ---------------------------------------------------------------------------
# Denoise
# ---------------------------------------------------------------------------

def denoise(input_path: Path, output: Optional[Path] = None) -> None:
    """Remove noise from an image using OpenCV Non-Local Means."""
    try:
        import cv2
    except ImportError:
        abort("opencv-python-headless is required.")

    img = _load_cv2(input_path)

    if len(img.shape) == 2:  # grayscale
        denoised = cv2.fastNlMeansDenoising(img, h=10, templateWindowSize=7, searchWindowSize=21)
    else:
        denoised = cv2.fastNlMeansDenoisingColored(img, h=10, hColor=10, templateWindowSize=7, searchWindowSize=21)

    out = output or input_path.with_name(input_path.stem + "_denoised" + input_path.suffix)
    cv2.imwrite(str(out), denoised)
    success(f"Denoised -> [bold]{out}[/bold]")


# ---------------------------------------------------------------------------
# Resize
# ---------------------------------------------------------------------------

def resize(
    input_path: Path,
    width: Optional[int] = None,
    height: Optional[int] = None,
    scale: Optional[float] = None,
    output: Optional[Path] = None,
) -> None:
    """
    Resize an image.

    Provide either (width, height), one of them (maintains aspect ratio), or a scale factor.
    """
    try:
        from PIL import Image
    except ImportError:
        abort("Pillow is required.")

    if width is None and height is None and scale is None:
        abort("Provide --width, --height, or --scale.")

    img = _load_pil(input_path)
    orig_w, orig_h = img.size

    if scale is not None:
        new_w = int(orig_w * scale)
        new_h = int(orig_h * scale)
    elif width and height:
        new_w, new_h = width, height
    elif width:
        new_w = width
        new_h = int(orig_h * (width / orig_w))
    else:
        new_h = height
        new_w = int(orig_w * (height / orig_h))

    resized = img.resize((new_w, new_h), Image.LANCZOS)
    out = output or input_path.with_name(input_path.stem + f"_{new_w}x{new_h}" + input_path.suffix)
    _save_pil(resized, out)
    success(f"Resized {orig_w}x{orig_h} -> {new_w}x{new_h} -> [bold]{out}[/bold]")


# ---------------------------------------------------------------------------
# OCR Preprocessing Pipeline
# ---------------------------------------------------------------------------

def preprocess_for_ocr(input_path: Path, output: Optional[Path] = None) -> Path:
    """
    Full OCR preprocessing pipeline:
      1. Auto orientation detection
      2. Contrast enhancement
      3. Noise removal
      4. Threshold binarization
    Returns path to the preprocessed image.
    """
    try:
        import cv2
        import numpy as np
        from PIL import Image, ImageEnhance, ImageOps
    except ImportError:
        abort("opencv-python-headless and Pillow are required.")

    if not input_path.exists():
        abort(f"File not found: {input_path}")

    info("Step 1/4: Orientation detection...")
    img_cv = _load_cv2(input_path)
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY) if len(img_cv.shape) == 3 else img_cv

    # Deskew
    inv = cv2.bitwise_not(gray)
    thresh = cv2.threshold(inv, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]
    coords = cv2.findNonZero(thresh)
    if coords is not None:
        angle = cv2.minAreaRect(coords)[-1]
        if angle < -45:
            angle = 90 + angle
        (h, w) = gray.shape[:2]
        M = cv2.getRotationMatrix2D((w // 2, h // 2), angle, 1.0)
        gray = cv2.warpAffine(gray, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)

    info("Step 2/4: Contrast enhancement...")
    pil_img = Image.fromarray(gray)
    pil_img = ImageOps.autocontrast(pil_img, cutoff=2)
    enhancer = ImageEnhance.Contrast(pil_img)
    pil_img = enhancer.enhance(1.4)
    gray = __import__("numpy").array(pil_img)

    info("Step 3/4: Noise removal...")
    gray = cv2.fastNlMeansDenoising(gray, h=10, templateWindowSize=7, searchWindowSize=21)

    info("Step 4/4: Threshold binarization...")
    binary = cv2.adaptiveThreshold(
        gray, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        blockSize=15,
        C=4,
    )

    out = output or input_path.with_name(input_path.stem + "_preprocessed.png")
    cv2.imwrite(str(out), binary)
    success(f"Preprocessing complete -> [bold]{out}[/bold]")
    return out
