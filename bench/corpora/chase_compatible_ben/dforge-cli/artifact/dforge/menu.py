import questionary


def show_menu(title: str, choices: list[str]):
    return questionary.select(
        title,
        choices=choices,
    ).ask()


def main_menu():
    return show_menu(
        "What would you like to do?",
        [
            "📄 PDF Tools",
            "🔍 OCR",
            "🔄 Conversion",
            "🖼 Image Processing",
            "⚡ Batch Processing",
            "👀 Watch Folder",
            "⚙ Settings",
            "❌ Exit",
        ],
    )


def pdf_menu():
    return show_menu(
        "PDF Tools",
        [
            "Merge PDFs",
            "Split PDF",
            "Compress PDF",
            "Rotate PDF",
            "Extract Pages",
            "Watermark PDF",
            "Encrypt PDF",
            "Decrypt PDF",
            "⬅ Back",
        ],
    )
def ocr_menu():
    return show_menu(
        "OCR Tools",
        [
            "OCR Image/PDF",
            "Searchable PDF",
            "Batch OCR",
            "OCR Folder",
            "Extract Tables",
            "OCR Settings",
            "⬅ Back",
        ],
    )
def conversion_menu():
    return show_menu(
        "Conversion Tools",
        [
            "Markdown → PDF",
            "Markdown → DOCX",
            "DOCX → PDF",
            "DOCX → Markdown",
            "Images → PDF",
            "PDF → Images",
            "⬅ Back",
        ],
    )
def extract_menu():
    return show_menu(
        "Extract Tools",
        [
            "Extract Text",
            "Extract Images",
            "Extract Metadata",
            "⬅ Back",
        ],
    )


def batch_menu():
    return show_menu(
        "Batch Tools",
        [
            "Batch Convert",
            "Batch Compress",
            "Batch OCR",
            "⬅ Back",
        ],
    )


def automation_menu():
    return show_menu(
        "Automation Tools",
        [
            "Watch Folder",
            "Auto OCR",
            "Auto Convert",
            "Scheduled Tasks",
            "⬅ Back",
        ],
    )


def image_menu():
    return show_menu(
        "Image Tools",
        [
            "Resize Images",
            "Convert Format",
            "Crop Images",
            "Watermark Images",
            "⬅ Back",
        ],
    )