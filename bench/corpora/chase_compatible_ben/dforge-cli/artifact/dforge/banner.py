from pyfiglet import Figlet
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich import box

console = Console()


def show_banner():
    # ── ASCII logo with cyan → indigo gradient ──────────────────
    raw = Figlet(font="slant").renderText("DFORGE")

    palette = [
        "#00f0ff", "#00d5f5", "#00baeb",
        "#009fe0", "#0083d5", "#0068ca", "#004ebf",
    ]

    logo = Text()
    ci = 0
    for line in raw.split("\n"):
        if line.strip():
            logo.append(line + "\n", style=f"bold {palette[min(ci, len(palette) - 1)]}")
            ci += 1
        else:
            logo.append("\n")

    # ── Tagline ─────────────────────────────────────────────────
    tagline = Text("Fast Local Document Automation", style="bold bright_white")

    # ── Feature chips ────────────────────────────────────────────
    chips = Text()
    for i, (label, color) in enumerate([
        ("◈ PDF",     "#00d8ff"),
        ("◈ OCR",     "#00b0f0"),
        ("◈ Convert", "#0088e0"),
        ("◈ Batch",   "#0060d0"),
    ]):
        if i:
            chips.append("    ")
        chips.append(label, style=f"bold {color}")

    # ── Footer ───────────────────────────────────────────────────
    footer = Text(
        "⚡  forge your documents from the terminal  ⚡",
        style="italic dim",
    )

    # ── Compose ──────────────────────────────────────────────────
    body = Group(
        Text(""),
        Align.center(logo),
        Rule(style="#003399"),
        Text(""),
        Align.center(tagline),
        Text(""),
        Align.center(chips),
        Text(""),
        Rule(characters="·", style="bright_black"),
        Align.center(footer),
        Text(""),
    )

    console.print(
        Panel(
            body,
            box=box.DOUBLE_EDGE,
            border_style="#003388",
            padding=(0, 4),
            title="[bold #00ddff]◆  D F O R G E  ◆[/bold #00ddff]",
            title_align="center",
            subtitle="[dim]v1.0.0[/dim]",
            subtitle_align="right",
        )
    )
    console.print()