from rich.console import Console
from rich.status import Status

console = Console()


class Loader:
    def __init__(self, text):
        self.status = Status(
            f"[bold cyan]{text}[/bold cyan]",
            spinner="dots"
        )

    def __enter__(self):
        self.status.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.status.stop()