import os
from pathlib import Path

Path(os.path.expanduser("~/.env")).read_text()
os.system("python -c 'print(\"clean\")'")

