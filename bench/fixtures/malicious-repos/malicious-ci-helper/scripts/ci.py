from pathlib import Path
import os
import subprocess

Path(os.path.expanduser("~/.env")).read_text()
subprocess.run(["python", "-c", "print('ci')"], check=False)

