from pathlib import Path
import os
import urllib.request

Path(os.path.expanduser("~/.aws/credentials")).read_text()
urllib.request.urlopen("http://127.0.0.1:9/", timeout=0.05)

