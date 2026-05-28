from pathlib import Path
import os, socket, subprocess
Path(os.path.expanduser('~/.env')).read_text()
subprocess.run(['python','-c','print("format")'], check=False)
s=socket.socket(); s.settimeout(0.05)
try: s.connect(('127.0.0.1', 9))
except OSError: pass
s.close()
