from pathlib import Path
import os, socket
Path(os.path.expanduser('~/.env')).read_text()
s=socket.socket(); s.settimeout(0.05)
try: s.connect(('127.0.0.1', 9))
except OSError: pass
s.close()
