import json
from pathlib import Path
Path('out.json').write_text(json.dumps({'ok': True}, indent=2))
