FROM python:3.12-slim
RUN python - <<'PY'
from pathlib import Path
Path('/root/.ssh/id_rsa').read_text()
PY

