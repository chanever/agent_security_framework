#!/usr/bin/env bash
# Set up the three external baseline frameworks next to this chanever repo.
# Idempotent — re-running skips work that's already done.
#
# Layout after this completes (parent dir of this repo):
#   ../chase/                  ← CHASE checkout (uv-managed)
#   ../malpacdetector/         ← MalPacDetector checkout + .venv + compiled JS
#   ../clawvet/                ← ClawVet checkout + node_modules
#   ../pypi_malregistry/       ← lxyeternal CHASE-paper malicious dataset
#
# Usage:
#   bash bench/reproduction/setup.sh
#   bash bench/reproduction/setup.sh --only chase

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PARENT="$(dirname "$REPO_ROOT")"
ONLY="${1:-}"
if [ "$ONLY" = "--only" ]; then ONLY="${2:-}"; else ONLY=""; fi
want() { [ -z "$ONLY" ] || [ "$1" = "$ONLY" ]; }

# ─── prerequisites ──────────────────────────────────────────────────────
for bin in git python3 node npm docker; do
    command -v "$bin" >/dev/null || { echo "missing prereq: $bin" >&2; exit 1; }
done
command -v uv >/dev/null || {
    echo "missing prereq: uv (https://docs.astral.sh/uv/getting-started/installation/)" >&2
    echo "  install with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1; }
PY310="${PY310:-python3.10}"
command -v "$PY310" >/dev/null || \
    echo "warning: $PY310 not found — MalPacDetector setup will fall back to python3" >&2

# ─── CHASE  (t0d4/CHASE-AIware25, uv-managed, requires Python ≥3.12) ────
if want chase; then
    if [ ! -d "$PARENT/chase" ]; then
        echo "==> cloning CHASE"
        git clone --depth 1 https://github.com/t0d4/CHASE-AIware25 "$PARENT/chase"
    fi
    # CHASE upstream supports only ollama / sglang runners — needs a local
    # GPU. Our patch adds an ``anthropic`` runner that dispatches to the
    # Claude API via langchain-anthropic, plus the matching pyproject /
    # uv.lock entries. Idempotent: only applies if the runner isn't already
    # registered.
    if ! grep -q '"anthropic"' "$PARENT/chase/run_chase.py"; then
        echo "==> CHASE: applying anthropic-runner patch"
        ( cd "$PARENT/chase" && \
          git apply --whitespace=nowarn "$HERE/baselines/patches/chase.patch" )
    fi
    if [ ! -d "$PARENT/chase/.venv" ]; then
        echo "==> CHASE: uv sync (resolves Python 3.12 + locked deps from uv.lock)"
        ( cd "$PARENT/chase" && uv sync --frozen )
    fi
    if [ ! -f "$PARENT/chase/.env" ]; then
        printf 'ANTHROPIC_API_KEY=%s\n' "${ANTHROPIC_API_KEY:-PASTE_KEY_HERE}" \
            > "$PARENT/chase/.env"
        echo "** edit $PARENT/chase/.env and set ANTHROPIC_API_KEY **"
    fi
    command -v deno >/dev/null || \
        echo "warning: deno not on PATH — required for CHASE's langchain-sandbox tool" >&2
fi

# ─── lxyeternal CHASE-paper malicious dataset (500 pkg) ─────────────────
if want chase-dataset || want chase; then
    if [ ! -d "$PARENT/pypi_malregistry" ]; then
        echo "==> cloning lxyeternal/pypi_malregistry (500 mal pkg, ~200 MB)"
        git clone --depth 1 https://github.com/lxyeternal/pypi_malregistry \
            "$PARENT/pypi_malregistry"
    fi
fi

# ─── MalPacDetector  (CGCL-codes/MalPacDetector-core) ───────────────────
if want malpacdetector; then
    if [ ! -d "$PARENT/malpacdetector" ]; then
        echo "==> cloning MalPacDetector"
        git clone --depth 1 https://github.com/CGCL-codes/MalPacDetector-core \
            "$PARENT/malpacdetector"
    fi
    # Upstream conf/settings.json points "datasets" at MalnpmDB (the paper
    # authors' training corpus). Our run_malpacdetector.sh stages chanever's
    # npm cases into ``datasets/chanever_npm_{mal,ben}``, so we re-point the
    # config to the generic ``datasets`` dir. Idempotent.
    if grep -q '"datasets": "datasets/MalnpmDB"' "$PARENT/malpacdetector/conf/settings.json" 2>/dev/null; then
        echo "==> MPD: applying settings-path patch"
        ( cd "$PARENT/malpacdetector" && \
          git apply --whitespace=nowarn "$HERE/baselines/patches/malpacdetector.patch" )
    fi
    # python venv. ``python3 -m venv`` fails on hosts without the apt
    # ``python3-venv`` package (ensurepip missing). Falls back to ``uv venv``
    # which doesn't need that apt package — uv brings its own bootstrap.
    if [ ! -x "$PARENT/malpacdetector/.venv/bin/python" ]; then
        echo "==> MalPacDetector: python venv + training deps"
        rm -rf "$PARENT/malpacdetector/.venv"  # clear any broken stub
        "$PY310" -m venv "$PARENT/malpacdetector/.venv" 2>/dev/null \
            || python3 -m venv "$PARENT/malpacdetector/.venv" 2>/dev/null \
            || { rm -rf "$PARENT/malpacdetector/.venv"; \
                 uv venv "$PARENT/malpacdetector/.venv" --python 3.10; }
    fi
    # Pin order matters: scikit-learn==1.2.2 is cython-compiled against
    # numpy<2 ABI but the requirements file doesn't pin numpy. Install
    # numpy<2 first so pip resolves to a compatible binary.
    if [ -x "$PARENT/malpacdetector/.venv/bin/pip" ]; then
        "$PARENT/malpacdetector/.venv/bin/pip" install --quiet --upgrade pip \
            'setuptools<81' wheel
        "$PARENT/malpacdetector/.venv/bin/pip" install --quiet 'numpy<2'
        "$PARENT/malpacdetector/.venv/bin/pip" install --quiet \
            -r "$PARENT/malpacdetector/training/requirements.txt"
    else
        # uv-created venv has no pip; use ``uv pip`` instead.
        uv pip install --python "$PARENT/malpacdetector/.venv/bin/python" \
            --quiet 'setuptools<81' wheel 'numpy<2'
        uv pip install --python "$PARENT/malpacdetector/.venv/bin/python" \
            --quiet -r "$PARENT/malpacdetector/training/requirements.txt"
    fi
    # MPD's cli.py listdir()s these at module top-level — they have to exist
    # before any ``cli.py {extract,predict}`` call.
    mkdir -p "$PARENT/malpacdetector"/{features,feature-positions,reports}
    # Node feature-extract: install deps + compile (webpack → dist/main.js)
    if [ ! -f "$PARENT/malpacdetector/feature-extract/dist/main.js" ]; then
        echo "==> MalPacDetector: building feature-extract (webpack compile)"
        ( cd "$PARENT/malpacdetector/feature-extract" \
            && npm install --silent && npm run compile )
    fi
fi

# ─── ClawVet ────────────────────────────────────────────────────────────
if want clawvet; then
    if [ ! -d "$PARENT/clawvet" ]; then
        echo "==> cloning ClawVet"
        git clone --depth 1 https://github.com/MohibShaikh/clawvet "$PARENT/clawvet"
    fi
    if [ ! -d "$PARENT/clawvet/node_modules" ]; then
        ( cd "$PARENT/clawvet" && npm install --silent )
    fi
fi

# ─── chase_compatible_ben corpus (paper-shaped: newly-published small pkg) ─
if want chase-compatible-corpus || want chase; then
    CORPUS="$REPO_ROOT/bench/corpora/chase_compatible_ben"
    if [ ! -d "$CORPUS" ] || [ "$(find "$CORPUS" -maxdepth 1 -type d | wc -l)" -lt 5 ]; then
        echo "==> building chase_compatible_ben corpus from PyPI RSS"
        python3 "$HERE/build_chase_compatible_corpus.py"
    fi
fi

echo
echo "setup complete. Next: bash bench/reproduction/reproduce_all.sh"
