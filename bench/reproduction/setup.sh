#!/usr/bin/env bash
# Set up the three external baseline frameworks next to this chanever repo.
# Idempotent — re-running skips work that's already done.
#
# Layout after this completes (parent dir of this repo):
#   ../chase/                  ← CHASE checkout + .venv
#   ../malpacdetector/         ← MalPacDetector checkout + .venv
#   ../clawvet/                ← ClawVet checkout + node_modules
#   ../pypi_malregistry/       ← lxyeternal CHASE-paper malicious dataset (500 pkg)
#
# Usage:
#   bash bench/reproduction/setup.sh
#   bash bench/reproduction/setup.sh --only chase    # one baseline
#
# Per-baseline detail lives in bench/reproduction/baselines/*.md — read those
# if something here fails.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PARENT="$(dirname "$REPO_ROOT")"
ONLY="${1:-}"
if [ "$ONLY" = "--only" ]; then ONLY="${2:-}"; else ONLY=""; fi
want() { [ -z "$ONLY" ] || [ "$1" = "$ONLY" ]; }

# ─────────────── prerequisites we expect on the host ────────────────────
for bin in git python3 node npm docker; do
    command -v "$bin" >/dev/null || { echo "missing prereq: $bin" >&2; exit 1; }
done
PY312="${PY312:-python3.12}"   # CHASE needs 3.12 (semgrep wheel)
PY310="${PY310:-python3.10}"   # MalPacDetector pinned to 3.10
for bin in "$PY312" "$PY310"; do
    command -v "$bin" >/dev/null || \
        echo "warning: $bin not found — install before running the matching baseline" >&2
done

# ─────────────────────────── CHASE ──────────────────────────────────────
if want chase; then
    if [ ! -d "$PARENT/chase" ]; then
        echo "==> cloning CHASE"
        git clone --depth 1 https://github.com/iydon/chase "$PARENT/chase"
    fi
    if [ ! -d "$PARENT/chase/.venv" ]; then
        echo "==> CHASE venv (Python 3.12)"
        "$PY312" -m venv "$PARENT/chase/.venv"
    fi
    "$PARENT/chase/.venv/bin/pip" install --quiet --upgrade 'setuptools<81' wheel
    "$PARENT/chase/.venv/bin/pip" install --quiet -r "$PARENT/chase/requirements.txt" \
        langchain-anthropic
    # Ensure CHASE knows our API key
    if [ ! -f "$PARENT/chase/.env" ]; then
        printf 'ANTHROPIC_API_KEY=%s\n' "${ANTHROPIC_API_KEY:-PASTE_KEY_HERE}" \
            > "$PARENT/chase/.env"
        echo "edit $PARENT/chase/.env and set ANTHROPIC_API_KEY"
    fi
    # CHASE needs deno on PATH for one of its tools
    command -v deno >/dev/null || \
        echo "warning: deno not on PATH — see baselines/CHASE.md" >&2
fi

# ───────────── lxyeternal CHASE-paper malicious dataset (500 pkg) ────────
if want chase-dataset || want chase; then
    if [ ! -d "$PARENT/pypi_malregistry" ]; then
        echo "==> cloning lxyeternal/pypi_malregistry (500 mal pkg)"
        git clone --depth 1 https://github.com/lxyeternal/pypi_malregistry \
            "$PARENT/pypi_malregistry"
    fi
fi

# ──────────────────────── MalPacDetector ────────────────────────────────
if want malpacdetector; then
    if [ ! -d "$PARENT/malpacdetector" ]; then
        echo "==> cloning MalPacDetector"
        git clone --depth 1 https://github.com/CGCL-codes/MalPacDetector-core \
            "$PARENT/malpacdetector"
    fi
    if [ ! -d "$PARENT/malpacdetector/.venv" ]; then
        echo "==> MalPacDetector venv (Python 3.10)"
        "$PY310" -m venv "$PARENT/malpacdetector/.venv"
    fi
    "$PARENT/malpacdetector/.venv/bin/pip" install --quiet --upgrade pip \
        'setuptools<81' 'numpy<2' wheel
    "$PARENT/malpacdetector/.venv/bin/pip" install --quiet \
        scikit-learn pandas joblib
    # Build the Babel feature-extract Node module
    if [ ! -d "$PARENT/malpacdetector/feature-extract/node_modules" ]; then
        ( cd "$PARENT/malpacdetector/feature-extract" && npm install --silent )
    fi
fi

# ─────────────────────────── ClawVet ────────────────────────────────────
if want clawvet; then
    if [ ! -d "$PARENT/clawvet" ]; then
        echo "==> cloning ClawVet"
        git clone --depth 1 https://github.com/MohibShaikh/clawvet "$PARENT/clawvet"
    fi
    if [ ! -d "$PARENT/clawvet/node_modules" ]; then
        ( cd "$PARENT/clawvet" && npm install --silent )
    fi
fi

# ──── chase_compatible_ben corpus (paper-shaped: newly-published small pkg) ────
if want chase-compatible-corpus || want chase; then
    CORPUS="$REPO_ROOT/bench/corpora/chase_compatible_ben"
    if [ ! -d "$CORPUS" ] || [ "$(find "$CORPUS" -maxdepth 1 -type d | wc -l)" -lt 5 ]; then
        echo "==> building chase_compatible_ben corpus from PyPI RSS"
        python3 "$HERE/build_chase_compatible_corpus.py"
    fi
fi

echo
echo "setup complete. Next: bash bench/reproduction/reproduce_all.sh"
