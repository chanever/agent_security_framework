#!/usr/bin/env bash
# Drive MalPacDetector (CGCL-codes/MalPacDetector-core) over chanever's
# npm corpora and emit a chanever-shaped results.json.
#
# Upstream MPD pipeline (cli.py, ``training/`` package, ``feature-extract/``):
#
#   1. Stage <pkg>.tar.gz files into ``malpacdetector/datasets/<corpus>/``
#      — cli.py's decompress_packages walks the dir for tar.gz archives.
#   2. ``python cli.py extract -d <corpus>`` — chdirs to feature-extract,
#      runs ``npm run start -- -d <dataset_path> <feature_path>
#      <feature_position_path>`` to produce per-pkg feature CSVs.
#   3. ``python cli.py predict -o RF -d <corpus>`` — runs the pretrained
#      ``models/RF.pkl`` over the features, writes
#      ``reports/<corpus>-RF-report.csv``.
#   4. aggregate_malpacdetector.py merges the two CSVs into a JSON
#      matching the other bench wrappers.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PARENT="$(dirname "$REPO_ROOT")"
MPD="$PARENT/malpacdetector"
OUT_JSON="${1:-/tmp/reproduction/malpacdetector_npm.json}"

[ -d "$MPD"          ] || { echo "MPD not installed — run setup.sh first" >&2; exit 1; }
[ -d "$MPD/.venv"    ] || { echo "MPD venv missing — run setup.sh first" >&2; exit 1; }
[ -f "$MPD/feature-extract/dist/main.js" ] || \
    { echo "feature-extract not compiled — run setup.sh first" >&2; exit 1; }
[ -f "$MPD/models/RF.pkl" ] || \
    { echo "MPD pretrained RF.pkl missing — clone integrity issue" >&2; exit 1; }

MAL_DIR="$REPO_ROOT/bench/corpora/datadog-npm"
BEN_DIR="$REPO_ROOT/bench/corpora/benign-npm"
[ -d "$MAL_DIR" ] && [ -d "$BEN_DIR" ] || \
    { echo "npm corpora missing — run bench/setup_corpora.sh first" >&2; exit 1; }

PY="$MPD/.venv/bin/python"

# ── 1. stage chanever cases as <name>-<ver>.tar.gz inside MPD datasets/ ──
# Source layout under bench/corpora/datadog-npm/<case>/artifact/tmp/<tmp>/<pkg>/package/
# Source layout under bench/corpora/benign-npm/<pkg>/artifact/package/
# Target layout: malpacdetector/datasets/<corpus>/<name>-<ver>.tar.gz
stage_one() {
    local pkg_root="$1"  # directory whose immediate child is package/
    local out_tgz="$2"
    [ -d "$pkg_root/package" ] || return 1
    tar -C "$pkg_root" -czf "$out_tgz" package
}

for corpus in chanever_npm_mal chanever_npm_ben; do
    rm -rf "$MPD/datasets/$corpus" \
           "$MPD/feature-positions/$corpus" \
           "$MPD/features/$corpus" \
           "$MPD/reports/${corpus}-RF-report.csv"
    mkdir -p "$MPD/datasets/$corpus"
done

echo "==> staging malicious npm cases"
count=0
for case_dir in "$MAL_DIR"/*/; do
    # case_dir typically holds artifact/tmp/<tmp>/<pkg>/package/
    pkg_root="$(find "$case_dir" -type d -name 'package' -print -quit)"
    [ -z "$pkg_root" ] && continue
    pkg_root="$(dirname "$pkg_root")"
    # derive <name>-<ver>: scrape from package.json if possible
    name=$("$PY" -c "
import json, sys, pathlib
p = pathlib.Path('$pkg_root/package/package.json')
d = json.loads(p.read_text())
print(f\"{d.get('name','unknown').replace('/','-')}-{d.get('version','0.0.0')}\")
" 2>/dev/null) || name="$(basename "$case_dir")"
    stage_one "$pkg_root" "$MPD/datasets/chanever_npm_mal/${name}.tar.gz" \
        && count=$((count + 1))
done
echo "  staged $count mal cases"

echo "==> staging benign npm cases"
count=0
for case_dir in "$BEN_DIR"/*/; do
    pkg_root="$(find "$case_dir" -type d -name 'package' -print -quit)"
    [ -z "$pkg_root" ] && continue
    pkg_root="$(dirname "$pkg_root")"
    name=$("$PY" -c "
import json, sys, pathlib
p = pathlib.Path('$pkg_root/package/package.json')
d = json.loads(p.read_text())
print(f\"{d.get('name','unknown').replace('/','-')}-{d.get('version','0.0.0')}\")
" 2>/dev/null) || name="$(basename "$case_dir")"
    stage_one "$pkg_root" "$MPD/datasets/chanever_npm_ben/${name}.tar.gz" \
        && count=$((count + 1))
done
echo "  staged $count ben cases"

# ── 2. feature extraction (Babel via feature-extract/dist/main.js) ──
echo "==> MPD cli.py extract"
( cd "$MPD" && "$PY" cli.py extract -d chanever_npm_mal chanever_npm_ben )

# ── 3. RF inference using pretrained models/RF.pkl ──
echo "==> MPD cli.py predict (RF)"
( cd "$MPD" && "$PY" cli.py predict -o RF -d chanever_npm_mal )
( cd "$MPD" && "$PY" cli.py predict -o RF -d chanever_npm_ben )

# ── 4. aggregate the two CSVs into chanever-shaped JSON ──
mkdir -p "$(dirname "$OUT_JSON")"
"$PY" "$HERE/aggregate_malpacdetector.py" \
    --mal-csv "$MPD/reports/chanever_npm_mal-RF-report.csv" \
    --ben-csv "$MPD/reports/chanever_npm_ben-RF-report.csv" \
    --out     "$OUT_JSON"

echo "wrote $OUT_JSON"
