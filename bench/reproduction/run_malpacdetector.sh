#!/usr/bin/env bash
# Drive MalPacDetector (CGCL-codes/MalPacDetector-core) over chanever's
# npm corpora and emit a chanever-shaped results.json.
#
# Pipeline matches the paper:
#   1. Babel AST feature extraction (Node)  → feature-positions/<corpus>/*.json
#   2. Per-package feature collection (Py)  → features/<corpus>/*.csv
#   3. RandomForest inference (Py)          → reports/<corpus>-RF-report.csv
#   4. Aggregate the two CSVs into a JSON matching the other bench wrappers
#
# Output JSON: $1 (default: /tmp/reproduction/malpacdetector_npm.json)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PARENT="$(dirname "$REPO_ROOT")"
MPD="$PARENT/malpacdetector"
OUT_JSON="${1:-/tmp/reproduction/malpacdetector_npm.json}"

[ -d "$MPD" ] || { echo "MPD not installed — run setup.sh first" >&2; exit 1; }
[ -d "$MPD/.venv" ] || { echo "MPD venv missing — run setup.sh first" >&2; exit 1; }

# ── 1. stage chanever npm cases into MPD's expected dir layout ──
MAL_DIR="$REPO_ROOT/bench/corpora/datadog-npm"
BEN_DIR="$REPO_ROOT/bench/corpora/benign-npm"
[ -d "$MAL_DIR" ] && [ -d "$BEN_DIR" ] || {
    echo "npm corpora missing — run bench/setup_corpora.sh first" >&2; exit 1; }

for corpus in chanever_npm_mal chanever_npm_ben; do
    rm -rf "$MPD/datasets/$corpus" "$MPD/feature-positions/$corpus" \
           "$MPD/features/$corpus"  "$MPD/reports/${corpus}-RF-report.csv"
    mkdir -p "$MPD/datasets/$corpus"
done

for case in "$MAL_DIR"/*/artifact/package; do
    name="$(basename "$(dirname "$(dirname "$case")")")"
    cp -r "$case" "$MPD/datasets/chanever_npm_mal/$name"
done
for case in "$BEN_DIR"/*/artifact/package; do
    name="$(basename "$(dirname "$(dirname "$case")")")"
    cp -r "$case" "$MPD/datasets/chanever_npm_ben/$name"
done

# ── 2. Babel feature extraction (Node) ──
cd "$MPD/feature-extract"
for corpus in chanever_npm_mal chanever_npm_ben; do
    node dist/index.js "$MPD/datasets/$corpus" \
        "$MPD/feature-positions/$corpus"
done

# ── 3. RF inference (Py) ──
cd "$MPD"
for corpus in chanever_npm_mal chanever_npm_ben; do
    "$MPD/.venv/bin/python" scripts/extract_features.py \
        "$MPD/feature-positions/$corpus" "$MPD/features/$corpus"
    "$MPD/.venv/bin/python" scripts/run_classifier.py \
        --features "$MPD/features/$corpus" \
        --model RF \
        --out    "$MPD/reports/${corpus}-RF-report.csv"
done

# ── 4. aggregate CSVs into chanever-shaped JSON ──
mkdir -p "$(dirname "$OUT_JSON")"
"$MPD/.venv/bin/python" "$HERE/aggregate_malpacdetector.py" \
    --mal-csv "$MPD/reports/chanever_npm_mal-RF-report.csv" \
    --ben-csv "$MPD/reports/chanever_npm_ben-RF-report.csv" \
    --out     "$OUT_JSON"

echo "wrote $OUT_JSON"
