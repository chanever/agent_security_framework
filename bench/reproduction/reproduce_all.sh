#!/usr/bin/env bash
# Drive every comparison-bench end-to-end. Run AFTER setup.sh has completed
# successfully. Output goes to /tmp/reproduction/<bench>/results.json.
#
# Idempotent: each wrapper supports --resume so re-running picks up from the
# last checkpoint. Total wall time on our reference machine: ≈ 6 h.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PARENT="$(dirname "$REPO_ROOT")"
OUT_DIR="${OUT_DIR:-/tmp/reproduction}"
mkdir -p "$OUT_DIR"

ONLY="${1:-}"
if [ "$ONLY" = "--only" ]; then ONLY="${2:-}"; else ONLY=""; fi
want() { [ -z "$ONLY" ] || [ "$1" = "$ONLY" ]; }

cd "$REPO_ROOT"

# Shared env for chanever-side runs (Claude CLI verifier + sandbox).
export SECURITY_FRAMEWORK_ENABLED=true
export SHADOW_SANDBOX_ENABLED=true
export SECURITY_STATIC_ANALYSIS_ENABLED=true
export SECURITY_REPUTATION_ANALYSIS_ENABLED=true
export VERIFIER_MODE=claude_cli
export SANDBOX_DOCKER_IMAGE="${SANDBOX_DOCKER_IMAGE:-shadow-agent-sandbox:latest}"
export CLAUDE_CLI_MAX_TURNS=12

# ─────────────── 1. chanever on CHASE's lxyeternal dataset + benign-pypi ──
if want chanever-on-chase; then
    echo "==> [1/5] chanever on CHASE dataset (~2 h)"
    python bench/run_chanever_on_chase_dataset.py \
        --malregistry-root "$PARENT/pypi_malregistry" \
        --benign-root      "$REPO_ROOT/bench/corpora/benign-pypi" \
        --n-mal 500 --n-ben 0 \
        --out "$OUT_DIR/chanever_on_chase.json" \
        --resume
fi

# ─────────────── 2. head-to-head on chase_compatible_ben (23 pkg) ─────────
if want head-to-head; then
    echo "==> [2/5] chanever vs CHASE on chase_compatible_ben (~3 h)"
    python bench/run_chase_vs_chanever_small.py \
        --out "$OUT_DIR/chase_vs_chanever_small.json" \
        --resume
fi

# ─────────────── 3. CHASE on our benign-pypi (out-of-scope cases ERR) ─────
if want chase-on-benign; then
    echo "==> [3/5] CHASE on chanever benign-pypi (~1 h)"
    python bench/run_chase_bench.py \
        --families benign-pypi \
        --cap 0 \
        --out "$OUT_DIR/chase_on_benign_pypi.json" \
        --resume
fi

# ─────────────── 4. ClawVet on skill / tool corpus ───────────────────────
if want clawvet; then
    echo "==> [4/5] ClawVet on chanever skill+tool corpus (~15 min)"
    python bench/run_clawvet_bench.py \
        --cap 0 \
        --out "$OUT_DIR/clawvet_skill.json" \
        --resume
fi

# ─────────────── 5. MalPacDetector on npm corpus ─────────────────────────
if want malpacdetector; then
    echo "==> [5/5] MalPacDetector RF on chanever npm corpus (~10 min)"
    bash "$HERE/run_malpacdetector.sh" "$OUT_DIR/malpacdetector_npm.json"
fi

echo
echo "all benches done. JSON outputs in $OUT_DIR/"
echo "to re-render the comparison charts:"
echo "  python bench/reproduction/render_charts.py --in $OUT_DIR \\"
echo "    --out bench/reproduction/expected_outputs/charts"
