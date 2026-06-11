# MalPacDetector

**Paper**: IEEE TIFS 2025
**Source**: github.com/CGCL-codes/MalPacDetector-core
**License**: Apache-2.0
**Training data**: MalnpmDB (authors' public dataset)

## What it is

A classical-ML classifier for malicious npm package detection. Two-stage
pipeline:

1. **Babel AST feature extraction** (TypeScript / Node) — walks each
   package's JS source under `feature-extract/` to produce
   per-package feature-position JSON.
2. **scikit-learn classifier** (Python) — collects features into CSV,
   then runs one of `RF | MLP | NB | SVM` to emit a `package, predict`
   CSV report. We use **RF** (Random Forest) — the paper's best
   reported model.

Paper-reported numbers (RF on MalnpmDB held-out): recall ≈ 95 %,
precision ≈ 97 %.

## How we ran it

### Install issues we hit (and patches we applied)

1. **`pkg_resources` removed in setuptools 82** — same as CHASE.
   → pin `setuptools<81`.
2. **sklearn binary incompatibility with numpy 2.x** — the wheels
   shipped at the time of writing are compiled against numpy 1.x ABI.
   → pin `numpy<2`.
3. **`python3 -m venv` missing pip** on some distros (Debian-flavoured
   installs minus `python3-venv`). → if `setup.sh`'s
   `python3 -m venv` line fails, install `python3.10-venv` apt package
   or use `uv venv --python 3.10`.
4. **Node-side**: `feature-extract/` is a TypeScript Babel walker. The
   first-time `npm install` builds the Babel deps; subsequent runs
   reuse `node_modules`.

### Running on chanever's npm corpus

`bench/reproduction/run_malpacdetector.sh` does everything end-to-end:

1. Stages chanever's `datadog-npm` (50 mal) and `benign-npm` (50 ben)
   into MPD's `datasets/<corpus>/<pkg>/...` layout.
2. Invokes the Babel feature extractor to write
   `feature-positions/<corpus>/*.json`.
3. Collects features → `features/<corpus>/*.csv`.
4. Runs the RF classifier → `reports/<corpus>-RF-report.csv`.
5. Calls `aggregate_malpacdetector.py` to merge the two CSVs into a
   chanever-shaped JSON matching `expected_outputs/malpacdetector_npm_results.json`.

### Determinism

The classifier is deterministic given a fixed model file. We did NOT
retrain — we use the pretrained `models/RF.joblib` the MPD repo ships.
So per-row outputs (`package name, predict`) should match the reference
CSV exactly on re-run.

## Numbers on our corpus

| | malicious-npm (50) | benign-npm (50) |
|---|---:|---:|
| TP | 44 | – |
| FN | 6 | – |
| TN | – | 49 |
| FP | – | 1 |

Recall 88 %, precision 97.8 %, accuracy 93 %, F1 92.6 %.

The 6 false negatives are highly-obfuscated payloads with patterns
post-dating MalnpmDB's training window.

## Outputs

Per-package: `feature-positions/<corpus>/<pkg>-<ver>.json` and
`features/<corpus>/<pkg>-<ver>.csv`. Aggregated: a single results
JSON at `$OUT_DIR/malpacdetector_npm.json` matching the schema used
by `bench/run_clawvet_bench.py`.
