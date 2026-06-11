# MalPacDetector

**Paper**: IEEE TIFS 2025
**Source**: github.com/CGCL-codes/MalPacDetector-core
**License**: as published by upstream
**Training data**: MalnpmDB (authors' public dataset)

## What it is

A classical-ML classifier for malicious npm package detection. Two-stage
pipeline:

1. **Babel feature extraction** (TypeScript / Node) — webpack-compiled
   walker under `feature-extract/dist/main.js` walks each package's JS
   source and emits per-package feature-position JSON.
2. **scikit-learn classifier** (Python) — collects features into CSV,
   then loads a pretrained model (`models/RF.pkl` for the paper's best
   RandomForest config) and emits a `package, predict` CSV report.

Paper-reported numbers (RF on MalnpmDB held-out): recall ≈ 95 %,
precision ≈ 97 %.

## Setup

`bench/reproduction/setup.sh` handles it:

```bash
git clone --depth 1 https://github.com/CGCL-codes/MalPacDetector-core ../malpacdetector
python3.10 -m venv ../malpacdetector/.venv
../malpacdetector/.venv/bin/pip install -r ../malpacdetector/training/requirements.txt
( cd ../malpacdetector/feature-extract && npm install && npm run compile )
```

The python deps are pinned by upstream's `training/requirements.txt`:
`scikit-learn==1.2.2` + `prettytable==3.7.0`. scikit-learn 1.2 implicitly
needs numpy<2, so no extra pin needed.

The Node side **must** be `npm install && npm run compile` (which runs
webpack and emits `dist/main.js`). A plain `npm install` is not enough
— `cli.py extract` invokes `npm run start` which expects the compiled
output.

## Running on chanever's npm corpus

`bench/reproduction/run_malpacdetector.sh` does the full pipeline:

1. **Stage**: for every case under `bench/corpora/datadog-npm/<case>/`
   and `bench/corpora/benign-npm/<pkg>/`, locate the unpacked
   `package/` subtree, repack it as
   `../malpacdetector/datasets/<corpus>/<name>-<ver>.tar.gz`. (MPD's
   `decompress_packages` walks each dataset dir for `.tar.gz` files.)
2. **Extract features**: `cd ../malpacdetector && python cli.py extract
   -d chanever_npm_mal chanever_npm_ben`. This `chdir`s into
   `feature-extract/` and runs `npm run start` per package.
3. **Predict**: `python cli.py predict -o RF -d chanever_npm_mal`
   (then again for `chanever_npm_ben`). Loads `models/RF.pkl` and
   writes `reports/<corpus>-RF-report.csv` with two columns
   (`package name`, `predict`).
4. **Aggregate**: `aggregate_malpacdetector.py` merges the two CSVs
   into a chanever-shaped JSON
   (`malpacdetector_npm_results.json`) matching the schema used by
   `bench/run_clawvet_bench.py`.

## Determinism

The RF classifier is deterministic given a fixed `models/RF.pkl` (the
pretrained model upstream ships in the repo). We did NOT retrain. So
per-row outputs should match the reference CSV on re-run unless MPD
upstream updates the model file.

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

Per-package: `feature-positions/<corpus>/<pkg>.json` and
`features/<corpus>/<pkg>.csv`. Aggregated reports:
`reports/<corpus>-RF-report.csv`. Final JSON: `$OUT_DIR/malpacdetector_npm.json`
matching the schema used by the other bench wrappers.
