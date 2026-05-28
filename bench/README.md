# Framework reliability bench

End-to-end measurement of the safeguard pipeline against a labelled corpus of
external-source install scenarios. Reports per-source-type Defense Success
Rate (framework OFF vs ON) and benign/malicious discrimination accuracy with
two PNG charts.

## Quickstart

```bash
# 1. Populate the downloadable corpora (one-time, ~10 min, ~500 MB on disk).
bash bench/setup_corpora.sh

# 2. Build & start the shadow sandbox docker image (one-time).
docker build -t shadow-agent-sandbox:latest -f sandbox/Dockerfile sandbox/

# 3. Run the bench (3 cases per family ≈ 30 min through the Claude CLI verifier).
SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \
SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \
VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
CLAUDE_CLI_MAX_TURNS=12 \
python bench/framework_reliability.py --cap 3
```

Outputs land at `/tmp/framework_reliability.json` plus `_dsr.png` and
`_discrim.png` alongside.

## Prerequisites

- Python 3.10+ with the framework's runtime deps installed
  (`security_framework` import works) and `matplotlib` for chart rendering.
- `docker` (semgrep static scan + shadow sandbox both run in containers).
- `curl`, `git`, `tar`, `unzip` — `bench/setup_corpora.sh` uses them.
- `VERIFIER_MODE=claude_cli` requires the Claude CLI to be authenticated
  (`claude login`) on the host. Each case spends ~60-90s in the verifier so a
  full census is multi-hour.

## Corpus layout (two-tier)

So the bench is reproducible on a fresh clone:

| dir | what | shipped in git? | populated by |
|---|---|---|---|
| `bench/fixtures/` | handcrafted, ours: `malicious-repos` (8), `skill-inject` (40), `toolhijacker` (11), `benign-tools` (8), `benign-skills` (20) | yes, version-controlled (~20 MB) | the PR itself — present on first checkout |
| `bench/corpora/`  | downloadable, public: `datadog-pypi` (50) + `datadog-npm` (50) + `benign-pypi` (45) + `benign-npm` (50) + `benign-repos` (20) | no, `.gitignore`d (~500 MB) | `bench/setup_corpora.sh` |

Per-family scenario templates (`task` / `history` / `action_reason`) live as
markdown files under `bench/scenarios/<family>.md` with a fenced `json`
block. The case lists `setup_corpora.sh` reads from live under
`bench/manifests/`.

## `setup_corpora.sh` — populating the downloadable corpus

```bash
# everything (5 ecosystems, ~10 min on a good connection):
bash bench/setup_corpora.sh

# subset by ecosystem (matches the --only filter substring):
bash bench/setup_corpora.sh --only datadog       # pypi + npm adversarial mirror
bash bench/setup_corpora.sh --only benign-pypi   # one family
bash bench/setup_corpora.sh --only benign-repos  # only the github clones
```

Sources, per family:

| family | source | size | notes |
|---|---|---|---|
| `datadog-pypi` | github.com/DataDog/malicious-software-packages-dataset | ~45 MB | password-protected ZIPs, unzip password is `infected` (DataDog convention) |
| `datadog-npm`  | same dataset | ~8 MB | same |
| `benign-pypi`  | pypi.org JSON API → sdist URL → tarball | ~600 MB | top PyPI packages, latest version |
| `benign-npm`   | registry.npmjs.org → tarball | ~150 MB | top npm packages, latest version |
| `benign-repos` | `git clone --depth 1` GitHub, then strips `.git` | ~30 MB after dedup | popular Python OSS (django, fastapi, pytest, …) |

**Idempotent.** Per case it checks `bench/corpora/<family>/<case>/` and
skips if the dir is non-empty. To re-fetch a case, delete its dir and
re-run. Partial failures don't poison subsequent runs — re-execute to fill
the gaps.

**No network / public source down?** You can still run the bench against
the 5 fixture families (87 cases handcrafted, shipped in the repo):

```bash
python bench/framework_reliability.py --cap 5 \
  --families malicious-repos,skill-inject,toolhijacker,benign-tools,benign-skills
```

## Running `framework_reliability.py`

```bash
# all 10 families, 3 cases each (≈30 min):
SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \
SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \
VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
CLAUDE_CLI_MAX_TURNS=12 \
python bench/framework_reliability.py --cap 3

# 5 cases per family (≈50 min) → headline measurement:
python bench/framework_reliability.py --cap 5 --out /tmp/fw_rel_census50.json

# full census, all cases (multi-hour):
python bench/framework_reliability.py --cap 0
```

Flags:

| flag | default | meaning |
|---|---|---|
| `--cap N` | 3 | cases per family. `0` = full census (multi-hour). |
| `--families a,b,c` | all | comma-separated subset of family names |
| `--bench-root PATH` | `bench/fixtures` + `bench/corpora` | corpus search root (repeatable). First root containing `<root>/<family>/` wins per family. Also settable via `BENCH_ROOT` env var (colon-separated). |
| `--out PATH` | `/tmp/framework_reliability.json` | JSON output |
| `--chart-out PREFIX` | `<out>.stem` | writes `<prefix>_dsr.png` + `<prefix>_discrim.png` |
| `--no-chart` | off | skip PNG rendering |

The five `SECURITY_*` / `VERIFIER_*` env vars in the example are the same
ones the README's "전체 동작 흐름" section documents — they switch the
whole safeguard pipeline ON. Drop one and the corresponding stage skips.

## Output

Stdout, summarising the run:

```
=== Per-family confusion ===
  benign-pypi        {'TN': 4, 'FP': 1}
  datadog-pypi       {'TP': 5}
  ...

=== TOTAL ===
  {'TP': 24, 'TN': 16, 'FP': 9, 'FN': 1}  (n=50, elapsed=52.4 min)

=== Metrics: Framework OFF (baseline) vs ON ===
  metric              OFF       ON
  DSR (recall)       0.0%    96.0%
  specificity      100.0%    64.0%
  accuracy          50.0%    80.0%
  ...

=== Per source type (framework ON) ===
  type    n_mal  n_ben     DSR    spec     acc
  pypi       5      5   100.0%   60.0%   80.0%
  npm        5      5   100.0%   80.0%   90.0%
  repo       5      5   100.0%  100.0%  100.0%
  skill      9     14    77.8%   85.7%   82.6%
```

JSON output at `--out` contains `confusion_total`, `confusion_per_family`,
`metrics_framework_on`, `metrics_baseline_off`, `metrics_per_source_type`,
`elapsed_min`, and per-case `rows` (decision + stages + reason).

Two PNG charts:

- `<prefix>_dsr.png` — DSR per source type, framework OFF vs ON. Baseline is
  0% by construction (no framework → every malicious install runs).
- `<prefix>_discrim.png` — per-source-type recall + specificity (left) and
  per-family confusion stack (right). Shows the framework distinguishes
  benign from harmful, not just blanket-blocks.

`bench/framework_reliability_RESULTS.md` records the analysis from the
most-recent reference census.

## Files

```
bench/
├── framework_reliability.py            ← bench driver (this README's main entry)
├── framework_smoke.py                  ← 3-fixture smoke (10s, no Claude CLI needed)
├── framework_reliability_RESULTS.md    ← prior census analysis
├── scenarios/<family>.md      × 10     ← per-family task/history/action templates
├── manifests/                          ← inputs for setup_corpora.sh
│   ├── datadog-{pypi,npm}.tsv          ← case_dir + package + sample + URL
│   ├── benign-{pypi,npm}.txt           ← package names (registry)
│   └── benign-repos.tsv                ← name + git URL
├── fixtures/                  × 5      ← handcrafted, version-controlled
├── corpora/                   × 5      ← downloadable, gitignored
├── setup_corpora.sh                    ← populates corpora/
└── README.md                           ← this file
```
