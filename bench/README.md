# Framework reliability bench

End-to-end measurement of the safeguard pipeline against a labelled corpus of
external-source install scenarios. Reports per-source-type Defense Success
Rate (framework OFF vs ON) and benign/malicious discrimination accuracy.

## What it measures

Each case simulates the README's `examples/` flow:

1. The user instructs the agent (`Install the 0wneg package…`).
2. The agent emits the install command (`pip install 0wneg`) with a plausible
   1-step exploration history.
3. The safeguard inspects that action through the full pipeline
   (classification → external target → asset_kind → static_analyzers →
   reputation → shadow sandbox → evidence builder → Claude CLI verifier).
4. The bench compares the safeguard's `decision` (allow / block) to the case
   label and folds outcomes (TP / TN / FP / FN / ERR) into per-family and
   per-source-type confusion matrices.

## Corpus layout

Two-tier so the bench is reproducible on a fresh clone:

| dir | contents | shipped? |
|---|---|---|
| `bench/fixtures/` | handcrafted cases — malicious-repos, skill-inject, toolhijacker, benign-tools, benign-skills | yes (version-controlled, ~20 MB) |
| `bench/corpora/`  | downloadable cases — datadog-pypi/npm, benign-pypi/npm, benign-repos | no (`.gitignore`d, populate via setup script) |

Per-family scenario templates (task / history / action_reason) live as
markdown files under `bench/scenarios/<family>.md` with a fenced `json`
block. Manifests describing the downloadable corpora live under
`bench/manifests/`.

## First-time setup

```bash
bash bench/setup_corpora.sh         # populate bench/corpora/ (all ecosystems)
bash bench/setup_corpora.sh --only datadog       # subset
bash bench/setup_corpora.sh --only benign-pypi   # one family
```

Pulls from public sources: the DataDog malicious-software-packages-dataset
(password-protected ZIPs, password `infected`), PyPI / npm registries, and
GitHub clones (`--depth 1`).

## Running the bench

```bash
# 3 cases per family, full pipeline ON
SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \
SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \
VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
CLAUDE_CLI_MAX_TURNS=12 \
python bench/framework_reliability.py --cap 3
```

Useful flags:

- `--cap N` — cases per family. `0` = full census (multi-hour).
- `--families a,b,c` — restrict to a comma-separated subset.
- `--bench-root PATH` (repeatable) — override the corpus search list
  (default: `bench/fixtures` + `bench/corpora`). Also settable via
  `BENCH_ROOT` env var (colon-separated).
- `--out PATH` — JSON output (default `/tmp/framework_reliability.json`).
- `--chart-out PREFIX` — output PNG prefix; writes `<prefix>_dsr.png` (OFF vs
  ON DSR per source type) and `<prefix>_discrim.png` (discrimination accuracy
  + per-family confusion).
- `--no-chart` — skip rendering.

## Output

Stdout summarises the confusion matrix and the metric table:

```
=== Metrics: Framework OFF (baseline) vs ON ===
  metric              OFF       ON
  DSR (recall)       0.0%    98.1%
  specificity      100.0%    60.5%
  accuracy          ...      ...
  ...

=== Per source type (framework ON) ===
  type    n_mal  n_ben     DSR    spec     acc
  pypi      ...    ...    ...%   ...%    ...%
  npm       ...    ...    ...%   ...%    ...%
  repo      ...    ...    ...%   ...%    ...%
  skill     ...    ...    ...%   ...%    ...%
```

Two PNG charts:

- `_dsr.png` — DSR per source type, framework OFF vs ON. Baseline is 0 by
  construction (no framework → every malicious install runs).
- `_discrim.png` — per-source-type recall + specificity (left) and per-family
  confusion stack (right) — shows that the framework distinguishes benign
  from harmful, not just blanket-blocks.

`bench/framework_reliability_RESULTS.md` records the analysis from a prior
full-census run.
