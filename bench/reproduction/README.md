# Reproduction package — chanever bench + baselines

End-to-end recipe for a TA / external reviewer to take a clean machine,
clone this repo, and reproduce every number and chart in
`bench/reproduction/expected_outputs/`.

The chanever framework itself is reproduced with `bench/framework_reliability.py`
(see `bench/README.md`). This folder adds the **baselines** (CHASE,
MalPacDetector, ClawVet) so head-to-head comparisons in the final report can
be re-run from a clean state.

---

## What gets reproduced

| Output file | Produced by | Approx wall time |
|-------------|-------------|------------------|
| `expected_outputs/chanever_full_census_results.json` | chanever on its own 302-case bench (`framework_reliability.py`) | ~11 h via Claude CLI verifier |
| `expected_outputs/chanever_on_chase_results.json` | chanever on CHASE's 500-pkg malicious dataset + our benign-pypi (`run_chanever_on_chase_dataset.py`) | ~2 h |
| `expected_outputs/chase_vs_chanever_small_results.json` | both frameworks on the 23-pkg `chase_compatible_ben` corpus (`run_chase_vs_chanever_small.py`) | ~3 h |
| `expected_outputs/chase_on_benign_pypi_results.json` | CHASE on chanever's benign-pypi (`run_chase_bench.py`) | ~1 h |
| `expected_outputs/clawvet_skill_results.json` | ClawVet on chanever's skill/tool corpus (`run_clawvet_bench.py`) | ~15 min |
| `expected_outputs/malpacdetector_npm_results.json` | MalPacDetector RF on chanever's npm corpus | ~10 min |
| `expected_outputs/charts/*.png` | helper plotting scripts in this folder | ~2 min total |

---

## Hardware / OS assumptions

These are what we ran on. The wall times above scale with hardware.

- Linux x86_64 (tested on Ubuntu 22.04 / kernel 5.15)
- Docker daemon running, user in `docker` group
- 32 GB RAM, 100 GB free disk (most consumed by docker images + corpora)
- Outbound network access to: PyPI, npmjs, GitHub, deps.dev, OSV.dev, Anthropic API, DuckDuckGo
- No GPU required. (CHASE has a local-LLM mode that needs a GPU; we use its `--llm-runner anthropic` mode.)

---

## Step 1 — chanever framework itself

```bash
bash bench/setup_corpora.sh                              # one-time, ~10 min
docker build -t shadow-agent-sandbox:latest -f sandbox/Dockerfile sandbox/
SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \
SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \
VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
CLAUDE_CLI_MAX_TURNS=12 \
python bench/framework_reliability.py --cap 0 \
  --out /tmp/framework_reliability_full_census.json
```

This is the chanever-side full census. See `bench/README.md` for the full
prerequisites — Claude CLI authenticated on host, docker for sandbox +
semgrep, etc.

Output: `/tmp/framework_reliability_full_census.json` should match
`expected_outputs/chanever_full_census_results.json` (TP 146 / TN 145 / FP 3
/ FN 7 / ERR 1; F1 96.7 %; numbers depend on verifier LLM nondeterminism
within ±2 %).

---

## Step 2 — Set up the three baselines

Run the one-shot setup script:

```bash
bash bench/reproduction/setup.sh
```

It clones each baseline into a sibling directory next to this repo,
builds its venv, installs dependencies, and downloads CHASE's public
malicious dataset (`lxyeternal/pypi_malregistry`).

Per-baseline install detail and the source repos:

- `baselines/CHASE.md` — CHASE (Toda & Mori, arXiv:2601.06838)
- `baselines/MalPacDetector.md` — MalPacDetector (IEEE TIFS 2025)
- `baselines/ClawVet.md` — ClawVet (github.com/MohibShaikh/clawvet)

---

## Step 3 — Run the head-to-head benches

After Step 2 succeeds, drive each bench:

```bash
bash bench/reproduction/reproduce_all.sh
```

This runs five wrapper scripts under `bench/`. Each writes a JSON in the
same shape as the `expected_outputs/` reference files. Re-running is
idempotent — wrappers support `--resume` so a partial run continues from
the last checkpoint.

Per-bench detail:

| Bench | Wrapper | Reference output |
|-------|---------|------------------|
| chanever on CHASE dataset | `bench/run_chanever_on_chase_dataset.py` | `expected_outputs/chanever_on_chase_results.json` |
| Head-to-head benign | `bench/run_chase_vs_chanever_small.py` | `expected_outputs/chase_vs_chanever_small_results.json` |
| CHASE on our benign-pypi | `bench/run_chase_bench.py` | `expected_outputs/chase_on_benign_pypi_results.json` |
| ClawVet on skills | `bench/run_clawvet_bench.py` | `expected_outputs/clawvet_skill_results.json` |
| MalPacDetector on npm | (see `baselines/MalPacDetector.md`) | `expected_outputs/malpacdetector_npm_results.json` |

---

## Step 4 — Re-render the charts

After every JSON exists under your working bench output dir:

```bash
python bench/reproduction/render_charts.py
```

Writes PNGs into `bench/reproduction/expected_outputs/charts/`. Compare
visually against the committed reference PNGs.

---

## What's *not* deterministic

Both chanever and CHASE include an LLM in the decision loop, so a
re-run will not be byte-identical to the reference JSON:

- Verifier text (`reason` field) varies even when the decision is the same.
- Edge cases sit close to the allow/block boundary — expect ≤ 2 % drift
  in F1 / DSR / specificity headline numbers.
- CHASE's web-research step uses DuckDuckGo; rate limits can change which
  cases ERR.

The MalPacDetector RF classifier and ClawVet's rule pack are deterministic
— their per-row outputs should match the reference exactly.

---

## Documents you might want to print

- `expected_outputs/chase_fp_analysis.md` — explanation of where chanever
  loses FPs to CHASE on benign packages
- `expected_outputs/QA_module_explanation.pdf` — Q&A on how the static
  analyzer and reputation modules work (Korean)
