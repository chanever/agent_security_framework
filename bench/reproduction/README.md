# Reproduction package — chanever bench + baselines

End-to-end recipe for a TA / external reviewer to take a clean machine,
clone **only this repo**, and reproduce every number and chart in
`bench/reproduction/expected_outputs/`.

`vulnerable_cli_agent` is **not** required for the bench — the bench
harness (`bench/framework_reliability.py`) drives `safeguard.inspect()`
directly with synthetic action+context records. The main repo README
mentions `vulnerable_cli_agent` because that's the production wiring;
reproduction only needs the safeguard framework.

---

## What gets reproduced

| Output file | Produced by | Approx wall time |
|-------------|-------------|------------------|
| `expected_outputs/chanever_full_census_results.json` | chanever on its own 302-case bench (`framework_reliability.py`) | ~11 h via Claude CLI verifier |
| `expected_outputs/chanever_on_chase_results.json` | chanever on CHASE's 500-pkg malicious dataset + benign-pypi (`run_chanever_on_chase_dataset.py`) | ~2 h |
| `expected_outputs/chase_vs_chanever_small_results.json` | both frameworks on the 23-pkg `chase_compatible_ben` corpus (`run_chase_vs_chanever_small.py`) | ~3 h |
| `expected_outputs/chase_on_benign_pypi_results.json` | CHASE on chanever's benign-pypi (`run_chase_bench.py`) | ~1 h |
| `expected_outputs/clawvet_skill_results.json` | ClawVet on chanever's skill/tool corpus (`run_clawvet_bench.py`) | ~15 min |
| `expected_outputs/malpacdetector_npm_results.json` | MalPacDetector RF on chanever's npm corpus | ~10 min |
| `expected_outputs/charts/*.png` | `render_charts.py` | ~2 min total |

---

## Hardware / OS assumptions

These are what we ran on. Wall times above scale with hardware.

- Linux x86_64 (tested on Ubuntu 22.04 / kernel 5.15)
- Docker daemon running, user in `docker` group
- 32 GB RAM, 100 GB free disk
- Outbound network: PyPI, npmjs, GitHub, deps.dev, OSV.dev, Anthropic API, DuckDuckGo
- No GPU required (CHASE has an Anthropic-API mode; we use that)

---

## Host prerequisites — install before anything else

```bash
# OS packages
sudo apt-get install -y curl git docker.io nodejs npm

# Python 3.10 + venv (chanever itself; system default on Ubuntu 22.04)
sudo apt-get install -y python3 python3-venv python3.10-venv

# Python 3.12 + venv (CHASE needs ≥ 3.12)
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get install -y python3.12 python3.12-venv

# uv (CHASE dep manager; ALSO fallback when python3-venv is unavailable)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Deno (CHASE shells out to deno for langchain-sandbox)
curl -fsSL https://deno.land/install.sh | sh

# Claude CLI (chanever's verifier)
# Follow https://docs.anthropic.com/claude/docs/claude-cli
# After install, run: claude login
```

Environment variable needed in your shell before running setup:

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # for CHASE; not needed for chanever
```

Add yourself to docker group if not already: `sudo usermod -aG docker $USER`
and log out / back in.

---

## Step 1 — Set up chanever itself

```bash
git clone https://github.com/chanever/agent_security_framework
cd agent_security_framework

# Python deps for the bench harness + reputation/static modules
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
# If the python3 -m venv step fails with "ensurepip is not available", you're
# missing the python3-venv apt package. Either install it (see prereqs above)
# or use uv as a fallback:
#   uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt

# Populate downloadable corpora (~10 min, ~500 MB)
bash bench/setup_corpora.sh

# Build the shadow sandbox docker image
docker build -t shadow-agent-sandbox:latest -f sandbox/Dockerfile sandbox/
```

The `chase_compatible_ben` corpus (23 packages, 11 MB) is shipped
committed under `bench/corpora/chase_compatible_ben/` so the head-to-head
comparison is reproducible without re-sampling PyPI RSS (which is a
moving window).

---

## Step 2 — Reproduce the chanever full census

```bash
SECURITY_FRAMEWORK_ENABLED=true SHADOW_SANDBOX_ENABLED=true \
SECURITY_STATIC_ANALYSIS_ENABLED=true SECURITY_REPUTATION_ANALYSIS_ENABLED=true \
VERIFIER_MODE=claude_cli SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
CLAUDE_CLI_MAX_TURNS=12 \
python bench/framework_reliability.py --cap 0 \
    --out /tmp/framework_reliability_full_census.json
```

Reference: `expected_outputs/chanever_full_census_results.json` —
TP 146 / TN 145 / FP 3 / FN 7 / ERR 1; F1 96.7 %. Verifier LLM
nondeterminism: expect ≤ 2 % drift on the headline metrics.

---

## Step 3 — Set up the three baselines

```bash
bash bench/reproduction/setup.sh
```

Clones CHASE / MalPacDetector / ClawVet next to this repo, builds
each baseline's venv with the version pins we hit during development,
and downloads CHASE's public `lxyeternal/pypi_malregistry` 500-pkg
malicious dataset.

Per-baseline install detail and the source repos:

- `baselines/CHASE.md` — github.com/t0d4/CHASE-AIware25, uv-managed, Python ≥ 3.12
- `baselines/MalPacDetector.md` — github.com/CGCL-codes/MalPacDetector-core, sklearn 1.2.2
- `baselines/ClawVet.md` — github.com/MohibShaikh/clawvet, Node + tsx

---

## Step 4 — Run the head-to-head benches

```bash
bash bench/reproduction/reproduce_all.sh
```

Total wall time ≈ 6 h on the reference machine. Each wrapper supports
`--resume` so partial runs continue from the last checkpoint.

| Bench | Wrapper | Reference output |
|-------|---------|------------------|
| chanever on CHASE dataset | `bench/run_chanever_on_chase_dataset.py` | `expected_outputs/chanever_on_chase_results.json` |
| Head-to-head benign | `bench/run_chase_vs_chanever_small.py` | `expected_outputs/chase_vs_chanever_small_results.json` |
| CHASE on our benign-pypi | `bench/run_chase_bench.py` | `expected_outputs/chase_on_benign_pypi_results.json` |
| ClawVet on skills | `bench/run_clawvet_bench.py` | `expected_outputs/clawvet_skill_results.json` |
| MalPacDetector on npm | `bench/reproduction/run_malpacdetector.sh` | `expected_outputs/malpacdetector_npm_results.json` |

---

## Step 5 — Re-render the charts

```bash
python bench/reproduction/render_charts.py \
    --in /tmp/reproduction \
    --out /tmp/charts
```

Writes 5 PNGs (one per framework + a head-to-head + F1 panel) and one
3000-case CHASE paper chart that's static (no JSON dependency). Compare
visually against `expected_outputs/charts/`.

---

## What's *not* deterministic

Both chanever and CHASE include an LLM in the decision loop, so a
re-run will not be byte-identical to the reference JSON:

- Verifier text (`reason` field) varies even when the decision is the same.
- Edge cases sit close to the allow/block boundary — expect ≤ 2 % drift
  in F1 / DSR / specificity headline numbers.
- CHASE's web-research step uses DuckDuckGo; rate limits can change
  which cases ERR.

The MalPacDetector RF classifier (pretrained `models/RF.pkl`) and
ClawVet's rule pack are deterministic — their per-row outputs should
match the reference exactly.

---

## Companion documents

- `expected_outputs/chase_fp_analysis.md` — where chanever loses FPs to
  CHASE on benign packages, broken down by root cause category
- `expected_outputs/QA_module_explanation.{md,pdf}` — Q&A on how the
  static analyzer and reputation modules work (Korean)
