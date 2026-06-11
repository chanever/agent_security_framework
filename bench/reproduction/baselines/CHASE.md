# CHASE — Collaborative Hierarchical Agents for Security Exploration

**Paper**: Toda & Mori, AIware 2025, arXiv:2601.06838
**Source**: github.com/t0d4/CHASE-AIware25
**License**: MIT (paper authors' implementation)

## What it is

A multi-agent LLM pipeline for malicious-PyPI-package detection:

| Agent | Role | Default model |
|-------|------|---------------|
| Supervisor | Plans the inspection sequence | Qwen3-32B |
| Worker × 2 | Deobfuscator + Web Researcher | Qwen3-8B |
| Formatter | Structures the final verdict (`malicious` / `benign`) | Gemma3-4B |

The pipeline reads `setup.py` + top-level `__init__.py` of an unpacked
PyPI package, the Supervisor delegates analysis tasks to Workers, and
the Formatter emits a structured JSON verdict the chanever wrapper
reads back.

Paper-reported numbers on its own 3000-pkg corpus (lxyeternal/pypi_malregistry
mal + custom benign): recall 98.4 %, FP rate 0.08 %, F1 99.19 %.

## How we ran it

CHASE supports three LLM runners: `ollama`, `sglang`, `anthropic`. We
used `anthropic` (no local GPU required) — this dispatches to the
Anthropic API via `langchain-anthropic`. Each case spends 6–10 API
calls + a handful of DuckDuckGo searches, ≈ 3–5 minutes wall time.

## Setup

The repo is uv-managed (pyproject.toml + uv.lock, `requires-python ≥ 3.12`).
`bench/reproduction/setup.sh` handles it:

```bash
git clone --depth 1 https://github.com/t0d4/CHASE-AIware25 ../chase
git apply --whitespace=nowarn .../patches/chase.patch       # adds anthropic runner
( cd ../chase && uv sync --frozen )
```

### The `chase.patch` we ship

CHASE upstream supports only `ollama` and `sglang` runners — both require
a local GPU to host Qwen3-32B. We added a third runner `anthropic` that
dispatches Supervisor + Workers to Claude Sonnet 4.6 and the Formatter
to Claude Haiku 4.5 via `langchain-anthropic`, so the bench is runnable
without a GPU. The patch lives at
`bench/reproduction/baselines/patches/chase.patch` and touches three files:

- `pyproject.toml` — adds `langchain-anthropic>=0.3.22` to deps
- `run_chase.py` — adds the `"anthropic"` branch in `prepare_llms()`
  plus the matching argparse choice
- `uv.lock` — regenerated lockfile (so `uv sync --frozen` produces the
  same env we used)

The patch was verified to apply cleanly against upstream HEAD as of the
commit shipped in `bench/reproduction/baselines/patches/`. `setup.sh` is
idempotent — re-running it skips the patch if `"anthropic"` is already
in `run_chase.py`.

`uv sync --frozen` then reads the patched `uv.lock` and creates
`../chase/.venv` with exactly the dependency versions the paper authors
used + our `langchain-anthropic` addition.

You also need:

- **Anthropic API key** in `../chase/.env` (the setup script writes a
  template if `ANTHROPIC_API_KEY` is already in your shell env)
- **Deno** on `PATH` — `langchain-sandbox` shells out to deno

## Running on our corpus

Invoke through `bench/run_chase_bench.py`. The wrapper:
- Uses chanever's panel construction so the case set matches
  `framework_reliability.py` exactly
- Filters to PyPI families only — CHASE inspects setup.py / Python source,
  so npm / repo / skill families are out of CHASE's threat model
- Maps `final_verdict` (malicious | benign) → chanever's `block` | `allow`

For modern PyPI packages shipped with `pyproject.toml` only (no `setup.py`),
CHASE's `collect_entrypoint_sourcecodes` raises
`ValueError: min() iterable argument is empty`. Our wrapper detects this
and marks those cases `ERR` with note `out of CHASE scope (no setup.py …)`.

## Running on CHASE's own dataset

`bench/run_chanever_on_chase_dataset.py` walks
`$PARENT/pypi_malregistry/<pkg>/<ver>/*.{tar.gz,whl}` and feeds each
unpacked artifact to chanever's `safeguard.inspect()`. Some of the
"`.tar.gz`" files are actually ZIP wheels (file magic `PK..`) — our
unpacker tries gzip first, falls back to `zipfile.ZipFile`.

## Cost expectations (Anthropic API)

Per-case cost: ~$0.10–0.30 (Claude Sonnet for Supervisor + Workers,
Haiku for Formatter). On Anthropic Tier 1 (30k input tokens / minute)
large packages will rate-limit; the wrapper marks those `ERR` and they
can be re-run after the token-bucket refills.

## Outputs

CHASE writes a `text-final-summary.md` + `structured-final-summary.json`
into the package's scan directory. Our wrapper reads only the JSON.
