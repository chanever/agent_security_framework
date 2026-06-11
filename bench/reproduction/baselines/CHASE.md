# CHASE — Collaborative Hierarchical Agents for Security Exploration

**Paper**: Toda & Mori, AIware 2025, arXiv:2601.06838
**Source**: github.com/iydon/chase
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

### Install issues we hit (and patches we applied)

1. **semgrep wheel + Python 3.10 + glibc 2.31 incompatibility**
   CHASE's `requirements.txt` pins a recent semgrep whose `manylinux_2_34`
   wheel doesn't load on the host glibc. → built a venv with Python 3.12
   (`PY312` in `setup.sh`).

2. **`pkg_resources` removed in setuptools 81**
   Some CHASE deps still `import pkg_resources`. → pin `setuptools<81`
   (`setup.sh` does this).

3. **`.env` newline handling**
   When appending `ANTHROPIC_API_KEY` to `.env`, ensure a leading newline.
   `printf "\n%s\n"` form, not `echo >>`.

4. **Docker image's bundled semgrep is broken**
   The CHASE docker mode fails with
   `Failed to find semgrep-core in PATH or in the semgrep package`. Use
   the venv approach (set `--llm-runner anthropic`) instead. We do.

### Running on our corpus

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

### Running on CHASE's own dataset

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
