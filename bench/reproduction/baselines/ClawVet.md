# ClawVet

**Source**: github.com/MohibShaikh/clawvet
**License**: MIT (open-source)
**Language**: TypeScript / Node

## What it is

A 6-pass static scanner for LLM-agent skill / tool manifests
(OpenClaw, MCP). Each pass applies a separate rule pack:

1. Prompt-injection phrases / instruction smuggling
2. Permission escalation patterns
3. External URL / network fetch
4. Filesystem write outside declared scope
5. Tool-hijacking patterns
6. Secret / credential exfiltration

Each finding gets a severity (`low | medium | high | critical`). The
overall package risk is the max severity across passes. The CLI's
`--fail-on high` policy is the bench's block-vs-allow decision boundary:
HIGH or CRITICAL → block; otherwise allow.

## How we ran it

### Install

Plain `npm install` in the cloned repo. No special version pinning needed
on Node 18+. The bench invokes the scanner via:

```
npx tsx packages/cli/src/index.ts scan <skill-dir> --json
```

`tsx` is dev-dep, already in package.json.

### Running on chanever's skill / tool corpus

`bench/run_clawvet_bench.py` iterates chanever's panel for the four
relevant families and invokes ClawVet's CLI per case:

| Family | Label | Cases |
|--------|-------|------:|
| `skill-inject` | malicious | 40 |
| `toolhijacker` | mixed (6 mal + 5 ben paired) | 11 |
| `benign-skills` | benign | 20 |
| `benign-tools` | benign | 8 |

Decision policy: per the `--fail-on high` default — any HIGH or CRITICAL
finding → `block`, otherwise → `allow`.

### Determinism

Rule-based, no ML, no LLM. Per-row output is bit-deterministic given
the same code base; the JSON should match the reference exactly on
re-run unless ClawVet's rule pack is updated upstream.

## Numbers on our corpus

| Family | TP | FN | TN | FP |
|--------|---:|---:|---:|---:|
| `skill-inject` (40 mal) | 9 | 31 | – | – |
| `toolhijacker` (6 mal + 5 ben) | 4 | 2 | 5 | 0 |
| `benign-skills` (20 ben) | – | – | 18 | 2 |
| `benign-tools` (8 ben) | – | – | 7 | 1 |
| **Total** | **13** | **33** | **30** | **3** |

Recall 28.3 %, specificity 90.6 %, F1 38.6 %. The 31 missed
`skill-inject` cases are natural-language prompt injections that
ClawVet's substring rule pack does not pattern-match — those cases
need a model-in-the-loop verifier, which is what chanever's pipeline
adds on top.

## Outputs

Per-case stdout: ClawVet `--json` output. Aggregated: a chanever-shaped
results JSON at `$OUT_DIR/clawvet_skill.json` with per-row `risk_score`,
`risk_grade`, and `findings_count` preserved.
