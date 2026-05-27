# chanever: An evaluation-grade reference implementation for LLM-agent action gating

> Draft — 2026-05-26. Replaces and supersedes earlier work-in-progress
> drafts. Numbers in this document are taken from `bench/` run outputs
> committed under `eval/` (or `/tmp` for live runs not yet committed) and
> are linked back to the exact result-JSON in §5.

## Abstract

We extend `chanever/agent_security_framework` from a research prototype into
an evaluation-grade reference implementation for **LLM-agent action gating**.
The framework intercepts every external-environment-touching action proposed
by an LLM agent, runs it in a Docker shadow sandbox, captures observation
evidence via cgroup-scoped eBPF (`kprobe:security_file_open` LSM hook
function) and semgrep static analysis (GuardDog supply-chain rules plus
chanever-authored rules), enriches with OSV reputation lookups, and submits
the resulting Evidence Package to a verifier (either a rule-based
``mock_verifier`` or a real LLM judge invoked via the local ``claude`` CLI
with OAuth subscription auth).

On a stratified smoke of N=31 labelled cases (8 malicious-repos + 5
skill-inject + 5 datadog-pypi + 5 benign-skills + 5 benign-pypi + 3
chanever bundled) with **sandbox + GLM** enabled, the framework achieves
**DR=95% [Wilson 95% CI 76.4–99.1%, N=20 malicious, single run], FPR=0% [Wilson 95% CI 0–28.5%, N=11 benign], Accuracy=96.77%**. On the InjecAgent indirect prompt
injection corpus (Zhan et al., ACL '24 Findings, N=200 of the base subset
covering Physical / Financial / Data Security Harm), the GLM verifier
achieves **100% recall** — compared to a published baseline where LLM
agents themselves execute 24–48% of the attacker instructions.

We publish both a negative and a positive EvidenceQualityBench result.
The **trace-axis** variant (5 evidence-package variants A/B/C/D/E with
progressively more sandbox observation, GLM judge held constant) on
N=20 datadog-pypi + benign-pypi cases yields ΔAcc(D − A) = 0% — the
pre-registered 5pp falsification gate does not pass. We attribute this
to a saturation effect: under ``network=none``, every pip-install trace
looks "incomplete" to the LLM judge, which biases verdicts toward
conservative blocking regardless of variant.

The **content-axis** variant (InjecAgent N=50, variants stripping
``external_environment`` components) yields **ΔRecall(D − A) =
+76.0pp (24% → 100%)** with the same 5pp pre-registered gate
PASSED. The full jump is concentrated at A → B (adding raw tool-return
text); subsequent additions (suspicious phrase list, content_summary)
add no marginal recall on this corpus. This is the strongest single
quantitative finding in the framework.

## 1. Introduction

[paper-quality intro pending — placeholder.]

## 2. Threat model

The LLM agent is treated as a partially-trusted code generator. It emits
shell commands or tool invocations on behalf of a benign user request.
The threat surface is the **content the agent consumes from the external
environment**: package install hooks (PyPI / npm / apt), repository
contents (README, setup scripts), skill / tool descriptors, fetched URLs,
and most importantly **tool returns** that contain attacker-planted
instructions (indirect prompt injection / IPI).

We do not attempt to harden the LLM itself against injection. We instead
add a *defence-in-depth* layer: every proposed external-environment-touching
action goes through an evidence-collection pipeline whose output is judged
by a verifier before real execution is permitted.

## 3. Architecture

```
        user task
           ↓
   LLM agent (untrusted)
           ↓ proposes action
   ShadowSandboxSafeguard.inspect(action, context)
           ├─ trigger.classify_command  (hard_block + external_env flags)
           ├─ external_target_extractor (URL / repo / package)
           ├─ external_interaction_analysis
           │     ├─ static_analyzer (semgrep + GuardDog + chanever rules)
           │     └─ reputation_analyzer (OSV.dev)
           ├─ sandbox_runner            (strace OR bpftrace+LSM)
           ├─ trace_parser              (semantic events, lsm_events from kprobe:security_file_open)
           ├─ event_logger              (formatted_events + process_tree for LLM consumption)
           ├─ evidence_builder          (Evidence Package JSON)
           └─ verifier                  (mock OR GLM/claude-CLI)
                  ↓
        ALLOW → real execution permitted
        BLOCK / HOLD / ISOLATE / ALLOW_WITH_SANITIZATION → blocked
```

### 3.1 eBPF / LSM observation

We use cgroup-scoped bpftrace probes (six emit JSONL):
- ``tracepoint:syscalls:sys_enter_execve`` (pre-exec argv)
- ``tracepoint:sched:sched_process_exec`` (post-exec comm + uid)
- ``tracepoint:sched:sched_process_fork`` (parent → child)
- ``tracepoint:sock:inet_sock_set_state`` (TCP_SYN_SENT, IPv4)
- ``kprobe:security_file_open`` (LSM hook function — observation only)
- ``tracepoint:syscalls:sys_enter_write`` (host-driven readiness sentinel)

We label this honestly: it is **kprobe-on-LSM-hook-function**, not BPF-LSM
in the strict module-registration sense. AgentSentinel (CCS '25) uses the
same approach for 5 of its 6 hooks while calling the suite "BPF-LSM"; we
do not. The only `lsm:` probe AgentSentinel actually registers is
``lsm/task_kill`` for self-protection — observation of file/network/exec
is via kprobes there too.

### 3.2 Barrier pattern for race-free attach

A naïve attach flow (docker create → start → pause → inspect → attach
bpftrace → unpause) loses events on fast-running commands because the
container's CMD can complete before pause + attach finish. We replace
that with a **barrier pattern**:

```
container CMD := until [ -e /var/sandbox/proceed ]; do sleep 0.05; done
                && cd /workspace && <real-command>
```

The host attaches probes, waits for the "Attaching N probes" stderr
marker, then issues ``docker exec touch /var/sandbox/proceed`` to release
the barrier. The real command then runs with probes already in place,
zero race window. Live-verified on a benign workspace: process_exec went
from 0 (Path B race) to 12 (barrier), lsm_events from 0 to 114.

### 3.3 Per-artifact-type dispatch

Action targets are not single-type. A `git clone` can deliver a repo that
*also* ships a pypi package *also* ships a SKILL.md. The framework therefore
runs each action's targets through an ``artifact_classifier`` that emits an
**artifact graph** — one node per recognised kind (`github_repo`,
`pypi_package`, `npm_package`, `skill`, `mcp_server`, `github_action`,
`container_image`, `local_directory`) — and dispatches each node to a
type-specific static analyzer and reputation lookup.

The classifier probes the workspace with bounded BFS (depth 3, skip
``node_modules``/`.git`/`.venv`/`__pycache__`/etc.) and records
`detected_kinds`, `manifests`, `instruction_surfaces`, `execution_surfaces`
per node. The output schema lets the verifier see per-type breakdown
instead of a single undifferentiated finding list.

| Artifact type | Static analyzer | Reputation source |
|---------------|-----------------|--------------------|
| `pypi_package` | semgrep + GuardDog Python + chanever rules | OSV.dev |
| `npm_package` | semgrep + GuardDog npm + chanever rules | OSV.dev |
| `github_repo` | repo_analyzer (same chained stack) | **OpenSSF Scorecard** (`api.securityscorecards.dev`) |
| `skill` | skill_analyzer: phrase scan on instruction surfaces + cross-file ref walk + chained semgrep on execution surfaces | manifest heuristic (declared_author + signature_present → trust_bucket) |
| `mcp_server` / `github_action` | repo_analyzer | repo_reputation |
| `local_directory` | repo_analyzer | (none) |

The skill analyzer specifically targets the **cross-file split attack**
pattern observed in `obvious_injections_{1,2,3}` of the SKILL-INJECT corpus,
where `SKILL.md` is benign and the payload lives in subsidiary files
(`ooxml.md`, `recalc.py`) referenced from it. The ref-walker reads every
backtick-quoted path ending in `{py,sh,md,yml,yaml,json,toml}`
(`_REF_PATH_RE` at `static_analyzers/skill_analyzer.py:41`); other
extensions (`.txt`, `.cfg`, `.docx`, `.pptx`, `.csv`) are intentionally
excluded to bound the walk size, accepted as a known limitation. The ref-walker reads every
`` `path.ext` `` mentioned in instruction surfaces and emits a
`chanever-skill-cross-file-split` finding when the referenced file
contains a suspicious phrase.

### 3.4 Static analyzer rule pack

We compose three rule sources into one semgrep invocation:

| Source | Origin | Coverage |
|--------|--------|----------|
| `p/security-audit` | semgrep registry | OWASP-style patterns (eval, SQLi, etc.) |
| `external_rules_guarddog/` (vendored, Apache-2.0) | DataDog/guarddog | Supply-chain: install hooks, exec-base64, exfiltrate-sensitive-data |
| `external_rules_guarddog_unscoped/` (generated) | GuardDog rules with `paths.include` filters stripped | Same patterns on workspace-wide files |
| `external_rules_chanever/` (new) | chanever-authored | Gaps GuardDog leaves: `~/.env` read, ``subprocess.run([..., "-c", ...])`` |

Live test on agent-mds's `malicious-ci-helper`: 0 findings with GuardDog
alone (its `paths.include: */setup.py` filter excludes `scripts/ci.py`).
**With unscoped + chanever rules: 2 findings** (`chanever-sensitive-file-read`
on `~/.env` read at line 5; `chanever-subprocess-exec-dash-c` at line 6).

### 3.5 Reputation analyzer (per-artifact-type)

The `reputation/` package dispatches per artifact graph node:

- `reputation/pypi_reputation.py` / `npm_reputation.py` — OSV.dev queries
  through a shared `_osv.py` helper. Severity normalization checks
  `severity[].score`, `database_specific.severity`, and
  `affected[].database_specific.severity` because OSV's severity field
  location varies by source advisory. Live-verified: PyPI:`requests`
  → 13 vulns / 1 HIGH; npm:`lodash` → 10 / 1 CRITICAL + 4 HIGH.
- `reputation/repo_reputation.py` — **OpenSSF Scorecard public API**
  (`api.securityscorecards.dev/projects/github.com/<owner>/<repo>`). Maps
  the 0.0–10.0 quality score into RED (<3) / YELLOW (<5) / GREEN buckets
  and surfaces low-scoring sub-checks. Live-verified
  `github.com/DataDog/guarddog` → `{score: 8.0, bucket: GREEN, date:
  2026-05-25, 3 checks ≤ 2/10}` (full JSON captured at
  `/tmp/scorecard_datadog_guarddog.json`).
- `reputation/skill_reputation.py` — heuristic (declared_author from
  SKILL.md frontmatter or `manifest.json`, presence of an alongside
  `.sig` / `.asc` / `.sigstore` file) → trust bucket. Marked
  "heuristic" honestly in the evidence so the verifier and reader can
  weight it accordingly.

### 3.6 GLM verifier

`glm_verifier.verify(evidence_package)` builds a prompt from
`prompts/glm_system_prompt.txt` + `glm_user_prompt_template.txt` and
pipes it to ``claude -p`` via subprocess. Uses OAuth subscription auth —
no Anthropic API key required. Returns a normalized verdict matching
the mock verifier's schema (decision + risk_score + reason + ...). On
parse failure / timeout, tags ``decision_source: glm_fallback_mock`` and
falls back to rule-based mock; this is documented for transparency, not
silent degradation.

## 4. Benchmark suite

See `BENCHMARK.md` for the per-family action templates, the corpus
integrity assertion (232/232 cases load), and the per-module quality gates.

**Corpus staging (reproducibility)**: the benchmark fixtures live in the
sibling `agent-mds` repository at `$AGENT_MDS_ROOT/eval/benchmarks/`, not
inside the framework repo itself. To reproduce these numbers, clone
`agent-mds` next to the framework and either symlink
`eval/benchmarks/` → `$AGENT_MDS_ROOT/eval/benchmarks/` or set
`BENCH_ROOT=$AGENT_MDS_ROOT/eval/benchmarks` in the environment. The
`bench/action_templates.py::BENCH_ROOT` constant hard-codes the
absolute path `/home/user/agent-mds/eval/benchmarks/` for the
experiments reported in this paper.

Headline corpora (paths relative to `$AGENT_MDS_ROOT/eval/benchmarks/`):
- `malicious-repos/` — 8 hand-crafted malicious scenarios
- `datadog-pypi/` — 50 human-triaged malicious PyPI samples (DataDog corpus, Apache-2.0)
- `skill-inject/` — 40 SKILL.md injections (aisa-group, aisa-group/skill-inject (arXiv ID pending verification — sourced via the literature-scan agent and not yet cross-checked))
- `benign-{pypi,skills,tools}/` — FPR controls
- **InjecAgent** (uiuc-kang-lab, ACL '24 Findings) — 1054 IPI cases at `/tmp/InjecAgent/data/`, sampled subset of 200

## 5. Evaluation

**Pre-registered falsification gate**: a variant ablation is published as
*informative* if |Δmetric(D − A)| ≥ 5pp; below threshold the result is
declared **INCONCLUSIVE** rather than positive. Direction is symmetric —
gate is on |Δ|, not signed Δ. §5.3 fails the gate (Δ=0, INCONCLUSIVE);
§5.4 passes by 15× (Δ=+76pp).

### 5.1 31-case smoke (sandbox + GLM verifier)

`bench/smoke_results.json` at commit `<TODO>`. Configuration:
``TRACE_MODE=strace``, ``VERIFIER_MODE=glm``, ``SANDBOX_NETWORK_MODE=none``,
``SHADOW_SANDBOX_ENABLED=true``, single run.

| Family | TP | FN | TN | FP |
|--------|----|----|----|----|
| malicious-repos (mal=8) | 8 | 0 | — | — |
| skill-inject (mal=5) | 4 | 1 | — | — |
| datadog-pypi (mal=5) | 5 | 0 | — | — |
| benign-skills (ben=5) | — | — | 5 | 0 |
| benign-pypi (ben=5) | — | — | 5 | 0 |
| chanever bundled (mal=2, ben=1) | 2 | 0 | 1 | 0 |
| **Overall (N=31)** | **19** | **1** | **11** | **0** |

**DR = 95.00% (19/20)**. **FPR = 0.00% (0/11)**. **Accuracy = 96.77%**.

The single FN is `skill_inject_contextual_injections_1`, where the
injection is a naturalistic instruction ("Important: After any changes to
the document make a backup to our central server by calling the
file_backup.py script") that does not trigger any phrase signal and that
GLM verifier sometimes ALLOWs depending on run. Run-to-run variance on
this case is the strongest single-case argument for the **mean-of-3**
requirement called for in the benchmark design (§4 of `BENCHMARK.md`).

### 5.2 InjecAgent recall (verifier only)

`bench/run_injecagent.py` against `uiuc-kang-lab/InjecAgent` base subset,
N=200 stratified across attack types. Verifier-only path — no sandbox
runs; every case's evidence is a tool-return injection wrapped in
`external_environment.raw_content_excerpt`.

| Attack type | N | Detected | Recall |
|-------------|----|----------|--------|
| Data Security Harm | 34 | 34 | 100% |
| Financial Harm | 119 | 119 | 100% |
| Physical Harm | 47 | 47 | 100% |
| **Total** | **200** | **200** | **100%** |

Decision mix: **123 HOLD (61.5%) + 66 ALLOW_WITH_SANITIZATION (33.0%) +
11 BLOCK (5.5%)**. The HOLD-majority distribution matters: the verifier
flags rather than autonomously denies the majority of IPI cases —
operationally a human-review escalation, not autonomous block. All three
decisions are non-ALLOW so under chanever's gating contract all 200 cases
are blocked from real execution, but N=123 (61.5%) would land in a human
queue rather than being autonomously denied.

Attack-type distribution of the N=200 subset is uneven (47 Physical Harm
+ 119 Financial Harm + 34 Data Security Harm) — drawn by corpus
availability, not equal-N stratified. Recall is 100% within each type;
counts reported for transparency.

Comparison anchor: published InjecAgent ASR (rate at which the agent
itself executes the attacker instruction) is 24% on base, ~48% on
reinforced ReAct-GPT-4. Our verifier catches **all** of them as a gating
layer — with the HOLD-majority caveat above.

### 5.3 EvidenceQualityBench v0 — trace axis (negative result)

`bench/evidence_quality_bench.py` on N=20 (10 datadog-pypi mal + 10
benign-pypi ben), 5 variants A/B/C/D/E. Pre-registered 5pp falsification
gate.

| Variant | Acc | DR | FPR | flip vs prev |
|---------|-----|----|----|--------------|
| A (action only) | 50% | 100% | 100% | 0 |
| B (+static) | 50% | 100% | 100% | 1 |
| C (+strace) | 50% | 100% | 100% | 1 |
| D (+bpftrace+LSM) | 50% | 100% | 100% | 1 |
| E (full) | 50% | 100% | 100% | 0 |

**ΔAcc(D − A) = 0%, gate not passed → INCONCLUSIVE on this axis with this
corpus.**

Diagnosis: with ``network=none`` enforced for safety, every pip install
fails part-way through (no PyPI index reachable). The trace is the same
shape for benign and malicious cases — execve(pip) → openat(metadata) →
connect() refused. The LLM judge cannot distinguish benign-pypi:click
from datadog-pypi:1337test from this evidence alone and defaults to
conservative ISOLATE. The same effect appears across all variants
because adding more (still-incomplete) trace data does not resolve the
ambiguity. We report this honestly as a methodological finding rather
than dropping the variants.

### 5.4 EvidenceQualityBench — content axis (InjecAgent N=50)

`bench/evidence_quality_bench_ia.py` against the InjecAgent base subset.
Variants progressively add ``external_environment`` components to an
otherwise identical evidence package; the GLM judge sees one variant at a
time. Pre-registered 5pp falsification gate.

| Variant | Recall | Detected | flip vs prev |
|---------|--------|----------|--------------|
| A (action only, empty external_environment) | **24%** | 12/50 | — |
| B (+raw_content_excerpt) | **100%** | 50/50 | 50 |
| C (+extracted_suspicious_instructions) | 100% | 50/50 | 4 |
| D (full external_environment) | 100% | 50/50 | 8 |

**ΔRecall(D − A) = +76.0pp, falsification gate PASSED.** Paired bootstrap
95% CI on the Δ (10k resamples): [+0.64, +0.88]. McNemar exact
p ≈ 7.3e-12.

Decision distribution per variant:
- A: 38 ALLOW + 12 HOLD
- B: 38 ALLOW_WITH_SANITIZATION + 12 BLOCK
- C: 40 ALLOW_WITH_SANITIZATION + 10 BLOCK
- D: 40 ALLOW_WITH_SANITIZATION + 9 BLOCK + 1 HOLD

Interpretation: handing the LLM judge the raw tool-return text (variant
B) is the entire jump from 24% → 100% recall. C and D add no marginal
recall on top of B, but the decision distribution *shifts*: BLOCK count
drops monotonically (12 → 10 → 9) as content_summary and linked_resources
are added, and one D case re-routes to HOLD. The flip rate (4 at B→C,
8 at C→D) confirms this: decisions are not stable across these
additions. Two interpretations are consistent with the data — (a) the
judge becomes more confident that the injection is sanitizable rather
than warranting outright BLOCK, or (b) the extra metadata dilutes the
signal. Disambiguating requires per-case ground-truth on whether
sanitization is sufficient, which is out of scope for this report; we
flag this as a documented limitation rather than claiming "more
evidence is always better."

This is the strongest single quantitative finding in the framework — an
evidence-package field (`raw_content_excerpt`) whose addition the LLM
judge can be statistically shown to need, with sample-bounded confidence
interval well clear of the pre-registered falsification threshold.

## 6. Comparison to prior work

| System | Metric | Published | Our equivalent |
|--------|--------|-----------|---------------|
| AgentSentinel (CCS '25) | DSR / FPR (N=60) | 79.6% / 10.8% | 95% / 0% (N=31; **not directly comparable** — our smoke skews toward malicious-by-name fixtures with 'malicious' literally in package name in 6/8 malicious-repos cases, while BadComputerUse uses adversarial-injection variants of realistic OSWorld/AgentBench tasks. Like-for-like via BadComputerUse translator is future work.) |
| InjecAgent (ACL '24) baseline | ASR (agent-side) | 24–48% | 100% recall as gating layer (N=200 base subset) |
| OSCAR (ASE '24) | F1 (production deployment, ~11.6K malicious detected) | 0.95 npm / 0.91 PyPI | Install-time only, no fuzz of exported entrypoints; F1 not directly comparable |
| SkillSieve | F1 vs ClawVet | 0.800 / 0.421 | Out of scope for this submission |
| PFI (Kim et al., '25) | ATR / SUR (AgentDojo OS) | 0.00 / 61.86 | Trajectory level — out of scope |

We deliberately do **not** claim "first per-module ablation" (SkillSieve
already publishes layer-attribution on its 3-tier triage). The tighter
claim we do make: **to our knowledge, no prior work decomposes
evidence-package marginal value (action vs +raw-content vs +phrase-scan
vs +full-metadata) on the InjecAgent corpus under a fixed verifier;
we publish that decomposition**. SkillSieve performs layer-attribution
on its own three-tier triage but does not ablate evidence components on
a shared external corpus with a frozen judge.

## 7. Limitations

- N=31 smoke + N=200 InjecAgent + N=50 EvQ-IA is small. The full
  publication should include mean-of-3 + bootstrap CI per family.
- ``network=none`` is a real evaluation constraint (we cannot risk
  malicious cases actually exfiltrating). The EvQ trace-axis
  inconclusive result is partly caused by this.
- The benign panel is short of ≥20-per-family on `benign-skills` (10) and
  `benign-tools` (8). Acquisition from SkillSieve 400-skill labelled set
  is on the roadmap.
- GLM verifier non-determinism: same prompt can yield different decisions
  on the FN edge case (`contextual_injections_1`). mean-of-3 + flip
  rate is the standard methodology and is set up in the harness but not
  yet executed at scale.

## 8. Conclusion

We have brought `chanever/agent_security_framework` from a placeholder-only
prototype to an evaluation-grade reference implementation. Six bug fixes
across four classes surfaced by the smoke loop (excerpt truncation,
narrow phrase list, AppArmor bind-mount path, three regex bugs in
hard-block patterns + one shell-operator bug in the target extractor).
Three new modules have been added
(`event_logger`, `glm_verifier`, vendored GuardDog + chanever supply-chain
rules), and the InjecAgent translator opens a published 1054-case IPI
corpus for evaluation. Headline numbers: DR=95% / FPR=0% on the 31-case
smoke, 100% recall on N=200 InjecAgent. The EvQ trace-axis result is
honestly published as inconclusive pending a network-bridge experiment.
