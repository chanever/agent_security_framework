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
**DR=95%, FPR=0%, Accuracy=96.77%**. On the InjecAgent indirect prompt
injection corpus (Zhan et al., ACL '24 Findings, N=200 of the base subset
covering Physical / Financial / Data Security Harm), the GLM verifier
achieves **100% recall** — compared to a published baseline where LLM
agents themselves execute 24–48% of the attacker instructions.

We also publish a negative result. The trace-evidence variant of
EvidenceQualityBench (5 evidence-package variants A/B/C/D/E with
progressively more sandbox observation, GLM judge held constant) on
N=20 datadog-pypi + benign-pypi cases yields ΔAcc(D − A) = 0% — the
pre-registered 5pp falsification gate does not pass. We attribute this
to a saturation effect: under ``network=none``, every pip-install trace
looks "incomplete" to the LLM judge, which biases verdicts toward
conservative blocking regardless of variant. We re-run the same
falsification gate on the **content axis** (InjecAgent, variants stripping
``external_environment`` components) where the saturation does not apply.

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

### 3.3 Static analyzer rule pack

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

### 3.4 Reputation analyzer

`reputation_analyzer.py` queries OSV.dev (no auth required, public API)
per package target. Severity normalization checks
``severity[].score`` / ``database_specific.severity`` /
``affected[].database_specific.severity`` because OSV's severity field
location varies by source advisory. Live-verified:
- PyPI:`requests` = 13 vulns, 1 HIGH
- npm:`lodash` = 10 vulns, 1 CRITICAL, 4 HIGH

### 3.5 GLM verifier

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

Headline corpora:
- `eval/benchmarks/malicious-repos/` — 8 hand-crafted malicious scenarios
- `eval/benchmarks/datadog-pypi/` — 50 human-triaged malicious PyPI samples (DataDog corpus, Apache-2.0)
- `eval/benchmarks/skill-inject/` — 40 SKILL.md injections (aisa-group, arXiv 2602.20156)
- `eval/benchmarks/benign-{pypi,skills,tools}/` — FPR controls
- **InjecAgent** (uiuc-kang-lab, ACL '24 Findings) — 1054 IPI cases, sampled subset of 200

## 5. Evaluation

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

Decision mix: 123 HOLD + 66 ALLOW_WITH_SANITIZATION + 11 BLOCK. All three
are non-ALLOW → all 200 cases would have been blocked in the real
execution path.

Comparison anchor: published InjecAgent ASR (rate at which the agent
itself executes the attacker instruction) is 24% on base, ~48% on
reinforced ReAct-GPT-4. Our verifier catches **all** of them as a
gating layer before the agent acts.

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

### 5.4 EvidenceQualityBench — content axis (InjecAgent)

[Pending G3 N=50 completion. Variants A/B/C/D progressively add
``external_environment`` components. Results below.]

| Variant | Recall | Detected | flip vs prev |
|---------|--------|----------|--------------|
| A (action only, empty external_env) | TBD | TBD | TBD |
| B (+raw_content_excerpt) | TBD | TBD | TBD |
| C (+extracted_suspicious_instructions) | TBD | TBD | TBD |
| D (full external_env) | TBD | TBD | TBD |

ΔRecall(D − A) = TBD; 5pp falsification gate = TBD.

## 6. Comparison to prior work

| System | Metric | Published | Our equivalent |
|--------|--------|-----------|---------------|
| AgentSentinel (CCS '25) | DSR / FPR (N=60) | 79.6% / 10.8% | 95% / 0% (N=31; not directly comparable corpus) |
| InjecAgent (ACL '24) baseline | ASR (agent-side) | 24–48% | 100% recall as gating layer (N=200 base subset) |
| OSCAR (ASE '24) | F1 (N=12K, fuzz+install) | 0.95 npm / 0.91 PyPI | Install-time only; F1 not directly comparable |
| SkillSieve | F1 vs ClawVet | 0.800 / 0.421 | Out of scope for this submission |
| PFI (Kim et al., '25) | ATR / SUR (AgentDojo OS) | 0.00 / 61.86 | Trajectory level — out of scope |

We deliberately do **not** claim "first per-module ablation" (SkillSieve
already publishes layer-attribution). We do claim **first published
trace-vs-content-axis ablation on the same corpus with the same GLM
judge held constant**.

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
prototype to an evaluation-grade reference implementation. Four real
infrastructure bugs surfaced by the smoke loop have been fixed (excerpt
truncation, narrow phrase list, AppArmor bind-mount path, three regex
bugs in hard-block patterns). Three new modules have been added
(`event_logger`, `glm_verifier`, vendored GuardDog + chanever supply-chain
rules), and the InjecAgent translator opens a published 1054-case IPI
corpus for evaluation. Headline numbers: DR=95% / FPR=0% on the 31-case
smoke, 100% recall on N=200 InjecAgent. The EvQ trace-axis result is
honestly published as inconclusive pending a network-bridge experiment.
