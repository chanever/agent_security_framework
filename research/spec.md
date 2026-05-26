# Phase 0 Spec — chanever framework benchmark + evaluation plan (v2)

Revised after critic review (2026-05-25, agent `a07ccb83`). Addresses all
P0 + P1 + key P2 findings. Source documents unchanged:

- `literature_scan.md` (16 papers, all live-fetched 2024–2026)
- `benchmark_design.md` (analyst review)
- `_notes_baseline_diagnostics.md` (skill-inject FN diagnosis)
- `bench/action_templates.py` (per-family templates; corpus integrity 232/232)

---

## 0. Phase 2 prerequisites (NEW — must complete before §7 starts)

| ID | Prerequisite | Owner | Status |
|----|--------------|-------|--------|
| Q0.1 | Build `shadow-agent-sandbox:latest` docker image from chanever Dockerfile | bench host | ✅ done 2026-05-25 |
| Q0.2 | Verify host bpftrace v0.19 + kprobe:security_file_open attachable | bench host | ✅ done 2026-05-25 |
| Q0.3 | Acquire ≥10 additional benign-skills cases (e.g., from SkillSieve 400-skill labelled set) to honor ≥20-benign commitment | corpus | ⏸ open |
| Q0.4 | Acquire ≥12 additional benign-tools cases | corpus | ⏸ open |
| Q0.5 | Acquire ≥15 benign-npm controls (currently 0; required for npm F1) | corpus | ⏸ open |
| Q0.6 | Write InjecAgent translator (~100 LOC) `bench/translators/injecagent.py` | code | ⏸ open |
| Q0.7 | Write R-Judge translator (~100 LOC) `bench/translators/rjudge.py` | code | ⏸ open |
| Q0.8 | Decide GLM verifier wiring status (blocks R5 ablation) | user | ⏸ open — §10 Q5 |
| Q0.9 | Pin `bench/action_templates.py` schema version so cross-row ablation comparability is preserved | code | ⏸ open |

---

## 1. Headline claim — revised after P0-1 finding

**Revised:**
> chanever is the **first LLM-agent security framework that publishes a
> strace-vs-bpftrace-`kprobe:security_file_open` ablation on a balanced
> benign panel**, with explicit per-observation-mode marginal contribution
> quantified via EvidenceQualityBench.

Two measurable sub-claims:
1. **Observation-mode ablation on a balanced panel**: R0 (strace) vs R4
   (bpftrace+kprobe-on-LSM-hook) on the same ≥20-benign-per-family corpus.
   Neither AgentSentinel (60-case total, 2 benign) nor agent-mds (2 benign
   in published report) nor SkillSieve (400 skills, no observation-mode
   axis) reports this.
2. **Marginal evidence value (EvidenceQualityBench)**: same LLM verifier
   sees 5 evidence-package variants (§5); ΔAccuracy(D, A) quantifies the
   value of `kprobe:security_file_open` over interaction-only judging.
   No prior published system measures this.

**Demoted to documentation framing** (not measurable, not a claim):
- "Methodological honesty" labeling (kprobe-on-LSM-function vs BPF-LSM).
  Acknowledged in README; not promoted to the headline.

Per-module attribution is **NOT** claimed novel — SkillSieve and
AgentSentinel both publish per-layer breakdowns. chanever's per-module
table is presented as standard reporting, not a contribution.

---

## 2. Prior-art landscape — calibrated targets, fuzz-vs-install scope explicit

| System | Benchmark | DR / DSR | FPR / FNR | Year | Comparable to chanever? |
|--------|-----------|----------|-----------|------|--------------------------|
| AgentSentinel (CCS '25, BadComputerUse) | 60 cases | DSR 79.6% | FPR 10.8%, FNR 4.2% | 2025 | Yes (translator needed for BadComputerUse) |
| OSCAR (ASE '24) supply-chain | ~12K pkgs, **fuzz testing + API hook + sandbox** | F1=0.95 npm, 0.91 PyPI | (production, ~18 mo Ant Group) | 2024 | **NOT directly** — chanever does install-time only, no fuzz of exported functions |
| SkillSieve | 400-skill labelled (ClawHub) | F1=0.800 | — | 2026 | Partial — skill family only |
| ClawVet (SkillSieve baseline) | same 400-skill | F1=0.421 | — | (prior to 2026) | Yes — direct baseline for chanever's skill-inject pipeline |
| PFI (Kim et al., '25) | AgentDojo OS / AgentBench-OS | SUR 61.86% / 68.42% | ATR 0.00% (deterministic) | 2025 | Different threat model (trajectory provenance), not action-level |
| R-Judge (EMNLP '24) | 569 multi-turn risk cases | GPT-4o judge acc 74.42% | — | 2024 | Yes — verifier upper-bound corpus |
| InjecAgent | 1054 IPI cases | ASR 24%→48% (LLMs hijacked) | — (corpus) | 2024 | Yes (translator → verifier-only) |
| BIPIA | 15 attack types × 5 instructions | white-box: ASR ~0% | — | 2023 | Yes — extends our phrase patterns |
| AgentDojo | 629 cases × 97 tasks | LLMs hijacked 20–60% | — | 2024 | Trajectory-level; out of scope for v1 |
| Spotlighting (datamarking) | various | ASR >50% → <2% | — | 2024 | Hardening recommendation for GLM verifier prompt |
| eBPF-PATROL | container syscall enforcement | reverse-shell / priv-esc blocked | <2.5% overhead | 2025 | Latency reference |
| AgentSight (PACMI '25) | TLS uprobe + kernel events | <3% overhead | — | 2025 | Latency reference |
| SandboxEscapeBench | container escape attempts | 67.57% kernel-blocked | — (corpus) | 2026 | Threat model we explicitly trust |

**Concrete targets (calibrated to chanever's scope — install-time only,
no fuzz of exported entrypoints):**

| Family | Target | Why not match OSCAR/SkillSieve verbatim |
|--------|--------|----------------------------------------|
| DataDog PyPI install-time | DR ≥ 0.80 with FPR ≤ 0.20 on ≥15 benign-pypi | OSCAR's F1=0.91 uses fuzz testing of exports; chanever does `pip install <pkg>` only. Install-time payloads (e.g. setup.py) are a subset of OSCAR's coverage. |
| DataDog npm install-time | DR ≥ 0.80 with FPR ≤ 0.20 on ≥15 **benign-npm (Q0.5)** | npm F1 currently unmeasurable — zero benign-npm cases on disk. Acquire ≥15 before reporting. |
| SKILL-INJECT (after §7 P0 fixes) | F1 ≥ 0.421 (beat ClawVet); aspire F1 ≥ 0.60 with mock_verifier | SkillSieve F1=0.800 needs 4-sub-task GLM decomposition; chanever's mock_verifier cannot match without GLM (R5 ablation). |
| BadComputerUse (after translator) | DSR ≥ 0.70 with FPR ≤ 0.15 | Stretch — AgentSentinel reports DSR 79.6%/FPR 10.8% but uses GLM judge. With mock_verifier we'll be lower. |
| R-Judge verifier-only | accuracy ≥ 0.65 with mock_verifier | R-Judge GPT-4o ceiling is 74.42%. With mock_verifier no realistic chance of matching; focus on Δ over baseline when GLM is wired. |

---

## 3. Benchmark suite — verified counts (P1-6 fix)

| Family | Source | Verified count | Headline N (mal / ben) | Action template |
|--------|--------|----------------|------------------------|------------------|
| malicious-repos | `agent-mds/eval/benchmarks/malicious-repos/` | 8 | 8 / 0 | `pip install .` |
| cloneguard-repos | `agent-mds/eval/benchmarks/cloneguard-repos/` | 40 | 30 / 0 (cap) | `pip install .` |
| datadog-pypi | `agent-mds/eval/benchmarks/datadog-pypi/` | 50 | 30 / 0 (cap) | `pip install <pkg>` |
| datadog-npm | `agent-mds/eval/benchmarks/datadog-npm/` | 50 | 30 / 0 (cap) | `npm install <pkg>` |
| benign-pypi | `agent-mds/eval/benchmarks/benign-pypi/` | 15 | 0 / 15 | `pip install <pkg>` |
| **benign-npm** | **needs Q0.5 acquisition** | **0** | **0 / 15 (after Q0.5)** | `npm install <pkg>` |
| skill-inject | `agent-mds/eval/benchmarks/skill-inject/` | 40 | 30 / 0 (cap) | `cat SKILL.md` |
| benign-skills | `agent-mds/eval/benchmarks/benign-skills/` | **10** | **10 / 0** in v1; **+10 via Q0.3** for ≥20 panel | `cat SKILL.md` |
| toolhijacker | `agent-mds/eval/benchmarks/toolhijacker/` | 11 | 6 mal / 5 ben | `cat tool.md` |
| benign-tools | `agent-mds/eval/benchmarks/benign-tools/` | **8** | **0 / 8** in v1; **+12 via Q0.4** for ≥20 panel | varies |
| gate-policy-controls | `agent-mds/eval/benchmarks/gate-policy-controls/` | 1 | regression | varies |
| **InjecAgent** | github (Q0.6 translator) | 1054 | cap 200 | tool-return injection |
| **R-Judge** | EMNLP '24 (Q0.7 translator) | 569 | cap 200 | risk-scenario classification |

**Honest-FPR commitment** (sub-claim #1): **≥20 benign / family before
reporting that family's FPR**. For benign-skills + benign-tools + benign-npm,
report with explicit N flag until Q0.3-Q0.5 acquisitions complete.

Total headline suite v1: ~160 malicious + ~38 benign = ~200 cases.
Post-acquisition v2: ~160 mal + ~75 ben = ~235 cases.

---

## 4. Headline metrics (4) + appendix metrics

**Always reported:**

| Metric | Definition |
|--------|------------|
| Detection Rate (DR) | TP / (TP+FN), per-family + macro-mean |
| False Positive Rate (FPR) | FP / (FP+TN), per-family + macro-mean. Reported with N flag when benign N < 20. |
| p50 latency | wall-clock `safeguard.inspect()` median, per-row. Per-case timeout: 60 s default, 180 s for npm/pypi install rows. |
| Evidence coverage | % of malicious cases where `system_trace.{lsm_events ∪ file_access}` captures the *key sensitive op* (credential file open, attacker-domain connect, suspicious exec). Decouples evidence from verifier. |

**Decision-flip rate (NEW formula per critic):** for each case run 3 times,
flip = 1 if decisions differ across the 3 runs, 0 otherwise. Flip rate =
sum(flips) / N. Report per-row. Cases with flip = 1 are flagged in the
per-case output but counted in DR/FPR with the modal decision.

**Appendix:** F1 (per family, agg), precision/recall, ASR (allowed AND
trace shows malicious behavior happened), utility drop (benign blocked /
benign total), per-rule confusion matrix in mock_verifier.

---

## 5. EvidenceQualityBench — power-calibrated (P1-3 fix)

Take **N ≥ 300 cases** (≥150 mal + ≥150 benign, mostly from DataDog) ×
5 evidence-package variants:

| Variant | Contents |
|---------|----------|
| A | `current_action` + `external_environment.content` only |
| B | A + `static_analysis` (semgrep findings) |
| C | A + `system_trace` from strace |
| D | A + `system_trace` from bpftrace with `kprobe:security_file_open` lsm_events |
| E | Full pipeline (B + D + reputation) |

**Power analysis**: McNemar's test, α=0.05, β=0.20 → N=300 detects
ΔAccuracy ≥ 7pp at discordant-pair rate ~20%. Smaller deltas → inconclusive.

**Falsification criterion (pre-registered)**: if |Acc(D) − Acc(A)| < 5pp
within 95% CI, the central contribution is **reported as inconclusive**;
we do not publish "improvement" claims unless lower bound > 0.

**Verifier requirement**: EvidenceQualityBench is *gated on GLM verifier
wiring* (Q0.8). With mock_verifier alone, the experiment degenerates to
"which rule branch fires" (deterministic given trace contents). State
this explicitly: if GLM is deferred, EvidenceQualityBench is a *sanity
check*, not the central paper contribution.

---

## 6. Ablation matrix — single-knob, R3 sequencing fix (P1-5)

| Row | Config | Sequencing note |
|-----|--------|-----------------|
| R0 (base) | trigger + strace + semgrep + evidence + mock_verifier | full primary; runs first |
| R1 | R0 − sandbox | impact of dynamic observation |
| R2 | R0 − semgrep | impact of static analyzer |
| **R3** | R0 − suspicious-instruction extractor | **must run AFTER §7 P0 fixes (gates #1 + #2); otherwise R3 ≡ R0 on skill-inject and the row is uninformative** |
| R4 | R0 with bpftrace replacing strace | LSM-hook observation contribution |
| R5 | R0 + GLM verifier | **blocked on Q0.8** — if deferred, R5 is empty and we publish 5 rows |

Each row × ~200 case suite + benign panel. R0+R1+R2+R3+R4 → ~5×6-8 min =
~40 min wall time per full pass; mean-of-3 = ~2 h. R5 doubles wall time
when wired.

---

## 7. Per-module quality gates — power-calibrated (P1-2 fix)

| # | Module | Pass criterion (with N + LCB) | Fixture |
|---|--------|-------------------------------|---------|
| 1 | Widen `policy.SUSPICIOUS_INSTRUCTION_PHRASES` | ≥80% of 20 obvious_injection fixtures match ≥1 phrase (95% LCB ≥ 60%) | `skill-inject/skill_inject_obvious_injections_{1..20}` |
| 2 | Fix `evidence_builder._safe_excerpt` cap | 5 locked `contextual_injections_*` fixtures by ID (specifically `_10, _11, _12, _13, _14`) — phrase match works after cap raised to ≥8000 | manual lock |
| 3 | `trigger.classify_command` | recall ≥ 95% with **95% one-sided LCB ≥ 90%** → requires N ≥ 60 hand-labeled commands with ≤ 1 miss | curated `bench/labeled_commands.json` (Q0 to build) |
| 4 | `external_target_extractor` | exact-match recall ≥ 95% on **N ≥ 30 with ≤ 1 miss** | curated |
| 5 | `sandbox_runner` strace | `execve("pip", …)` in trace on **all 8 malicious-ci-helper-like cases** | 8-case smoke |
| 6 | `sandbox_runner` bpftrace (host verified 2026-05-25) | attach marker fires + `lsm_events` non-empty on `benign_project` AND 1 malicious-repo case | live |
| 7 | `trace_parser` | golden-fixture round-trip pass on **5 recorded traces** | locked |
| 8 | `event_logger` | golden formatted_events + tree shape match on **10 curated traces** | locked |
| 9 | `static_analyzer` semgrep | ≥1 CRITICAL/HIGH finding on **8 mal-repos + 30 datadog-pypi (N=38, ≤ 1 miss)** AND 0 CRITICAL on **15 benign-pypi** | live |
| 10 | `evidence_builder` | JSON-schema conformance on all 200 cases | suite-wide |
| 11 | `mock_verifier` | per-rule confusion matrix reported (descriptive, not gated) | 200 cases |
| 12 | `safeguard.inspect` E2E | gates Phase 3 | 200-case stratified |

**Phase 2 P0 critical-path bugs** (fix before any gate runs):

- **Bug A**: `evidence_builder._safe_excerpt(path, max_chars=2000)` → raise
  to ≥8000 or chunk-scan full file. Unlocks gate #2.
- **Bug B**: `policy.SUSPICIOUS_INSTRUCTION_PHRASES` widened with regex set
  + injection signatures. Unlocks gate #1.
- **Order**: A then B (A is more localized; B depends on knowing what
  patterns to add).

---

## 8. Translator layer (Q0.6, Q0.7) — Phase 2 work

`bench/translators/injecagent.py` and `bench/translators/rjudge.py`. Each
~100 LOC. Input: corpus JSON. Output: `BenchmarkCase` per
`action_templates.py` schema. Translators pass through verifier only (no
sandbox) for these corpora — they are content-injection benchmarks, not
package-install benchmarks.

AgentDojo + BadComputerUse translators **deferred from Phase 2** (per
critic recommendation): trajectory-level, scope creep risk.

---

## 9. Hardening recommendations (corrected paraphrase per P1-1)

Adopt these before publishing numbers:

1. **Spotlighting / datamarking** (Hines et al., 2024) — wrap
   `external_environment.content` with a unique per-invocation token in
   the GLM verifier prompt. ASR > 50% → < 2% in their paper.
2. **SkillSieve 4-sub-task decomposition** — for skill artifacts,
   structure the verifier prompt around: intent alignment, permission
   justification, covert behavior, cross-file consistency. **SkillSieve's
   decomposed prompting achieves F1=0.800 vs. ClawVet (a prior different
   system) F1=0.421** on the 400-skill benchmark.
3. **PFI Data-ID provenance markers** — tag tool returns with content IDs
   that survive into evidence package, so the verifier can discriminate
   user-instructions from tool-return-instructions.

All three are R5 ablation territory (GLM verifier).

---

## 10. Open questions blocking Phase 2 — expanded (P1-4 fix)

| # | Question | Status | Recommendation |
|---|----------|--------|-----------------|
| Q1 | Action-level vs trajectory-level evaluation? | open | Action-level for headline; AgentDojo trajectory subset for appendix later |
| Q2 | Which 3 prior-work baselines to compare against publicly? | open | AgentSentinel + agent-mds + raw-semgrep+pip-audit; PFI as 4th when GLM wired |
| Q3 | Network mode `none` (deterministic) vs `bridge` with captive resolver? | open | `none` primary; `bridge`+resolver as ablation when latency budget allows |
| Q4 | Deterministic re-run: single-seed vs mean-of-3 with flip-flag? | open | Mean-of-3 + flip-flag (formula in §4) |
| Q5 | GLM verifier wiring in Phase 2 or deferred? | open | Defer to follow-up; R5 + EvidenceQualityBench gated on this |
| **Q6** (P1-4a) | Is sandbox image build a Phase 2 prereq or assumed done? | resolved → Q0.1 done | n/a |
| **Q7** (P1-4b) | Corpus label trust — do we spot-check labels for noise? | open | Sample-and-verify 10 from each malicious family before publishing FPR |
| **Q8** (P1-4c) | InjecAgent + R-Judge translator effort budget | open | Q0.6 + Q0.7 each ~100 LOC; estimate 1 day each |
| **Q9** (P1-4d) | If R5 deferred, is the 5-row ablation table publishable? | open | Yes — frame as "R5 reserved for follow-up" |
| **Q10** (P0-2 recovery) | Acquire benign-npm controls (Q0.5)? Source? | open | npm-trends + manual triage; aim for 15 from `npm`/`react`/`lodash`/etc safelist |
| **Q11** | Acquire +10 benign-skills + +12 benign-tools? Source? | open | SkillSieve 400-skill labelled set; mark provenance in fixture |

---

## 11. Acceptance — revised gates

- ✅ §1 headline claim is empirically defensible (per-observation-mode ablation IS novel)
- ✅ §2 SOTA targets calibrated to chanever scope (install-time, mock_verifier)
- ✅ §3 corpus counts verified against disk (P1-6 fix)
- ✅ §5 EvidenceQualityBench has N=300 + falsification criterion
- ✅ §6 R3 sequencing explicit
- ✅ §7 quality gates carry N + LCB requirements
- ✅ §9 ClawVet/SkillSieve paraphrase corrected
- ✅ §10 expanded with 6 new questions (Q6-Q11)
- ✅ §0 Phase 2 prerequisites enumerated
- ⏸ Q0.3, Q0.4, Q0.5, Q0.6, Q0.7, Q0.8 still open — user resolution needed
- ⏸ Critic re-review (this is v2; v1 found 2 P0 + 6 P1 — does v2 close all of them?)

Ready for Phase 2 once Q0.6 + Q0.7 (translators) are accepted as
in-scope, OR a "v1 = without InjecAgent/R-Judge" minimal deliverable is
agreed.
