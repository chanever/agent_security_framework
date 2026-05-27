# LLM Agent Security: Literature Scan for Benchmark Design

**Purpose:** Focused literature scan to inform benchmark design for the
`chanever/agent_security_framework` shadow-execution + post-hoc judgment pipeline.
Each paper section ends with a "→ relevance to our framework" note keyed to our
modules: eBPF/bpftrace, kprobe:security_file_open, semgrep, target extractor,
verifier, evidence package.

**Scan date:** 2026-05-25  
**Papers fetched and verified:** 12 (all arxiv abstracts or HTML fetched live;
no entry is training-memory-only)

---

## Part 1 — Attack Benchmarks

---

### Paper 1 — AgentDojo

| Field | Value |
|---|---|
| **Title** | AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents |
| **Year** | 2024 (submitted June 2024; final November 2024) |
| **Venue** | arXiv cs.CR / cs.LG — 2406.13352 |
| **Authors** | Debenedetti, Zhang, Balunović, Beurer-Kellner, Fischer, Tramèr |
| **Link** | https://arxiv.org/abs/2406.13352 |

**Threat model:** Indirect prompt injection — "data returned by external tools
hijacks the agent to execute malicious tasks." Attack is injected into tool
return values (email bodies, calendar entries, bank transaction notes, travel
site content) to redirect the agent away from the user's original goal.

**Defense mechanism:** Framework for evaluating arbitrary defenses. Does not
prescribe a single defense. Baselines include detection prompts, output
sanitization, re-ranking, and tool-return filtering.

**Benchmark:**
- 97 realistic user tasks across 4 domains: email/calendar, e-banking, travel, Slack workspace
- 629 security test cases (97 tasks × injected variants)
- Malicious cases: injections embedded in tool returns; benign: same tasks without injection
- Ground-truth: manually authored expected agent behavior

**Metrics reported:**
- Task Utility Rate (TUR): fraction of benign tasks completed correctly
- Attack Success Rate (ASR): fraction of injected tasks that redirect the agent
- Defense Success Rate (DSR): fraction of attacked tasks where defense prevents hijack

**Key result:** State-of-the-art LLMs complete ~50–70% of benign tasks but are
hijacked in 20–60% of attacked tasks; no existing defense achieves both high
DSR and minimal utility drop simultaneously.

**Benchmark publicly available:** Yes — https://github.com/ethz-spylab/agentdojo

**Compatible with evidence-package interface?** Partial. AgentDojo exposes
task/tool-return pairs. A translator would map each tool-return event to our
`external_environment` field and the injected payload to
`external_interaction_analysis.prompt_injection_phrases`. No native eBPF or
sandbox trace; those would be added by wrapping agent execution in our sandbox.

**Does it measure what we care about?** Measures ASR/DSR per domain; does NOT
measure per-module DR (eBPF miss rate, semgrep hit rate) or evidence quality.
Latency overhead is not tracked.

→ **Relevance to our framework:**
- **Verifier module:** AgentDojo's 629 cases provide labelled ground-truth that
  our LLM verifier can be scored against (DSR as verifier recall).
- **Evidence package:** The injected tool-return text is exactly the
  `prompt_injection_phrases` our evidence_builder.py extracts.
- **Target extractor:** Tool calls carry URLs/package names that our
  external_target_extractor.py would parse.
- **Gap:** No syscall/eBPF data; our sandbox would need to wrap each AgentDojo
  step. A thin adapter script would achieve this.

---

### Paper 2 — InjecAgent

| Field | Value |
|---|---|
| **Title** | InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents |
| **Year** | 2024 |
| **Venue** | ACL 2024 Findings — arXiv 2403.02691 |
| **Authors** | Zhan, Liang, Ying, Kang |
| **Link** | https://arxiv.org/abs/2403.02691 |

**Threat model:** Indirect prompt injection (IPI) via tool outputs. Two attack
intentions: (a) direct harm to users (destructive commands), (b) exfiltration
of private data. Injections are embedded in content returned by 17 user tools;
the agent is driven toward 62 distinct attacker tools.

**Defense mechanism:** None proposed; purely an attack evaluation benchmark.

**Benchmark:**
- 1,054 test cases covering 17 user tools × 62 attacker tools
- Two attack modes: (1) base IPI, (2) reinforced IPI (hacking-prompt-augmented)
- Ground-truth: manually authored correct vs. hijacked action labels
- Evaluated on 30 LLM agents

**Metrics reported:**
- ASR: ReAct-GPT-4 hijacked 24% (base), ~48% (reinforced)
- Per-tool breakdown available

**Key result:** All tested agents are vulnerable to IPI; reinforced attacks
nearly double ASR. Smaller models are more susceptible.

**Benchmark publicly available:** Yes — https://github.com/uiuc-kang-lab/InjecAgent

**Compatible with evidence-package interface?** High compatibility. Each test
case has a user task, a tool name, a tool return (the injection vehicle), and a
ground-truth expected action. This maps directly to our `user_task`,
`current_action`, `external_environment.content`, and verifier ground-truth
label. No sandbox trace included; we add that layer.

**Does it measure what we care about?** ASR per tool — useful for verifier
recall. No latency, no per-module eBPF DR.

→ **Relevance to our framework:**
- **Verifier:** 1,054 labelled injection cases are the largest ready-to-use
  corpus for scoring our mock→LLM verifier upgrade. Each case should yield a
  BLOCK/HOLD decision.
- **Target extractor:** Attacker tool calls often contain URLs or package
  references parseable by our extractor.
- **Evidence package:** The `tool_return` field maps to
  `external_environment.content`; injection phrase extraction would fire on the
  majority of cases.
- **eBPF/semgrep:** Not applicable directly; these are prompt-level injections,
  not package execution. Our sandbox would fire only on cases that resolve to
  shell commands.

---

### Paper 3 — SKILL-INJECT

| Field | Value |
|---|---|
| **Title** | Skill-Inject: Measuring Agent Vulnerability to Skill File Attacks |
| **Year** | 2026 |
| **Venue** | arXiv cs.CR — 2602.20156 |
| **Authors** | Schmotz, Beurer-Kellner, Abdelnabi, Andriushchenko |
| **Link** | https://arxiv.org/abs/2602.20156 |

**Threat model:** Prompt injection embedded in agent skill/instruction files
(SKILL.md, .claude/skills/*.md). Two attack categories: (1) obvious injections
(ransomware deployment, mass deletion, phishing); (2) contextual injections
(subtle attacks hidden in otherwise legitimate skill instructions). Distinct
from traditional IPI because "the entire skill file is composed of instructions
— the standard defense of separating instructions from data does not apply."

**Defense mechanism:** None provides adequate protection. Context-aware
authorization frameworks are recommended but not implemented. Tested defenses
(scaling, simple filtering) fail.

**Benchmark:**
- 202 injection-task pairs
- Split: obvious injections + contextual injections (exact split not published
  in abstract; full data at https://www.skill-inject.com)
- Attack categories: data exfiltration, destructive actions (rm -rf equivalents),
  ransomware-like behaviour
- Evaluated on: Claude Code, Codex, Gemini CLI

**Metrics reported:**
- ASR: obvious injections 36–75% (single attempt); Gemini Flash 83% with best-of-5
- Contextual injections: up to 79% (no warning), up to 58% (with security instruction)

**Key result:** Frontier coding agents execute extremely harmful instructions
from skill files; no model scales to safety. Best-of-5 sampling pushes ASR
above 80%.

**Benchmark publicly available:** Yes — https://github.com/aisa-group/skill-inject
and https://www.skill-inject.com

**Compatible with evidence-package interface?** Direct — our benchmark_datasets.md
already ingests `obvious_injections.json` and `contextual_injections.json` from
this repo (40 malicious cases configured). The SKILL.md artifacts are exactly
what our `cat skill.md` → `external_env=true` path handles.

**Does it measure what we care about?** ASR per LLM. Does NOT measure
semgrep hit rate or eBPF trace quality. We should add those as additional
columns in our eval loop.

→ **Relevance to our framework:**
- **Already integrated** in agent-mds benchmark_datasets.md (40 cases).
- **Semgrep:** SKILL.md files contain shell command patterns that `p/security-audit`
  rules may flag — our eval should report semgrep DR on this subset separately.
- **Evidence package:** `prompt_injection_phrases` extraction is the primary
  detection signal for this class; verifier must correctly classify HOLD/BLOCK.
- **eBPF:** Only fires if the agent attempts to execute the injected commands.
  Our trigger.py `external_instruction_source` path handles the read-only case.

---

### Paper 4 — Agent Skills Enable a New Class of Prompt Injections (promptinject-agent-skills)

| Field | Value |
|---|---|
| **Title** | Agent Skills Enable a New Class of Realistic and Trivially Simple Prompt Injections |
| **Year** | 2025 |
| **Venue** | arXiv cs.LG — 2510.26328 |
| **Authors** | Schmotz, Abdelnabi, Andriushchenko (precursor to SKILL-INJECT) |
| **Link** | https://arxiv.org/abs/2510.26328 |

**Threat model:** Skill-file prompt injection exploiting markdown instruction
files to hide malicious commands (data exfiltration via curl/POST). Key insight:
"benign, task-specific 'Don't ask again' approval can carry over to closely
related but harmful actions," bypassing system-level guardrails.

**Defense mechanism:** None effective; identifies that standard instruction/data
separation fails for skill files.

**Benchmark:** Predecessor to SKILL-INJECT; exact case count not published in
abstract. Evaluated on Claude Code and Gemini CLI.

**Metrics reported:** ASR per agent (numerical values not in abstract).

**Key result:** Trivially simple injections in skill files bypass agent
guardrails due to approval-carry-over; demonstrates a previously uncharacterised
attack surface.

**Benchmark publicly available:** Yes — https://github.com/aisa-group/promptinject-agent-skills

**Compatible with evidence-package interface?** Yes — same SKILL.md artifact
format as Paper 3. Treat as additional cases for our skill injection test set.

→ **Relevance to our framework:**
- Confirms the `external_instruction_source` classification path in trigger.py
  is the right first gate.
- **Verifier:** Approval-carry-over attacks require the verifier to track
  multi-turn context, not just single-action evidence — a gap in our current
  mock verifier.

---

### Paper 5 — BadComputerUse + AgentSentinel

| Field | Value |
|---|---|
| **Title** | AgentSentinel: An End-to-End and Real-Time Security Defense Framework for Computer-Use Agents |
| **Year** | 2025 |
| **Venue** | ACM CCS 2025 — arXiv 2509.07764 |
| **Authors** | Haitao Hu, Peng Chen, Yanpeng Zhao, Yuqi Chen |
| **Link** | https://arxiv.org/abs/2509.07764 |

**Threat model:** Seven attack categories targeting computer-use agents:
(1) Direct Task Injection, (2) Agent Infrastructure Attack, (3) Backdoor Attack,
(4) Bad Tool Result Attack, (5) Hallucination Exploitation,
(6) Malicious Agent-Execution Environment, (7) AgentDojo prompt injection.
Average ASR of 87% across 4 frontier LLMs with no defense.

**Defense mechanism:** eBPF + LSM interception of all sensitive operations.
16 trace probes covering process control (fork/exec/kill/exit), filesystem
(open/remove/rename), and network (connect/listen/accept/DNS). Four-stage
auditing pipeline: (1) rule-based auditor (56% of events, negligible latency);
(2) task-context summarization; (3) cache lookup (14% of events, three-tier
cache: once/task/universal scope); (4) LLM-based auditor query (30% of events,
~2.4–2.8 queries per tool use). Cache filters 84% of file events and 61% of
network events before LLM query.

**Benchmark (BadComputerUse):**
- 60 attack scenarios, 10 per attack category (7 categories)
- Ground-truth sourced from: OSWorld, AgentInstruct, AgentBench, NL2Bash tasks
  extended with adversarial injection variants
- Evaluated on: GPT-4o, Claude 3.7 Sonnet, Gemini 2.0 Flash, Qwen-Max

**Metrics reported:**
- Baseline ASR: 87% average across 4 LLMs
- Defense Success Rate (DSR): 79.6% average across 4 LLMs
- FPR: 10.8% aggregate
- FNR: 4.2%
- Task Failure Rate: 4.2%
- Cache resolution: 56% rule-based, 14% cache hit, 30% LLM query
- Event filtering: 84% file events filtered, 61% network events filtered
- Specific hook names: paper does not expose kernel identifiers (bpf_lsm_* or
  kprobe names), only functional categories

**Key result:** AgentSentinel achieves 79.6% DSR vs. 87% baseline ASR while
maintaining 10.8% FPR and 4.2% task failure — the only system combining
kernel-level tracing with LLM auditing for computer-use agents.

**Benchmark publicly available:** Yes — https://github.com/m4p1e/agent-sentinel
(BadComputerUse included in repo)

**Compatible with evidence-package interface?** High. Each BadComputerUse case
has a user task, tool calls, expected outcome, and attack type label. Our
evidence builder produces exactly the context AgentSentinel's LLM auditor
consumes. Major gap: AgentSentinel's eBPF hooks are in the host process (not
cgroup-scoped); our bpftrace uses cgroup-id scoping via docker pause/inspect.

**Does it measure what we care about?** DSR (≈ verifier recall), FPR, FNR,
task failure rate. Does NOT report per-event eBPF detection latency in ms or
semgrep contribution. Cache hit rates are reported, which is analogous to our
rule-based mock verifier fast path.

→ **Relevance to our framework:**
- **eBPF/bpftrace:** This is the closest existing system to our probe.bt design.
  AgentSentinel uses eBPF+LSM but does NOT use `kprobe:security_file_open` —
  our specific hook for LSM-layer observation. This is a differentiator worth
  benchmarking: does `kprobe:security_file_open` catch events that a simple
  `open` tracepoint misses?
- **Verifier:** AgentSentinel's 4-stage pipeline (rule→cache→LLM) is the
  production reference for our mock→LLM verifier upgrade path.
- **Evidence package:** AgentSentinel's "enforcement event + dependent trace +
  task context" maps directly to our evidence package structure.
- **BadComputerUse benchmark:** 60 labelled cases can be adapted for our
  framework with a translator that generates MDS-style evidence packages from
  each scenario. All 7 attack categories map to threat types we test.

---

### Paper 6 — BIPIA

| Field | Value |
|---|---|
| **Title** | Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models |
| **Year** | 2023 (submitted Dec 2023; accepted KDD 2025) |
| **Venue** | KDD 2025 — arXiv 2312.14197 |
| **Authors** | Yi, Xie, Zhu, Kiciman, Sun, Xie, Wu (Microsoft) |
| **Link** | https://arxiv.org/abs/2312.14197 |

**Threat model:** Indirect prompt injection via external content embedded in
LLM context (retrieval, tool calls, multi-turn). 15 attack types across
task-irrelevant, task-relevant, and targeted attack categories. Three scenario
categories: retrieval-based, tool-calling, multi-turn.

**Defense mechanism:** Two novel defenses: (1) boundary awareness — marking
instruction/data boundaries explicitly; (2) explicit reminder — appending a
reminder of the original instruction. Both work in black-box and white-box
settings.

**Benchmark (BIPIA):**
- 15 attack types × 5 instructions per type = structured evaluation corpus
- Covers three attack position variants within external content
- Ground-truth: manually authored expected vs. hijacked outputs

**Metrics reported:**
- ASR (all LLMs universally vulnerable at baseline)
- White-box defense: ASR reduced to near-zero
- Output quality preservation confirmed (no significant degradation)

**Key result:** All tested LLMs are universally vulnerable; white-box boundary
awareness defense reduces ASR to near-zero while preserving task quality.

**Benchmark publicly available:** Yes — https://github.com/microsoft/BIPIA

**Compatible with evidence-package interface?** Partial. BIPIA focuses on
model-level response, not agent tool execution. Tool-calling scenario subset
is directly adaptable: tool returns map to `external_environment.content`,
attack type maps to verifier ground-truth label. No sandbox trace.

**Does it measure what we care about?** ASR reduction; utility preservation.
No per-module DR, no eBPF, no semgrep.

→ **Relevance to our framework:**
- **Evidence package:** BIPIA's `prompt_injection_phrases` extraction cases are
  a superset of our suspicious-phrase detector's target patterns.
- **Verifier:** The 15 attack types provide a taxonomy for annotating our own
  evidence packages with injection categories.
- **Complementary use:** BIPIA + InjecAgent together cover the full
  prompt-injection landscape; use both as verifier scoring corpora.

---

## Part 2 — Defense / Observation Systems

---

### Paper 7 — Prompt Flow Integrity (PFI)

| Field | Value |
|---|---|
| **Title** | Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents |
| **Year** | 2025 |
| **Venue** | arXiv cs.CR — 2503.15547 |
| **Authors** | Kim, Choi, Lee |
| **Link** | https://arxiv.org/abs/2503.15547 |

**Threat model:** Privilege escalation via prompt injection — attacker-controlled
content in untrusted tool returns steers the trusted agent to invoke privileged
tool calls or leak data. Models the agent as two trust levels: trusted (A_T)
and untrusted (A_U).

**Defense mechanism:** Three components:
1. **Agent Isolation:** Separate trusted agent (A_T, full tool access) from
   untrusted agent (A_U, restricted token). Fresh A_U context per call prevents
   cross-contamination.
2. **Secure Untrusted Data Processing:** Data ID mechanism (#DATA0, #DATA1) lets
   A_T reference untrusted data without direct exposure. Supports data
   referencing, computation offloading, and prompt transformation (requires user
   approval).
3. **Privilege Escalation Guardrails:** DataGuard monitors every A_T tool call
   for unsafe data flows; CtrlGuard monitors A_U responses for prompt-type
   untrusted data. Both require user approval for risky operations.
Sandboxed shell via nsjail for AgentBench OS tasks.

**Benchmark:**
- AgentDojo (modified with untrusted injection tasks)
- AgentBench OS (extended with mobile agent attack scenarios)
- 108 tasks analysed for failure attribution

**Metrics reported:**
- Secure Utility Rate (SUR): PFI 61.86% (AgentDojo) vs. baseline 12.37%
- PFI SUR on AgentBench OS: 68.42% vs. baseline 0%
- Attacked Task Rate (ATR): PFI 0.00% on both benchmarks
- DataGuard/CtrlGuard: 0% FP, 0% FN (deterministic tracking)

**Key result:** PFI eliminates privilege escalation attacks (ATR=0%) while
preserving the highest utility among all compared defenses (SUR=61–68%).

**Benchmark publicly available:** Yes — https://github.com/compsec-snu/pfi

**Compatible with evidence-package interface?** Structural overlap: PFI's data
flow tracking (DataGuard) and our `external_environment` content provenance
tracking address the same problem from different angles. PFI is static-token
enforcement; we are runtime-trace + verifier judgment. Adapting PFI's 108-task
evaluation set to our framework would provide ATR ground truth.

**Does it measure what we care about?** SUR and ATR — equivalent to our utility
preservation and verifier recall. No eBPF/syscall, no semgrep, no latency
figures for the sandbox path.

→ **Relevance to our framework:**
- **Verifier:** PFI's DataGuard/CtrlGuard decision logic is a formal analogue to
  our mock verifier's `credential_access` and `unknown_post` BLOCK rules.
- **Evidence package:** Data-flow provenance tracking (which data came from
  untrusted source) is a future enhancement to our `external_environment` field.
- **Gap validation:** PFI shows 0% ATR with deterministic enforcement. Our
  probabilistic verifier approach should be benchmarked against this ceiling.
- **nsjail sandbox** is an alternative to Docker for the OS-level tasks —
  relevant for our sandbox_runner.py evolution.

---

### Paper 8 — AgentSentry (Temporal Causal Diagnostics)

| Field | Value |
|---|---|
| **Title** | AgentSentry: Mitigating Indirect Prompt Injection in LLM Agents via Temporal Causal Diagnostics and Context Purification |
| **Year** | 2026 |
| **Venue** | arXiv cs.CR — 2602.22724 |
| **Authors** | Zhang, Xu, Wang, Guo, Xu, Xiao, Guan, Fan, Liu, Liu, Hu |
| **Link** | https://arxiv.org/abs/2602.22724 |

**Threat model:** Multi-turn indirect prompt injection across all three IPI
attack families (direct hijack, goal hijack, combined). Attacker-controlled
context embedded in tool outputs or retrieved content silently steers agent
actions away from user intent across conversation turns.

**Defense mechanism:** Inference-time detection via temporal causal analysis:
(1) localises takeover points via controlled counterfactual re-executions at
tool-return boundaries; (2) context purification removes attack-induced
deviations while preserving task-relevant information. No kernel-level tracing;
entirely inference-time.

**Benchmark:** AgentDojo (all four task suites, three IPI attack families,
multiple black-box LLMs).

**Metrics reported:**
- Utility Under Attack (UA): 74.55% average
- Improvement over baseline defenses: +20.8–33.6 percentage points
- Benign performance: no degradation reported

**Key result:** Temporal causal counterfactual re-execution improves UA by
20.8–33.6pp over prior defenses without benign performance degradation.

**Benchmark publicly available:** Uses AgentDojo (public). AgentSentry code
availability not stated in abstract.

**Compatible with evidence-package interface?** Indirect. AgentSentry's
counterfactual re-executions are an inference-time technique; our framework
does a single shadow-execution pass. The temporal takeover-point detection
concept could be adapted as a post-hoc analysis step on our evidence package's
`previous_context` + `current_action` history.

**Does it measure what we care about?** UA (utility under attack) — equivalent
to our utility preservation metric. No per-module DR, no eBPF, no semgrep.

→ **Relevance to our framework:**
- **Verifier:** The counterfactual re-execution idea validates our shadow-
  execution + post-hoc judgment design philosophically. AgentSentry does it at
  the LLM layer; we do it at the OS layer.
- **Evidence package:** Multi-turn context (our `previous_context` field) is
  critical; AgentSentry shows that single-step evidence misses trajectory-level
  attacks.

---

### Paper 9 — AgentSight (eBPF TLS Interception)

| Field | Value |
|---|---|
| **Title** | AgentSight: System-Level Observability for AI Agents Using eBPF |
| **Year** | 2025 |
| **Venue** | PACMI'2025 Workshop — arXiv 2508.02736 |
| **Authors** | Zheng, Hu, Yu, Quinn |
| **Link** | https://arxiv.org/abs/2508.02736 |

**Threat model:** Prompt injection detection; resource-wasting reasoning loops;
hidden multi-agent coordination bottlenecks. Focuses on observability as a
prerequisite for detection, not enforcement.

**Defense mechanism (observation):** "Boundary tracing" — two correlated streams:
(1) TLS uprobe interception of encrypted LLM API traffic to extract semantic
intent (prompts + completions) without modifying the agent; (2) kernel event
monitoring (process exec, file access, network connect) to observe system
effects. A real-time causal correlation engine links semantic intent to
OS-level effects across process boundaries. Secondary LLM analysis flags
anomalies. Framework-agnostic, instrumentation-free. Less than 3% performance
overhead.

**Benchmark:** No formal benchmark with labelled ground-truth cases. Demonstrates
prompt injection detection, loop detection, and multi-agent bottleneck analysis
as use cases.

**Metrics reported:** <3% overhead. No DR/FPR figures in published abstract.

**Key result:** Zero-instrumentation eBPF boundary tracing bridges the semantic
gap between LLM intent and OS-level effects with <3% overhead.

**Benchmark publicly available:** Open source — https://github.com/eunomia-bpf/agentsight

**Compatible with evidence-package interface?** High architectural overlap.
AgentSight's "intent + kernel events" output is structurally equivalent to our
Evidence Package's `shadow_agent_execution` + `system_trace` sections. The TLS
uprobe approach could complement our bpftrace mode by adding semantic-layer
context.

**Does it measure what we care about?** Overhead (<3%) is directly comparable
to our bpftrace mode's pause/unpause latency. No DR/FPR benchmark.

→ **Relevance to our framework:**
- **eBPF/bpftrace:** AgentSight validates the eBPF+semantic-correlation approach
  for LLM agents. Their TLS uprobe for prompt capture is a future enhancement
  to our probe.bt — capturing the agent's actual LLM query alongside the kernel
  trace would enrich our evidence package significantly.
- **Evidence package:** The "causal correlation across process boundaries" is
  exactly what our `trace_parser.py` → `evidence_builder.py` pipeline does at
  a simpler level. AgentSight's full correlation engine is the production
  evolution of our current approach.
- **Benchmark gap:** AgentSight has no labelled DR/FPR benchmark — an
  opportunity for our framework to produce one.

---

### Paper 10 — eBPF-PATROL

| Field | Value |
|---|---|
| **Title** | eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation using eBPF in Containerized and Virtualized Environments |
| **Year** | 2025 |
| **Venue** | arXiv cs.CR — 2511.18155 |
| **Authors** | Ghimire, Bhurtel, Sahani, Jha |
| **Link** | https://arxiv.org/abs/2511.18155 |

**Threat model:** Runtime container/VM threats: reverse shells, privilege
escalation, container escape. Not LLM-specific, but directly applicable to
Docker sandbox enforcement in our pipeline.

**Defense mechanism:** eBPF with: (1) syscall interception, (2) execution
context analysis, (3) user-defined rule enforcement. Runtime policy enforcement
(not just observation), blocking violations before they succeed. Lightweight
design for containerized environments.

**Benchmark:** Real-world attack scenarios (specific dataset not named in abstract;
not a formal public benchmark).

**Metrics reported:**
- Overhead: <2.5%
- Detection accuracy: "high" across real-world attack scenarios (specific DR/FPR
  not published in abstract)

**Key result:** <2.5% overhead runtime policy enforcement against reverse shells,
privilege escalation, and container escapes in containerized environments.

**Benchmark publicly available:** Not stated.

**Compatible with evidence-package interface?** Structural complement: eBPF-PATROL
enforces where we only observe. Its rule format could inform our `policy.py`
forbidden-behavior list and future BPF LSM enforcement upgrade.

**Does it measure what we care about?** Overhead (<2.5%) is a useful comparison
point for our bpftrace mode. No DR/FPR with formal benchmark.

→ **Relevance to our framework:**
- **eBPF/bpftrace:** Validates the <3% overhead claim for eBPF container
  monitoring, consistent with AgentSight's <3% figure.
- **Future enforcement path:** eBPF-PATROL's rule enforcement model is a
  reference for upgrading our kprobe:security_file_open observation to active
  denial (bpf_lsm_file_open enforcement).
- **Sandbox integrity:** Reverse shell and container escape detections are
  relevant to ensuring our Docker sandbox cannot be subverted by sophisticated
  malicious packages.

---

## Part 3 — Supply Chain & Static Analysis

---

### Paper 11 — OSCAR (Supply Chain Sandbox Execution)

| Field | Value |
|---|---|
| **Title** | Towards Robust Detection of Open Source Software Supply Chain Poisoning Attacks in Industry Environments |
| **Year** | 2024 |
| **Venue** | ASE'24 Industry Showcase — arXiv 2409.09356 |
| **Authors** | Zheng, Wei, Wang, Zhao, Gao, Zhang, Wang, Wang (Ant Group) |
| **Link** | https://arxiv.org/abs/2409.09356 |

**Threat model:** Software supply chain poisoning attacks in npm and PyPI —
malicious packages obfuscating payloads to evade static analysis, using dynamic
code execution at install time.

**Defense mechanism:** OSCAR pipeline — three components:
1. Full package execution in sandbox environment (install-time execution capture)
2. Fuzz testing on exported functions and classes (surfaces latent behaviour)
3. Aspect-based behaviour monitoring with tailored API hook points (tracks
   network/file/process calls during execution)
Static analysis alone is insufficient; dynamic execution exposes obfuscated
payloads that static tools miss.

**Benchmark:**
- Comprehensive dataset of real-world malicious and benign packages (npm + PyPI)
- Deployed in production at Ant Group for 18 months
- 10,404 malicious npm packages detected; 1,235 malicious PyPI packages

**Metrics reported:**
- F1: 0.95 (npm), 0.91 (PyPI)
- FPR reduction: 32.06% (npm), 39.87% (PyPI) vs. static-only baseline

**Key result:** Combining sandbox execution + fuzzing + API hook monitoring
achieves F1=0.95/0.91 on npm/PyPI, substantially reducing FPR vs. static-only
tools.

**Benchmark publicly available:** Not stated (industrial deployment dataset;
paper code not released).

**Compatible with evidence-package interface?** High structural alignment.
OSCAR's "sandbox execution + API hook monitoring" is our shadow_runner +
trace_parser pipeline. Their API hook points are our bpftrace probes. Their
"malicious/benign" label is our verifier ground-truth. Key difference: OSCAR
uses fuzz testing of exported functions; we replay the original agent command.

**Does it measure what we care about?** F1, FPR reduction per ecosystem —
directly comparable to our per-module DR. No latency figures.

→ **Relevance to our framework:**
- **eBPF/bpftrace + sandbox:** OSCAR validates our core design — sandbox
  execution with syscall/API hook monitoring outperforms static analysis alone.
  Their F1=0.95 on npm is our target for the DataDog npm benchmark.
- **Semgrep:** Their static-only baseline is our semgrep-only path. The delta
  between static and static+dynamic informs how much our eBPF trace adds.
- **Benchmark gap:** OSCAR's production dataset is not public. DataDog's dataset
  (Paper 12) is the best public substitute.

---

### Paper 12 — DataDog Malicious Software Packages Dataset

| Field | Value |
|---|---|
| **Title** | DataDog Malicious Software Packages Dataset (corpus, not a paper) |
| **Year** | 2023–present (created March 2023, continuously updated) |
| **Venue** | GitHub — DataDog/malicious-software-packages-dataset |
| **Authors** | DataDog Security Research |
| **Link** | https://github.com/DataDog/malicious-software-packages-dataset |

**Threat model:** Real-world supply chain attacks: typosquatting, compromised
legitimate packages, packages published with malicious intent. Ecosystems:
npm, PyPI, IDE extensions, AI Skills. Includes credential theft, data
exfiltration, malware installation.

**Defense mechanism (associated tool — GuardDog):** CLI tool using Semgrep rules
and package metadata heuristics. Heuristics include: install-command overwrite
detection in setup.py, Base64-encoded dynamic execution (taint tracking),
data exfiltration patterns. GuardDog accuracy: 89.60% with ~25 second/package
analysis time. Associated supply-chain firewall blocks installation of flagged
packages.

**Dataset:**
- 27,165 malicious packages (as of scan date)
- Human-triaged: every package manually reviewed
- Ecosystems: npm (~44,407 malicious-intent names), PyPI (~1,814 malicious-intent
  names in our configured run), IDE extensions, AI Skills
- License: Apache-2.0

**Metrics reported (our framework's run on this dataset):**
- 50 PyPI + 40 npm ZIP artifacts: 90 true positives, 0 false negatives
- (from agent-mds docs/datadog_packages_90_report.md)

**Benchmark publicly available:** Yes — https://github.com/DataDog/malicious-software-packages-dataset

**Compatible with evidence-package interface?** Direct — already integrated in
agent-mds. Each package ZIP is an artifact; our adapter runs `pip install .`
or `npm install` in the sandbox and collects eBPF/strace evidence.

**Does it measure what we care about?** Real-world malicious packages provide
the highest-fidelity ground truth for eBPF trace quality, semgrep DR, and
verifier precision. Our 90/90 TP result needs FPR measurement (benign controls
from PyPI) to be a complete benchmark number.

→ **Relevance to our framework:**
- **Primary benchmark — already in use.** Most directly validates our full
  pipeline: eBPF trace quality on real malicious packages, semgrep rule
  coverage, target extractor accuracy, and verifier BLOCK rate.
- **eBPF/bpftrace:** Credential-access events (`kprobe:security_file_open` on
  ~/.ssh/id_rsa) are observable in real DataDog samples — our key eBPF
  differentiator over strace-only approaches.
- **Semgrep:** GuardDog's Semgrep rules complement our `p/security-audit` pack;
  consider adding GuardDog rules to our semgrep config.
- **Benign controls needed:** Current 90-sample run lacks benign PyPI packages
  to compute FPR. Add the 15 benign controls listed in benchmark_datasets.md.

---

## Part 4 — Verifier / Judge Systems

---

### Paper 13 — R-Judge

| Field | Value |
|---|---|
| **Title** | R-Judge: Benchmarking Safety Risk Awareness for LLM Agents |
| **Year** | 2024 |
| **Venue** | EMNLP Findings 2024 — arXiv 2401.10019 |
| **Authors** | Yuan, He, Dong, Wang, Zhao, Xia, Xu, Zhou, Li, Zhang, Wang, Liu |
| **Link** | https://arxiv.org/abs/2401.10019 |

**Threat model:** Safety risks arising from agent actions in interactive
environments — not content harmlessness but behavioral safety. 27 key risk
scenarios across 5 application categories, 10 risk types.

**Defense mechanism:** LLM-as-judge scoring of agent action traces. Provides
multi-turn interaction records as input; judge outputs safety label + risk
description.

**Benchmark:**
- 569 records of multi-turn agent interaction
- 27 risk scenarios, 5 application categories, 10 risk types
- Ground-truth: high-quality manual curation with annotated safety labels and
  risk descriptions

**Metrics reported:**
- Accuracy: GPT-4o best at 74.42%; all other models near random
- Fine-tuning on R-Judge data significantly improves judge performance

**Key result:** LLM safety judgment of agent actions is hard — even GPT-4o
achieves only 74.42% accuracy; fine-tuning on domain-specific data is necessary.

**Benchmark publicly available:** Yes (GitHub link in paper).

**Compatible with evidence-package interface?** Direct. R-Judge's input format
(multi-turn agent interaction record + risk label) is equivalent to our evidence
package + verifier ground-truth label. Our evidence package adds eBPF trace and
semgrep findings on top of the interaction record.

**Does it measure what we care about?** Judge accuracy (74.42% for GPT-4o) is
the ceiling benchmark for our LLM verifier upgrade from mock. Directly measures
verifier quality.

→ **Relevance to our framework:**
- **Verifier:** R-Judge's 569 cases with annotated safety labels are the best
  available benchmark for scoring our verifier module. The 74.42% GPT-4o
  ceiling tells us what to expect before adding eBPF evidence.
- **Evidence package enrichment hypothesis:** Our framework's claim is that
  adding eBPF trace, semgrep findings, and sandbox execution to the interaction
  record improves judge accuracy above 74.42%. R-Judge is the baseline to beat.
- **Risk taxonomy:** R-Judge's 10 risk types map to our `violated_properties`
  field; using the same taxonomy improves comparability.

---

### Paper 14 — SandboxEscapeBench

| Field | Value |
|---|---|
| **Title** | Quantifying Frontier LLM Capabilities for Container Sandbox Escape |
| **Year** | 2026 |
| **Venue** | arXiv cs.CR — 2603.02277 |
| **Authors** | Marchand, O Cathain, Wynne, Giavridis, Deverett, Wilkinson, Gwartz, Coppock |
| **Link** | https://arxiv.org/abs/2603.02277 |

**Threat model:** Adversarial LLM agent with shell access inside a container
attempts to escape isolation. Attack vectors: misconfiguration, privilege
allocation mistakes, kernel flaws, runtime/orchestration weaknesses.

**Defense mechanism:** Evaluated existing container hardening (capabilities,
seccomp, MAC). Kernel security mechanisms block 67.57% of privilege escalation
attacks.

**Benchmark (SandboxEscapeBench):**
- Inspect AI Capture-the-Flag evaluation
- Escape mechanisms: misconfiguration, privilege allocation, kernel flaws,
  runtime/orchestration weaknesses
- Exact case count not in abstract

**Metrics reported:**
- 67.57% of privilege escalation attempts blocked by kernel security mechanisms
- LLMs successfully exploit vulnerabilities when present

**Key result:** When container vulnerabilities exist, frontier LLMs can identify
and exploit them — ongoing evaluation of sandbox encapsulation is necessary for
capable models.

**Benchmark publicly available:** Partial (Inspect AI framework used; specific
scenario set availability unclear).

**Compatible with evidence-package interface?** Adversarial. This benchmark
tests our sandbox against LLM-driven escape attempts — a threat model we have
not yet addressed. If a sophisticated malicious package includes a sandbox
escape attempt, our current evidence collection would fail.

**Does it measure what we care about?** Sandbox integrity — currently not
measured by our framework. Critical gap: we assume the Docker sandbox is
trustworthy; SandboxEscapeBench shows that assumption requires validation.

→ **Relevance to our framework:**
- **Sandbox runner:** Our most critical architectural gap. We assume the sandbox
  confines the artifact; SandboxEscapeBench shows capable LLMs can escape.
  Mitigation: seccomp profiles, capability dropping, and Landlock in
  sandbox_runner.py (listed in README Section 13 as future work).
- **eBPF/bpftrace:** Container escape attempts would generate anomalous
  `process_exec` and `network_egress` events in our bpftrace log — our
  probe.bt would catch the attempt even if it succeeds.
- **Benchmark to add:** Run SandboxEscapeBench scenarios against our framework
  to measure sandbox integrity (a metric we currently have zero coverage on).

---

### Paper 15 — SkillSieve

| Field | Value |
|---|---|
| **Title** | SkillSieve: A Hierarchical Triage Framework for Detecting Malicious AI Agent Skills |
| **Year** | 2026 |
| **Venue** | arXiv cs.CR — 2604.06550 |
| **Authors** | Hou, Yang |
| **Link** | https://arxiv.org/abs/2604.06550 |

**Threat model:** Malicious agent skills in OpenClaw ClawHub marketplace —
13–26% of 13,000+ community skills contain security vulnerabilities. Attacks:
obfuscated payloads in code, prompt injection in SKILL.md natural-language
instructions, social engineering via permission justification text.

**Defense mechanism:** Three-layer hierarchical triage:
1. **Layer 1:** XGBoost + regex/AST/metadata features; filters ~86% of benign
   skills in <40ms, zero API cost.
2. **Layer 2:** LLM with decomposed analysis (4 parallel sub-tasks: intent
   alignment, permission justification, covert behaviour detection,
   cross-file consistency).
3. **Layer 3:** Ensemble vote of 3 independent LLMs; debate resolution on
   disagreement.

**Benchmark:**
- 49,592 real ClawHub skills evaluated in production
- 400-skill labelled benchmark (ground-truth from manual audit)
- Malicious/benign split not specified in abstract

**Metrics reported:**
- F1: 0.800 (vs. ClawVet baseline 0.421)
- Layer 1 latency: <40ms average
- Cost: ~$0.006 per skill average

**Key result:** SkillSieve achieves F1=0.800 on the 400-skill benchmark vs.
ClawVet's 0.421, at $0.006/skill average cost.

**Benchmark publicly available:** Yes (code, data, benchmark open-sourced;
specific repo not in abstract).

**Compatible with evidence-package interface?** High. SkillSieve's Layer 2
LLM analysis sub-tasks (intent alignment, permission justification, covert
behaviour, cross-file consistency) are an explicit decomposition of what our
verifier's GLM prompt should ask. The 400-skill labelled benchmark directly
extends our SKILL-INJECT 40-case set.

**Does it measure what we care about?** F1 per skill — our verifier recall on
skill artifacts. Layer 1 latency (<40ms) benchmarks our semgrep-equivalent fast
path. Cost per query ($0.006) is relevant for our LLM verifier upgrade budget.

→ **Relevance to our framework:**
- **Verifier:** SkillSieve's 4-sub-task decomposition is the best published
  reference for structuring our GLM verifier prompt for skill artifacts.
  Decomposed prompting directly addresses the verifier's weakness on subtle
  contextual injections.
- **Semgrep (Layer 1 analogue):** Our current semgrep static analysis maps to
  SkillSieve's Layer 1 AST/regex triage. SkillSieve filters 86% of benign
  cases in <40ms — matching this benchmark on our semgrep gate would validate
  our fast-path design.
- **Benchmark:** The 400-skill labelled set should be acquired and added to our
  skill-injection test suite.

---

### Paper 16 — Spotlighting

| Field | Value |
|---|---|
| **Title** | Defending Against Indirect Prompt Injection Attacks With Spotlighting |
| **Year** | 2024 |
| **Venue** | arXiv cs.CR — 2403.14720 (Microsoft Research) |
| **Authors** | Hines, Lopez, Hall, Zarfati, Zunger, Kiciman |
| **Link** | https://arxiv.org/abs/2403.14720 |

**Threat model:** Indirect prompt injection via external documents/tool returns
processed alongside user instructions. LLMs cannot reliably distinguish input
source provenance.

**Defense mechanism:** Spotlighting — three modes applied as prompt engineering:
1. **Delimiting:** Wrap untrusted content in explicit delimiters
2. **Datamarking:** Insert per-invocation unique token (e.g. `#$_^%`) into both
   system prompt and untrusted content to signal data provenance
3. **Encoding:** Apply a transformation (e.g. base64 or rot-13) to untrusted
   content, tell the model to decode before reading

**Benchmark:** GPT-family models; specific test case count not published.

**Metrics reported:**
- ASR reduced from >50% to <2%
- "Minimal impact on task efficacy"

**Key result:** Spotlighting reduces ASR from >50% to <2% with negligible
utility impact on GPT-family models.

**Benchmark publicly available:** Code/dataset availability not confirmed.

**Compatible with evidence-package interface?** Indirect. Spotlighting is a
prompt-level defense applied at LLM inference; our framework operates at the OS
execution layer. However, the datamarking concept could be applied to our
verifier prompt — marking `external_environment.content` with a unique token
so the LLM verifier does not confuse injected content with instructions.

**Does it measure what we care about?** ASR reduction (>50% → <2%). No per-
module DR, no eBPF, no sandbox.

→ **Relevance to our framework:**
- **Verifier:** Apply spotlighting (datamarking mode) to our GLM verifier
  prompt: wrap `external_environment.content` with a unique token so the
  verifier is not itself injection-susceptible. This is a direct hardening
  recommendation.
- **Evidence package:** The `prompt_injection_phrases` field in our evidence
  builder should flag content that would bypass spotlighting (i.e., injections
  that work even with delimiters).

---

## Summary Table

| # | Paper | Year | Venue | Benchmark | Cases | Malicious | Public | eBPF | Semgrep | Verifier | Evidence Pkg |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | AgentDojo | 2024 | arXiv/CCS | AgentDojo | 629 | 629 | Yes (GitHub) | No | No | Partial | Partial |
| 2 | InjecAgent | 2024 | ACL | InjecAgent | 1,054 | 1,054 | Yes (GitHub) | No | No | Direct | Partial |
| 3 | SKILL-INJECT | 2026 | arXiv | SkillInject | 202 | ~150? | Yes (GitHub) | No | Partial | Direct | Direct |
| 4 | promptinject-skills | 2025 | arXiv | Unlabelled | N/A | N/A | Yes (GitHub) | No | No | Partial | Partial |
| 5 | AgentSentinel | 2025 | CCS | BadComputerUse | 60 | 60 | Yes (GitHub) | Yes | No | Direct | Direct |
| 6 | BIPIA | 2023 | KDD | BIPIA | ~75+ | ~75+ | Yes (GitHub) | No | No | Partial | Partial |
| 7 | PFI | 2025 | arXiv | AgentDojo+OS | 108 | 108 | Yes (GitHub) | No | No | Direct | Partial |
| 8 | AgentSentry | 2026 | arXiv | AgentDojo | 629 | 629 | Unknown | No | No | Direct | Partial |
| 9 | AgentSight | 2025 | PACMI | None | N/A | N/A | Yes (GitHub) | Yes | No | No | Direct |
| 10 | eBPF-PATROL | 2025 | arXiv | Real-world | N/A | N/A | Unknown | Yes | No | No | No |
| 11 | OSCAR | 2024 | ASE | Internal | ~12K | ~11.6K | No | Partial | Partial | No | Partial |
| 12 | DataDog Dataset | 2023+ | GitHub | Real packages | 27K+ | 27K+ | Yes (GitHub) | No | Yes | No | Partial |
| 13 | R-Judge | 2024 | EMNLP | R-Judge | 569 | ~569 | Yes (GitHub) | No | No | Direct | Direct |
| 14 | SandboxEscapeBench | 2026 | arXiv | SandboxEscape | N/A | N/A | Partial | No | No | No | No |
| 15 | SkillSieve | 2026 | arXiv | ClawHub-400 | 400 | ~50% | Yes | No | Yes | Direct | Partial |
| 16 | Spotlighting | 2024 | arXiv | Internal | N/A | N/A | Unknown | No | No | Partial | Partial |

---

## Benchmark Design Recommendations

### Top 3 Benchmarks to Reuse

**1. DataDog Malicious Software Packages Dataset** (highest priority)
- Why: Real malicious packages with real credential exfiltration, data
  exfiltration, and supply chain attack behaviours. Our 90/90 TP result confirms
  the pipeline works; adding the 15 benign PyPI controls gives us FPR.
- What to add: (a) Per-module DR columns: semgrep-only, eBPF-only, combined;
  (b) `kprobe:security_file_open` vs. strace comparison on credential-access
  events; (c) Expand to 200+ cases using the full malicious-intent manifest.
- Compatible: Yes, already integrated. Evidence package adapter: direct.
- Target metrics: DR, FPR, per-ecosystem F1, trace-method latency delta.

**2. InjecAgent** (second priority)
- Why: 1,054 labelled IPI cases with 17 tools × 62 attacker tools — largest
  publicly available injection corpus. Directly scores our verifier on
  prompt-injection evidence quality.
- What to add: Wrap each test case in our sandbox pipeline; the agent command
  that executes the injection becomes our `current_action`; the tool return
  becomes `external_environment.content`. Ground-truth label becomes verifier
  expected decision (HOLD/BLOCK).
- Compatible: Needs a translator script (~100 lines) mapping InjecAgent JSON
  format to our MDSRequest/evidence-package format.
- Target metrics: Verifier BLOCK rate on injected cases, ALLOW rate on benign
  cases (FPR), latency per case.

**3. SKILL-INJECT + SkillSieve 400-skill benchmark** (third priority)
- Why: SKILL-INJECT is already integrated (40 cases). Adding SkillSieve's
  400-skill labelled set raises our skill-injection coverage by 10×. Together
  they cover obvious, contextual, and social-engineering injection variants.
- What to add: Acquire SkillSieve 400-skill benchmark. Report per-layer
  detection contribution: semgrep (Layer 1 analogue), verifier single-prompt,
  verifier decomposed (4 sub-tasks per SkillSieve Layer 2).
- Compatible: Both use SKILL.md artifact format. Direct integration.
- Target metrics: F1 (compare to SkillSieve baseline 0.421 and their 0.800),
  semgrep DR on skill artifacts, verifier accuracy improvement from adding
  eBPF trace context.

### 1 Benchmark We Should Build Ourselves: eBPF Trace Quality Benchmark

**Name:** EvidenceQualityBench

**Why it must be built:** No existing benchmark measures what we uniquely
provide — the marginal detection gain from adding eBPF/bpftrace evidence to
a static analysis + LLM judge pipeline. R-Judge shows GPT-4o achieves 74.42%
judge accuracy on interaction-only input. Our hypothesis is that adding
`system_trace` (eBPF file/process/network events) and `static_analysis`
(semgrep findings) to the evidence package improves judge accuracy above 74.42%.
No paper has tested this.

**Structure:**
- Take 100–150 cases from DataDog packages (malicious) + benign PyPI controls
- For each case, produce three evidence package variants:
  A. Interaction-only (no trace, no semgrep) — baseline matching R-Judge
  B. + semgrep findings only
  C. + strace only
  D. + bpftrace (with `kprobe:security_file_open` LSM events)
  E. Full (semgrep + bpftrace + reputation placeholder)
- Score the same LLM verifier on each variant
- Report: accuracy, DR, FPR per variant; latency overhead per variant

**Ground-truth labels:** DataDog human-triaged labels (malicious/benign) +
our analyst review of `system_trace` events for each case.

**Key metric to report:** Delta accuracy (variant D vs. variant A) — this
quantifies the value of `kprobe:security_file_open` over interaction-only
judging. This is our primary research contribution.

**Module coverage:**
- eBPF/bpftrace: variant C vs. D comparison
- kprobe:security_file_open: LSM-layer event capture vs. strace
- Semgrep: variant A vs. B comparison
- Verifier: scored across all variants
- Evidence package: the benchmark IS the evidence package quality test

**Estimated effort:** 2–3 days of eval engineering (mostly the evidence package
serialisation and variant generation), using existing DataDog cases already
in our pipeline.

---

## Source Verification Notes

All entries were fetched live from arxiv.org, GitHub, or ACL Anthology during
this scan (2026-05-25). No entry relies solely on training-memory retrieval.

Papers where only the abstract was fetchable (HTML version returned 404 or
403): eBPF-PATROL (abstract only), BIPIA (abstract only). All key numbers for
those papers come from the abstract text.

Papers where the full HTML was successfully fetched and mined for details beyond
the abstract: AgentSentinel (2509.07764), PFI (2503.15547), SKILL-INJECT
(2602.20156), AgentSentry (2602.22724), AgentDojo (2406.13352), InjecAgent
(2403.02691), Spotlighting (2403.14720), OSCAR (2409.09356).

