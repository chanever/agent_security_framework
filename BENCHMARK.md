# BENCHMARK — chanever framework 평가 도구

이 문서는 PR #1에 포함된 평가 harness(`bench/`)가 **무엇을 측정하고, 어떻게
동작하며, 왜 이 설계를 선택했는지** 설명합니다. 최종 detection rate / FPR
숫자 발표는 Phase 3(분리 PR)에서 N≥200 stratified suite + mean-of-3 결과로
이루어집니다. 본 PR은 **harness 인프라 + 모듈별 검증 게이트**까지만 다룹니다.

---

## 1. 무엇을 측정하는가

agent action 한 건마다 `ShadowSandboxSafeguard.inspect(action, context)`이
출력하는 **이진 결정** (`allow` / `block`)을 라벨링된 ground truth와
비교합니다. 측정 4축:

| 메트릭 | 정의 |
|--------|------|
| Detection Rate (DR) | TP / (TP+FN) — malicious 케이스를 block한 비율 |
| False Positive Rate (FPR) | FP / (FP+TN) — benign 케이스를 잘못 block한 비율 |
| p50 latency | `safeguard.inspect()` 한 번에 걸린 wall-clock 중앙값 |
| Evidence coverage (malicious만) | `system_trace.{lsm_events ∪ file_access}`가 핵심 sensitive op를 잡은 비율 |

부가 — F1, precision/recall per family, mock vs GLM verifier 비교,
ablation row별 기여도 분리, 결정 flip rate(GLM 비결정성 모니터링).

---

## 2. 벤치마크 데이터 출처 — 직접 만들지 않고 검증된 corpora 재사용

| Family | 출처 | 라벨 정확도 | 우리 N |
|--------|------|-------------|--------|
| **malicious-repos** | `agent_mds/eval/benchmarks/malicious-repos/` — agent-mds 팀이 손으로 만든 시나리오 8개 (CI helper, data cleaner, doc converter 등) | 100% (manifest `malicious: true`) | 8 |
| **datadog-pypi** | DataDog/malicious-software-packages-dataset (27,165 인간 triaged PyPI samples) | 인간 검증 | 50 (cap 30) |
| **datadog-npm** | 같은 corpus, npm 쪽 | 인간 검증 | 50 (cap 30) |
| **skill-inject** | aisa-group/skill-inject (40 obvious + contextual 인젝션 페어, arXiv 2602.20156) | 작성자 라벨 | 40 (cap 30) |
| **toolhijacker** | agent-mds — tool-selection hijacking 시나리오 11개 | dir prefix `malicious-`/`benign-` | 11 |
| **benign-pypi** | agent-mds — 인기 PyPI 패키지 (attrs/certifi/click 등) | 모두 benign | 15 |
| **benign-skills** | agent-mds — 합법적 skill 디스크립터 | 모두 benign | 10 |
| **benign-tools** | agent-mds — 합법적 tool 디스크립터 | 모두 benign | 8 |
| **cloneguard-repos** | agent-mds — 봇 자동 생성 malicious repo | manifest | 40 |
| **gate-policy-controls** | agent-mds — 정책 edge case | manifest | 1 |

총 **232 케이스**가 `bench/action_templates.py`의 builder를 통과 (corpus
integrity check 통과 완료).

새로운 corpus를 만들지 않는 이유: 우리가 만들면 (a) 라벨 검증 없음,
(b) chanever framework가 자기 룰을 가르친 데이터로 측정하는 contamination 위험,
(c) 다른 시스템과 비교 불가. 기존 공개 corpus를 재사용하면 직접 비교 가능합니다.

---

## 3. 어떻게 동작하는가 — agent 행동을 simulate

각 fixture에 대해 builder가 **agent가 그 케이스를 만났을 때 가장 자연스럽게
emit할 단일 command**를 결정합니다. 예:

| Family | Action template | 이유 |
|--------|-----------------|------|
| malicious-repos | `pip install .` | agent가 워크스페이스의 Python 프로젝트를 받으면 가장 흔한 동작 |
| datadog-pypi | `pip install <pkg>` | 실제 PyPI 패키지 install — 이때 setup.py의 install hook이 실행됨 |
| skill-inject | `cat SKILL.md` | agent가 skill 디스크립터를 읽는 read-only 동작 |
| toolhijacker | `cat tool.md` | tool 디스크립터 읽기 |
| benign-pypi | `pip install <pkg>` | malicious와 동일 패턴 — framework가 이걸 분리할 수 있어야 진짜 가치 |

template들은 `bench/action_templates.py`에 잠겨 있고 fixture 존재 여부를
런타임이 아니라 **테스트 시점에 검증**합니다 — 예전 smoke run에서 silently
fall through하던 `cat skill.md`(소문자, 파일 없음) 같은 ground-truth-invert
버그를 방지합니다.

생성된 `(action, context)`는 `ShadowSandboxSafeguard.inspect()`에 그대로
전달되어 실제 파이프라인을 통과합니다:

```
trigger.classify_command(command, context)
  → external_target_extractor
  → static_analyzer (semgrep + GuardDog 룰)
  → sandbox_runner (strace 또는 bpftrace 모드)
  → trace_parser → event_logger (formatted_events + process_tree)
  → evidence_builder → write_evidence_package
  → verifier (mock 규칙 또는 GLM = claude CLI subprocess)
  → safeguard binary decision
```

`SHADOW_SANDBOX_ENABLED=false` 모드는 sandbox docker container를 끄고
(정적 평가만) 측정하기 위한 옵션입니다 — sandbox-required-then-disabled →
auto block 같은 artifact을 명시적으로 격리하는 ablation row 용도.

---

## 4. 무엇을 어떻게 측정하는지 — 모듈별 검증 (Phase 2)

PR #1에는 **모듈별 quality gate 7건**이 포함됩니다. 각 게이트는 사이즈 ≥ 30
의 labeled corpus에서 ≤ 1 miss를 통과 기준으로 합니다 (95% 일측 LCB ≥ 90%
recall):

| Gate | 모듈 | corpus | 통과 기준 |
|------|------|--------|----------|
| #1 | `policy.SUSPICIOUS_INSTRUCTION_PHRASES` | skill-inject obvious + contextual 23 | ≥ 80% 매치 |
| #2 | `evidence_builder._safe_excerpt` cap | 5 locked contextual_injection IDs | cap ≥ 8000 + phrase 매치 |
| #3 | `trigger.classify_command` | 72 hand-labeled commands | ≤ 1 miss |
| #4 | `external_target_extractor` | 34 commands | ≤ 1 miss |
| #5 | `sandbox_runner` strace | live docker on malicious-repo | execve trace 캡쳐 |
| #6 | `sandbox_runner` bpftrace | live cgroup-scoped probe | `lsm_events` non-empty |
| #7 | `static_analyzer` semgrep + GuardDog | live on datadog-pypi 3+ | finding ≥ 1 |

모듈 단위 검증은 통계적으로 valid한 sub-corpus에서 합니다. **전체 framework
DR/FPR claim은 Phase 3 후속 PR에서 200+ case stratified suite + 3회 평균으로
보고**됩니다.

---

## 5. 왜 이 벤치마크 설계가 좋은가 — 5가지 honest framing

**(1) 직접 비교 가능한 corpus 사용** — DataDog malicious packages, SKILL-INJECT,
AgentSentinel BadComputerUse(추후 translator) 같은 published corpora를
재사용. 새 데이터셋을 만들면 다른 시스템과 비교 불가.

**(2) Honest FPR 약속** — benign corpus N ≥ 20 per family 미달 시 `N=` flag로
공개. AgentSentinel paper(60 cases total)나 agent-mds 이전 report
(2 benign)는 통계적으로 의미 있는 FPR을 못 냅니다. 우리는 부족한 family는
명시적으로 표시.

**(3) Action-level evaluation의 한계 명시** — 우리는 단일 agent action을
측정합니다. AgentDojo/PFI 같은 trajectory-level attack은 별도 axis. PR description에서
이 한계를 숨기지 않음.

**(4) Sandbox required-but-disabled artifact을 ablation으로 격리** — `pip install`은
sandbox 없으면 자동 block되어 FPR을 인위적으로 부풀립니다. 이게 framework의
보수성인지 측정 artifact인지 분리하기 위해 R1(no sandbox) row를 명시.

**(5) GLM verifier 비결정성을 mean-of-3 + flip-flag로 노출** — Claude 같은 LLM
judge는 같은 prompt에 다른 결정 가능. 단일 run 숫자에 발표하지 않고
케이스별 flip rate도 함께 표시.

**(6) Module ablation row를 publish** — R0 base / R1 -sandbox / R2 -semgrep /
R3 -phrase / R4 strace→bpftrace로 어떤 모듈이 어떤 catch에 기여하는지
attribution table을 제공. SkillSieve가 layer-attribution을 publish하지만
**observation-mode axis (strace vs bpftrace+kprobe-LSM)** 에서는 우리가 첫 publish.

---

## 6. 실행 방법

### 모듈별 단위 게이트 (빠른 검증, docker 불필요)

```bash
cd /path/to/agent_security_framework
pytest tests/ -q
# 201 passed, 1 skipped (Live semgrep는 SEMGREP_LIVE=1로 활성)
```

### 정적 모드 smoke (sandbox 없음, ~1분)

```bash
SECURITY_ARTIFACT_ROOT=/tmp/bench python -u bench/run_smoke.py --no-sandbox
```

### sandbox 모드 smoke (~15분, docker 필요)

```bash
# 1) sandbox 이미지 빌드 (최초 1회)
docker build -t shadow-agent-sandbox:latest .

# 2) smoke
SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
SECURITY_ARTIFACT_ROOT=/tmp/bench \
python -u bench/run_smoke.py
```

### GLM verifier (Claude CLI 필요)

```bash
# Claude OAuth 로그인이 되어 있다고 가정 (API key 불필요)
VERIFIER_MODE=glm SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
python -u bench/run_smoke.py
```

결과는 `bench/smoke_results.json`에 confusion + 케이스별 결정 + 트리거 이유와
함께 저장됩니다.

### Live infrastructure gates

```bash
# probe.bt live attach + semgrep + GuardDog 룰 통합 검증
python -u bench/run_live_gates.py
```

### 모듈별 신뢰성 검증 — labelled corpus 위 contingency

평판/정적 모듈이 **자기가 주장하는 일을 실제로 하는지**를 라벨링된 패널 위에서
검증하는 harness 두 개. "검출률을 높였다"가 아니라 "모듈이 X라고 말하면 X가
ground truth와 맞는가"를 정직하게 표로 보여주는 것이 목적.

```bash
# 평판 모듈 (docker 불필요, 외부 API 호출)
python -u bench/reputation_reliability.py
#   pypi/npm/repo/skill 4종 × {benign-popular, known-malicious,
#   typosquat-suspect, nonexistent} 패널 → known-bad 판정이 출처(DataDog/OSSF)
#   인용과 함께 맞는지 대조

# 정적 모듈 (docker semgrep, 케이스당 최대 semgrep_timeout초)
python -u bench/static_analysis_reliability.py --cap 6
```

정적 모듈 contingency (cap 6, 패밀리별):

| family | 결과 |
|---|---|
| datadog-pypi (malicious) | 6 TP — packed 페이로드는 semgrep timeout이어도 `_obfuscation` 휴리스틱이 탐지 |
| malicious-repos (malicious) | 4 TP / 1 FN / 1 UNAVAIL |
| skill-inject (malicious) | 6 TP — `cross-file-split` phrase walk |
| benign-pypi (benign) | 6 TN — **0 FP** (난독화 휴리스틱이 정상 대형 모듈을 오탐하지 않음) |
| benign-skills (benign) | 5 TN / 1 FP |

신뢰성 설계 포인트:

- **UNAVAIL은 FP/FN과 분리 집계** — docker 미동작 등 "분석기가 못 돈 것"을
  "틀린 판정"으로 오염시키지 않음 (timeout은 더 이상 UNAVAIL이 아니라, 휴리스틱
  결과를 담은 `success`).
- **난독화 휴리스틱은 packing density(bytes/line)** 기준이라 정상 대형 소스
  (click `core.py` 137KB)는 통과하고 packed 페이로드(EZBEAMER 6800 bytes/line)만
  잡음. byte-entropy는 정상 소스가 더 높아 채택하지 않음(근거는 `_obfuscation.py`
  docstring).
- 남은 1 FP(`benign-skills/agent-identifier`)는 난독화가 아니라
  `chanever-skill-cross-file-split`이 일반 문구 `'send to'`에 반응한 것 —
  phrase list 정밀도 이슈로 별도 추적.

---

## 7. 비교 대상 (Phase 3 PR에서 실측)

| System | 보고된 DR / FPR | 우리의 위치 |
|--------|----------------|-------------|
| AgentSentinel (CCS '25) | DSR 79.6% / FPR 10.8% (N=60) | 더 큰 benign panel에서 측정 예정 |
| OSCAR (ASE '24) | F1=0.95 npm / 0.91 PyPI | 우리는 install-time only, fuzz 미적용 → 더 낮을 것 |
| SkillSieve | F1=0.800 (vs ClawVet 0.421) | mock verifier로는 0.421 위, GLM verifier로는 0.800 목표 |
| agent-mds (이전 자체 report) | DR=1.0 on 50 (benign N=2) | benign N 부족으로 FPR 신뢰성 부재 — 우리는 다름 |

이 표의 우리 칸은 PR #1에서는 **TBD pending Phase 3 measurement**. 본 PR은
inf rastructure + 모듈별 게이트까지만 검증된 상태로 merge합니다.
