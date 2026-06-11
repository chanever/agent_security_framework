# Why chanever's FP rate is higher than CHASE on benign packages

Companion to `bench/chase_ben_comparison.png` (head-to-head) and
`bench/chase_mal_comparison.png` (malicious side).

## Bench setup

Same 23-package corpus, both frameworks, same setup.py directory passed
to both. Corpus shape matches CHASE's paper sampling filter: small
newly-published PyPI packages that ship both `setup.py` and
`__init__.py`. Built by `tools/build_chase_compatible_corpus.py` walking
PyPI RSS, dropped under `bench/corpora/chase_compatible_ben`. Driver:
`bench/run_chase_vs_chanever_small.py`; raw results
`/tmp/chase_vs_chanever_small.json`.

|                       | chanever | CHASE |
|----------------------|---------:|------:|
| TN (correctly passed) | 12       | 21    |
| FP (over-blocked)     | 11       | 0     |
| ERR (crash / OOM)     | 0        | 2     |
| Specificity (on evaluable) | 52.2 % | 100 % |
| Evaluable rate        | 100 %    | 91.3 % |

CHASE's two ERRs are `min() iterable argument is empty` —
`run_chase.py::collect_entrypoint_sourcecodes` raised when the package
had setup.py at an unusual depth. CHASE crashes instead of
fail-safe-blocking, so those don't count against its FP column.

## The 11 chanever FPs break into three concrete root causes

Categorising by reason text from the verifier (`row['chanever']['reason']`):

### Category A — sandbox strace permission failure (5 cases, 45 %)

| Case | Static signal | What blocked |
|------|---------------|--------------|
| `microframex`           | clean | sandbox strace permission denied → no dynamic evidence → HOLD |
| `portmate`              | clean | same |
| `prune-sdk`             | clean | same |
| `pynightmares`          | clean | same |
| `sythonlab-kiu-sdk`     | clean | same |

These are not chanever's static/reputation layers being wrong — the
sandbox sub-system (teammate's area) returned `strace: permission
denied` so the dynamic telemetry block of the evidence package was
empty. Under our `uncertainty_rule` policy the verifier holds when
both static is ambiguous AND dynamic is absent — that's the correct
behaviour but on a benign package it costs an FP.

Fix is environmental (sandbox container CAP\_SYS\_PTRACE), not a
chanever rule change.

### Category B — package published today, zero reputation signal (3 cases, 27 %)

| Case | Detail |
|------|--------|
| `alibabacloud-searchagent20260515` | first upload = install day, 1 version, 1 release |
| `tree-sitter-hujson`               | same shape — newly published |
| `vibetodev`                        | same shape — newly published |

The verifier holds because the package has no community signal: no
download history, no GitHub stars, no transitive dependents — exactly
the threat pattern of an attacker uploading a typosquat today and
hoping an agent installs it before anyone notices. We accept this is
correct behaviour against the threat model (a real attacker's package
also looks like this), but CHASE doesn't make a reputation query at
all so it never produces this signal and never holds on it.

This is a **threat-model-driven false positive**, not a bug. The
trade-off is: we catch day-zero typosquat uploads CHASE cannot, at the
cost of holding on legitimate brand-new packages. Closing this gap
would require a separate signal that distinguishes "new but from an
established maintainer" — currently we don't query PyPI's
`Author-email` against any reputation set.

### Category C — guarddog install_time code-execution rule fired (3 cases, 27 %)

| Case | Finding |
|------|--------|
| `dforge-cli`                       | `guarddog_unscoped.code-execution` on `setup.py:26` |
| `wexample-wex-addon-dev-python`    | `guarddog_unscoped.code-execution` on `setup.py:55` |
| `wexample-wex-addon-services-db`   | `guarddog_unscoped.code-execution` on `setup.py:25` |

GuardDog's vendored rule pack flags `os.system` / `subprocess.run` /
`shell=True` patterns inside `setup.py`. Combined with our verifier
prompt update (commit `873c4cf`: "weight install_time findings
heavily"), this is now a near-deterministic block.

This is where chanever's design is fundamentally stricter than
CHASE's. CHASE reads the same `setup.py` source but its multi-agent
chain treats shell-exec as a *signal* the Supervisor weighs against
the Web Researcher's reputation finding — so a legitimate package that
runs `apt-get install …` in setup.py to compile a C extension reads
as benign in CHASE's pipeline and as suspicious in ours. We chose
the stricter side because the threat-model question is "should the
agent be allowed to install this in the user's environment" not "is
this a known supply-chain attack" — and arbitrary install-time shell
execution is the textbook delivery vector regardless of intent.

We could relax this by adding a reputation override (if reputation
score > N, demote install_time code-exec from `block` to `hold`) but
that re-introduces the FP source we just removed from Category B.

## Structural sources of asymmetry (independent of any single case)

Documented for completeness; these are why even after fixing each
category above we'd still have a non-zero gap vs CHASE's reported 0.08
% on its 2500-pkg benign corpus.

### 1. Wider file scope on the static side

CHASE only reads `setup.py` plus the top-level `__init__.py`
(`run_chase.py::collect_entrypoint_sourcecodes`). chanever's
`pypi_analyzer` runs semgrep `p/security-audit` over **every** `*.py`.
Big libraries with realistic crypto/network code produce more
use-time findings → larger verifier context → more chances to hold.

Already mitigated in commit `873c4cf` via the `install_time | use_time`
tagging — use_time hits are now low-weighted — but the signal is still
present.

### 2. OSV vulnerability lookup

CHASE does **no** OSV / GHSA query at all. chanever's `pypi_reputation`
emits a vuln-count signal even after the version-aware filter in
`reputation/_osv.py` filters out CVEs already fixed in the target
version. On established libraries with many genuinely-affecting CVEs
(e.g. pillow, cryptography) the signal is non-zero and contributes.

### 3. Single verifier call vs CHASE's 4-agent loop

chanever runs **one** Claude call; CHASE runs Supervisor +
Deobfuscator + Web Researcher + Formatter, each able to correct
another. CHASE's Web Researcher in particular can dig up reputation
signal mid-decision. Our single-pass verifier cannot recover from an
ambiguous evidence package the way a multi-step agent can. We accepted
this trade for latency: chanever median 45-90s, CHASE 3-5 min/case.

### 4. Broader threat model

CHASE: "is this PyPI package malicious?" — binary, package-level.
chanever: "should this action be allowed *in this agent context*?" —
includes install commands, repo clones, npm add, skill loads, all
through `ShadowSandboxSafeguard.inspect`. The context layer can over-
block on a benign package that just looks suspicious in a particular
agent task.

### 5. Build-system asymmetry

`run_chase.py` crashes on packages without setup.py (see CHASE's 2 ERR
rows above). chanever evaluates all 23 cases. On a corpus that
includes pyproject-only modern packages the denominator gap widens
further in CHASE's favour for FP rate, even though that's an
artifact of CHASE skipping the harder cases.

## Summary

The 11 chanever FPs on this 23-pkg head-to-head are:

* 5 of 11 (45 %) come from **sandbox strace permission failures** — environmental, not a chanever-detection issue.
* 3 of 11 (27 %) come from **day-zero packages with no reputation signal** — intentional threat-model trade-off (day-zero typosquat coverage).
* 3 of 11 (27 %) come from **install-time shell exec in setup.py** — intentional threat-model strictness (CHASE treats this as soft signal, we treat it as hard).

If the sandbox env issue is fixed (Category A) and we make no other
changes, chanever's FP count on this slice would drop from 11 → 6 and
specificity from 52.2 % → 73.9 %. The remaining 6 are by-design under
our threat model; closing them further means accepting CHASE's
narrower "malware-only" framing.
