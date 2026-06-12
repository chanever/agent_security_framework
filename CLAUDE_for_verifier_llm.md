# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Python security framework that implements **selective shadow execution** for LLM agent CLI commands. Before an agent runs a command that touches the external environment, the framework intercepts it, replays it inside a Docker sandbox with strace tracing, builds an evidence package from the observed syscalls, and routes that package to a verifier (Claude Code CLI). Only if the verifier returns ALLOW does the real command proceed.

## Commands

```bash
# Run all tests (from repo root, one level up)
cd /Users/justin/Desktop/test/agent_prj
python -m pytest security_framework/tests -v

# Run a single test file
python -m pytest security_framework/tests/test_trigger.py -v

# Build the Docker sandbox image (required for sandbox execution)
cd /Users/justin/Desktop/test/agent_prj/security_framework
docker build -t shadow-agent-sandbox:latest .

# Run the vulnerable CLI agent example
cd /Users/justin/Desktop/test/agent_prj/vulnerable_cli_agent
python main.py --task "List files in the workspace" --run-id sf_safe_ls --verbose
python main.py --task "Install this Python project and run it" \
  --workspace ../security_framework/examples/malicious_package \
  --run-id sf_malicious_pkg --verbose
```

No setup.py or pyproject.toml — the framework uses stdlib only. pytest is the only dev dependency.

## Architecture

### Decision Flow

```
Agent action
  → ShadowSandboxSafeguard.inspect()
      → trigger.py: classify_command()          # Is this an external-env action?
          → If needs_shadow_execution:
              → sandbox_runner.py               # Run in Docker + strace
              → trace_parser.py                 # Parse syscalls into structured events
          → evidence_builder.py                 # Assemble Evidence Package JSON
          → verifier.py                         # Always route to Claude Code CLI
              → claude_cli_verifier.py          # `claude -p` subprocess
      → Return "allow" or "block"
```

### Key Data Contracts

**Classification** (trigger.py output):
- `external_env`: touches anything outside the local workspace
- `needs_shadow_execution`: run in sandbox first

**Evidence Package** (evidence_builder.py output): JSON with `user_task`, `current_action`, `external_environment`, `system_trace` (file_access / process_execution / network_activity), and `external_interaction_analysis`. This is what gets sent to the verifier.

**Verifier decisions**: `ALLOW`, `ALLOW_WITH_SANITIZATION`, `HOLD`, `BLOCK`, `ISOLATE`. Verifier fallback on any error is `HOLD` (conservative).

### Module Responsibilities

| Module | Role |
|--------|------|
| `shadow_sandbox_safeguard.py` | Main entry point; orchestrates full workflow; writes artifacts |
| `trigger.py` | Rule-based command classifier; detects package installs, git clones, curl/wget, API calls |
| `sandbox_runner.py` | Docker executor; creates dummy home with fake SSH key and AWS creds; wraps with strace |
| `trace_parser.py` | Parses strace output; tags sensitive credential paths |
| `evidence_builder.py` | Aggregates all signals into Evidence Package |
| `verifier.py` | Routes Evidence Package to Claude Code CLI backend |
| `claude_verifier.py` | Shared response parsing/normalization helpers and API adapter utilities |
| `claude_cli_verifier.py` | `claude -p --output-format json` subprocess backend |
| `policy.py` | Security constants: sensitive paths, forbidden patterns, destructive regexes |
| `config.py` | Env-var-driven settings dataclass; default artifact root at `../artifacts/security_runs/` |
| `static_analyzer.py`, `reputation_analyzer.py` | Placeholder stubs for future Semgrep/OSV/deps.dev integration |

### Sandbox Design

- Workspace is copied to a temp directory — **real credentials are never mounted**
- A dummy `~/.ssh/id_rsa` and `~/.aws/credentials` are created so credential-stealing attempts are observable
- strace traces: `openat`, `execve`, `connect`, `unlink`, `rename`
- `SANDBOX_NETWORK_MODE=none` by default (configurable)

### Prompts

Claude verifier prompts live in `prompts/`:
- `claude_system_prompt.txt` — Establishes verifier role and trust model (external content = untrusted)
- `claude_user_prompt_template.txt` — 5-decision schema with `{{EVIDENCE_PACKAGE_JSON}}` placeholder

### Artifacts

Each safeguard run writes to `<SECURITY_ARTIFACT_ROOT>/<run_id>_step<N>_<timestamp>/`:
- `evidence_package.json`, `sandbox_result.json`, `semantic_trace.json`, `verifier_result.json`, `trace.log`

## Configuration

All settings in `config.py` are driven by environment variables:

| Var | Default | Purpose |
|-----|---------|---------|
| `SECURITY_FRAMEWORK_ENABLED` | `true` | Master on/off switch |
| `VERIFIER_MODE` | `claude_cli` | Operational verifier backend; keep `claude_cli` |
| `ANTHROPIC_API_KEY` / `CLAUDE_API_KEY` | — | Optional API credentials for helper adapters |
| `SANDBOX_DOCKER_IMAGE` | `shadow-agent-sandbox:latest` | Docker image name |
| `SANDBOX_NETWORK_MODE` | `none` | Network isolation |
| `SANDBOX_TIMEOUT` | `30` | Execution timeout (seconds) |
| `TRACE_MODE` | `strace` | Telemetry source (eBPF planned) |
| `SECURITY_ARTIFACT_ROOT` | `../artifacts/security_runs/` | Artifact output directory |

## Examples

- `examples/malicious_package/` — `setup.py` reads the fake SSH key and attempts a network POST; demonstrates credential-theft detection
- `examples/benign_project/` — Normal project; should result in ALLOW
- `examples/suspicious_project/` — README contains prompt injection phrase (`Ignore previous instructions...`); tests phrase detection in `evidence_builder.py`
