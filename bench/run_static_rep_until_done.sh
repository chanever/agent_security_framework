#!/usr/bin/env bash
set -u

ROOT="/home/jhc7781/agent_prj/agent_security_framework"
PY="$ROOT/.venv/bin/python"
OUT="${OUT:-/tmp/fw_rel_static_rep_guarded.json}"
LOG="${LOG:-/tmp/fw_rel_static_rep_guarded.log}"
SLEEP_SECONDS="${SLEEP_SECONDS:-900}"

cd "$ROOT" || exit 1

if [ ! -x "$PY" ]; then
  echo "Python venv not found: $PY" | tee -a "$LOG"
  exit 1
fi

echo "=== guarded static+reputation benchmark ===" | tee -a "$LOG"
echo "out: $OUT" | tee -a "$LOG"
echo "log: $LOG" | tee -a "$LOG"
echo "sleep_seconds: $SLEEP_SECONDS" | tee -a "$LOG"

attempt=1
while true; do
  echo "" | tee -a "$LOG"
  echo "=== attempt $attempt: $(date -Is) ===" | tee -a "$LOG"

  SECURITY_FRAMEWORK_ENABLED=true \
  SHADOW_SANDBOX_ENABLED=true \
  SECURITY_STATIC_ANALYSIS_ENABLED=true \
  SECURITY_REPUTATION_ANALYSIS_ENABLED=true \
  VERIFIER_MODE=claude_cli \
  SANDBOX_DOCKER_IMAGE=shadow-agent-sandbox:latest \
  CLAUDE_CLI_MAX_TURNS=12 \
  PYTHONUNBUFFERED=1 \
  "$PY" -u bench/framework_reliability.py \
    --cap 0 \
    --out "$OUT" \
    --resume 2>&1 | tee -a "$LOG"

  rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ]; then
    echo "=== benchmark complete: $(date -Is) ===" | tee -a "$LOG"
    exit 0
  fi

  if [ "$rc" -eq 75 ]; then
    echo "=== Claude usage/session limit detected; sleeping ${SLEEP_SECONDS}s before resume ===" | tee -a "$LOG"
    sleep "$SLEEP_SECONDS"
    attempt=$((attempt + 1))
    continue
  fi

  if [ "$rc" -eq 130 ]; then
    echo "=== interrupted; resume later with this same script ===" | tee -a "$LOG"
    exit 130
  fi

  echo "=== benchmark failed with exit code $rc; not retrying ===" | tee -a "$LOG"
  exit "$rc"
done
