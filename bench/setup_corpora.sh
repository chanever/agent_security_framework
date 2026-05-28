#!/bin/bash
# Populate bench/corpora/ from public sources so the framework reliability
# bench is reproducible on a fresh clone.
#
# Reads manifests under bench/manifests/ and produces the following layout
# under bench/corpora/ (gitignored):
#
#   datadog-pypi/<case>/artifact/<unpacked>/    ← DataDog public dataset
#   datadog-npm/<case>/artifact/<unpacked>/     ← DataDog public dataset
#   benign-pypi/<name>/artifact/<unpacked>/     ← PyPI registry sdist
#   benign-npm/<name>/artifact/package/         ← npm registry tarball
#   benign-repos/<name>/                        ← github clones (--depth 1)
#   benign-skills/<name>/                       ← anthropics/skills subset
#
# Requirements (all standard *nix tools):
#   curl  git  python3  tar  unzip
#
# Usage:
#   bash bench/setup_corpora.sh              # populate everything
#   bash bench/setup_corpora.sh --only datadog       # subset
#   bash bench/setup_corpora.sh --only benign-pypi   # one ecosystem
#
# Idempotent: skips entries whose target dir already exists. Re-run safely.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MANIFESTS="$HERE/manifests"
CORPORA="$HERE/corpora"
PY="${PY:-python3}"
DD_PASSWORD="${DD_PASSWORD:-infected}"

ONLY=""
if [ "${1:-}" = "--only" ]; then
  ONLY="${2:-}"
fi
want() { [ -z "$ONLY" ] || [[ "$1" == *"$ONLY"* ]]; }

mkdir -p "$CORPORA"

# ───────────────────────── DataDog adversarial mirror ─────────────────────────
# samples are password-protected zips ("infected" by convention) hosted on
# the public github.com/DataDog/malicious-software-packages-dataset repo.
fetch_datadog() {
  local family="$1" manifest="$2"
  want "datadog" || want "$family" || return 0
  echo "=== $family ==="
  local ok=0 skip=0 fail=0
  while IFS=$'\t' read -r case_dir pkg sample url; do
    [ -z "$case_dir" ] && continue
    local out="$CORPORA/$family/$case_dir/artifact"
    if [ -d "$out" ] && [ "$(ls -A "$out" 2>/dev/null)" ]; then
      skip=$((skip+1)); echo "  skip $case_dir"; continue
    fi
    mkdir -p "$CORPORA/$family/$case_dir"
    local zip="$CORPORA/$family/$case_dir/$sample"
    if ! curl -sfL "$url" -o "$zip"; then
      fail=$((fail+1)); echo "  FAIL $case_dir (curl)"; continue
    fi
    mkdir -p "$out"
    if ! unzip -qq -P "$DD_PASSWORD" "$zip" -d "$out" 2>/dev/null; then
      fail=$((fail+1)); echo "  FAIL $case_dir (unzip)"
      rm -rf "$CORPORA/$family/$case_dir"; continue
    fi
    rm -f "$zip"
    cat > "$out/agent_mds_benchmark.json" <<EOF
{"benchmark":"DataDog malicious $family dataset","category":"malicious_intent","package":"$pkg","sample":"$sample","source":"$url"}
EOF
    ok=$((ok+1)); echo "  ok   $case_dir ($pkg)"
  done < "$manifest"
  echo "  $family: ok=$ok skip=$skip fail=$fail"
}

[ -f "$MANIFESTS/datadog-pypi.tsv" ] && fetch_datadog "datadog-pypi" "$MANIFESTS/datadog-pypi.tsv"
[ -f "$MANIFESTS/datadog-npm.tsv"  ] && fetch_datadog "datadog-npm"  "$MANIFESTS/datadog-npm.tsv"

# ───────────────────────── benign-pypi (PyPI registry) ───────────────────────
fetch_benign_pypi() {
  want "benign" || want "benign-pypi" || return 0
  local manifest="$MANIFESTS/benign-pypi.txt"
  [ -f "$manifest" ] || return 0
  echo "=== benign-pypi ==="
  local ok=0 skip=0 fail=0
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    local case_dir="$CORPORA/benign-pypi/$pkg"
    local out="$case_dir/artifact"
    if [ -d "$out" ] && [ "$(ls -A "$out" 2>/dev/null)" ]; then
      skip=$((skip+1)); echo "  skip $pkg"; continue
    fi
    local url
    url=$("$PY" -c "
import json, urllib.request
try:
    d = json.load(urllib.request.urlopen('https://pypi.org/pypi/$pkg/json', timeout=10))
    sdist = next((u for u in d.get('urls',[]) if u.get('packagetype')=='sdist'), None)
    print(sdist['url'] if sdist else '')
except Exception:
    print('')" 2>/dev/null)
    if [ -z "$url" ]; then
      fail=$((fail+1)); echo "  FAIL $pkg (no sdist)"; continue
    fi
    mkdir -p "$out"
    local sdist="$case_dir/$(basename "$url")"
    if curl -sfL "$url" -o "$sdist" && tar -xzf "$sdist" -C "$out" 2>/dev/null; then
      rm -f "$sdist"; ok=$((ok+1)); echo "  ok   $pkg"
    else
      fail=$((fail+1)); echo "  FAIL $pkg (download/untar)"
      rm -rf "$case_dir"
    fi
  done < "$manifest"
  echo "  benign-pypi: ok=$ok skip=$skip fail=$fail"
}
fetch_benign_pypi

# ───────────────────────── benign-npm (npm registry) ─────────────────────────
fetch_benign_npm() {
  want "benign" || want "benign-npm" || return 0
  local manifest="$MANIFESTS/benign-npm.txt"
  [ -f "$manifest" ] || return 0
  echo "=== benign-npm ==="
  local ok=0 skip=0 fail=0
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    local case_dir="$CORPORA/benign-npm/$pkg"
    local out="$case_dir/artifact"
    if [ -d "$out" ] && [ "$(ls -A "$out" 2>/dev/null)" ]; then
      skip=$((skip+1)); echo "  skip $pkg"; continue
    fi
    local url
    url=$("$PY" -c "
import json, urllib.request
try:
    d = json.load(urllib.request.urlopen('https://registry.npmjs.org/$pkg/latest', timeout=10))
    print(d.get('dist',{}).get('tarball',''))
except Exception:
    print('')" 2>/dev/null)
    if [ -z "$url" ]; then
      fail=$((fail+1)); echo "  FAIL $pkg (no tarball)"; continue
    fi
    mkdir -p "$out"
    local tarball="$case_dir/$(basename "$url")"
    if curl -sfL "$url" -o "$tarball" && tar -xzf "$tarball" -C "$out" 2>/dev/null; then
      rm -f "$tarball"; ok=$((ok+1)); echo "  ok   $pkg"
    else
      fail=$((fail+1)); echo "  FAIL $pkg (download/untar)"
      rm -rf "$case_dir"
    fi
  done < "$manifest"
  echo "  benign-npm: ok=$ok skip=$skip fail=$fail"
}
fetch_benign_npm

# ───────────────────────── benign-repos (git clone --depth 1) ────────────────
fetch_benign_repos() {
  want "benign" || want "benign-repos" || return 0
  local manifest="$MANIFESTS/benign-repos.tsv"
  [ -f "$manifest" ] || return 0
  echo "=== benign-repos ==="
  local ok=0 skip=0 fail=0
  while IFS=$'\t' read -r name url; do
    [ -z "$name" ] && continue
    local case_dir="$CORPORA/benign-repos/$name"
    if [ -d "$case_dir" ] && [ "$(ls -A "$case_dir" 2>/dev/null)" ]; then
      skip=$((skip+1)); echo "  skip $name"; continue
    fi
    if git clone --depth 1 -q "$url" "$case_dir" 2>/dev/null; then
      rm -rf "$case_dir/.git"  # save space; bench only needs working tree
      ok=$((ok+1)); echo "  ok   $name"
    else
      fail=$((fail+1)); echo "  FAIL $name"
    fi
  done < "$manifest"
  echo "  benign-repos: ok=$ok skip=$skip fail=$fail"
}
fetch_benign_repos

# Note: benign-skills + benign-tools + malicious-repos + skill-inject +
# toolhijacker ship as fixtures under ``bench/fixtures/`` (handcrafted, text-
# only, ~20MB) and are version-controlled. No download needed for those.

echo
echo "=== final counts under bench/corpora/ (downloadable) ==="
for f in datadog-pypi datadog-npm benign-pypi benign-npm benign-repos; do
  n=$(ls "$CORPORA/$f" 2>/dev/null | wc -l)
  printf "  %-15s %3d cases\n" "$f" "$n"
done
echo "=== fixtures (already shipped under bench/fixtures/) ==="
for f in malicious-repos skill-inject toolhijacker benign-tools benign-skills; do
  n=$(ls "$HERE/fixtures/$f" 2>/dev/null | wc -l)
  printf "  %-15s %3d cases\n" "$f" "$n"
done
