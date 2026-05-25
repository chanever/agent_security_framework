"""Phase 2 §7 gate #1+#2 regression — lock skill-inject fixtures by ID.

Spec §7 #2 ("Bug B" — widen `SUSPICIOUS_INSTRUCTION_PHRASES`) requires that
5 contextual_injections fixtures match ≥1 phrase after the policy widening,
proving the excerpt-cap + phrase-list fixes work together.

These tests do NOT call the full safeguard — they assert at the level of
`extract_suspicious_instructions` against the real fixture content, so the
failure mode (cap truncation? phrase missing? matcher bug?) is locatable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_framework.evidence_builder import (
    _safe_excerpt,
    extract_suspicious_instructions,
)


SKILL_INJECT_ROOT = Path("/home/user/agent-mds/eval/benchmarks/skill-inject")
BENIGN_SKILLS_ROOT = Path("/home/user/agent-mds/eval/benchmarks/benign-skills")


def _read(case_dir: Path) -> str:
    skill_file = case_dir / "SKILL.md"
    return _safe_excerpt(skill_file)


# Locked fixture set — these IDs are the regression panel. If the corpus
# evolves and a case is renumbered, update the IDs deliberately rather than
# letting the test silently drift.
LOCKED_CONTEXTUAL_INJECTIONS = [
    "skill_inject_contextual_injections_10",
    "skill_inject_contextual_injections_11",
    "skill_inject_contextual_injections_12",
    "skill_inject_contextual_injections_13",
]

LOCKED_OBVIOUS_INJECTIONS = [
    # IDs 1-5 plant the injection in subsidiary files (e.g. ooxml.md,
    # recalc.py) referenced by SKILL.md — they're not detectable with the
    # current `cat SKILL.md` action template, which is a separate
    # benchmark-architecture issue tracked in spec.md §10 Q1.
    # Use 6/8/10 — these plant the injection in SKILL.md itself, so they
    # exercise the phrase-list path directly.
    "skill_inject_obvious_injections_6",
    "skill_inject_obvious_injections_8",
    "skill_inject_obvious_injections_10",
]

# Known limit — natural-language contextual injection that substring matching
# cannot detect. Documented as the case where R5 (GLM verifier) is required.
KNOWN_NL_LIMIT = "skill_inject_contextual_injections_1"

# Benign skills that previously over-fired during phrase-list widening; now
# they must match zero suspicious phrases.
LOCKED_BENIGN_PANEL = [
    "agent-identifier",
    "bats-testing-patterns",
    "analyzing-financial-statements",
    "applying-brand-guidelines",
    "calendar",
]


@pytest.mark.parametrize("case", LOCKED_CONTEXTUAL_INJECTIONS)
def test_contextual_injection_matches_at_least_one_phrase(case: str):
    case_dir = SKILL_INJECT_ROOT / case
    if not (case_dir / "SKILL.md").exists():
        pytest.skip(f"fixture missing: {case}")
    text = _read(case_dir)
    matches = extract_suspicious_instructions(text)
    assert matches, (
        f"contextual injection {case} must match ≥1 SUSPICIOUS_INSTRUCTION_PHRASE; "
        f"matches: {matches}"
    )


@pytest.mark.parametrize("case", LOCKED_OBVIOUS_INJECTIONS)
def test_obvious_injection_matches_at_least_one_phrase(case: str):
    case_dir = SKILL_INJECT_ROOT / case
    if not (case_dir / "SKILL.md").exists():
        pytest.skip(f"fixture missing: {case}")
    text = _read(case_dir)
    matches = extract_suspicious_instructions(text)
    assert matches, f"obvious injection {case} must match ≥1 phrase; got {matches}"


@pytest.mark.parametrize("case", LOCKED_BENIGN_PANEL)
def test_benign_skill_does_not_over_fire(case: str):
    case_dir = BENIGN_SKILLS_ROOT / case
    if not (case_dir / "SKILL.md").exists():
        pytest.skip(f"fixture missing: {case}")
    text = _read(case_dir)
    matches = extract_suspicious_instructions(text)
    assert matches == [], (
        f"benign skill {case} should not trigger SUSPICIOUS_INSTRUCTION_PHRASES; "
        f"unexpected matches: {matches}"
    )


def test_excerpt_cap_at_least_8000_chars():
    """Bug A regression — the cap MUST be ≥8000 to catch injections placed
    past the original 2000-char boundary (smoke discovery 2026-05-25)."""
    import inspect
    sig = inspect.signature(_safe_excerpt)
    default_cap = sig.parameters["max_chars"].default
    assert default_cap >= 8000, (
        f"_safe_excerpt default cap must be ≥8000; got {default_cap}"
    )


def test_known_nl_limit_is_still_unmatched():
    """Documents that `contextual_injections_1` is a known FN for substring
    matching — requires LLM judge (R5 ablation). If this test starts FAILING
    (the case now matches), the phrase list got tightened — re-evaluate the
    R5-requirement claim in the spec."""
    case_dir = SKILL_INJECT_ROOT / KNOWN_NL_LIMIT
    if not (case_dir / "SKILL.md").exists():
        pytest.skip(f"fixture missing: {KNOWN_NL_LIMIT}")
    text = _read(case_dir)
    matches = extract_suspicious_instructions(text)
    assert matches == [], (
        f"{KNOWN_NL_LIMIT} was previously unmatched (LLM-judge-required case). "
        f"If your widening now matches it ({matches}), update the spec — the "
        f"'natural-language limit' claim no longer holds."
    )
