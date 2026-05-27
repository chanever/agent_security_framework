"""Known-bad lists — cited primary sources for each artifact type.

The per-type reputation modules consume these lists to surface an explicit
*negative* trust signal. **Each entry must have a documented primary source**
(an audit report, registry quarantine, or peer-reviewed paper). Curation
discipline is the entire point: a hardcoded blocklist with no traceable
source is undefendable; one with cited sources is auditable.

Active sources:

- **DataDog Malicious Software Packages Dataset** (Apache-2.0, public)
  https://github.com/DataDog/malicious-software-packages-dataset
  Human-triaged corpus of confirmed malicious PyPI / npm packages.
  Our copy is at ``agent-mds/eval/benchmarks/datadog-{pypi,npm}/`` and is
  loaded lazily by ``load_known_bad_*``.

- **OpenSSF malicious-packages** (Apache-2.0, OSF Foundation operated)
  https://github.com/ossf/malicious-packages — confirmed malicious packages
  across pypi/npm/rubygems/cargo. Not yet wired (TODO: fetch at install time
  and cache locally). Listed here so the source is documented even for
  future expansion.

- **OSV.dev MAL-records** (CC-BY-4.0, public)
  https://osv.dev — MAL-YYYY-XXXX advisories for confirmed malicious
  packages. Already covered by ``_osv.query`` in the per-type modules,
  which surfaces ``vuln_count`` including MAL- entries.

- **SkillSieve paper** (arXiv:2604.06550, April 2026) + Koi Security
  ClawHub audit (Jan-Feb 2026). Cited in ``skill_reputation`` for the
  ``hightower6eu`` author group attribution.

- **GitHub Advisory Database — Malware category** (CC-BY-4.0, public)
  https://github.com/advisories?query=type%3Amalware — fetched per-repo
  by ``repo_reputation._query_github_advisories``.

If you add an entry to any of the lists below, also append the primary
source URL and the date you verified it.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path


# Default location of the DataDog corpus mirror. Override via env var
# DATADOG_CORPUS_ROOT for a different filesystem layout.
import os
DATADOG_CORPUS_ROOT = Path(os.environ.get(
    "DATADOG_CORPUS_ROOT",
    "/home/user/agent-mds/eval/benchmarks",
))


def _strip_prefix(name: str, prefix: str) -> str:
    return name[len(prefix):] if name.startswith(prefix) else name


@lru_cache(maxsize=1)
def load_known_bad_pypi_packages() -> frozenset[str]:
    """Confirmed malicious PyPI package names.

    Primary source: DataDog Malicious Software Packages Dataset, human-
    triaged corpus mirrored at ``datadog-pypi/datadog_pypi_malicious_intent_*``.
    """
    root = DATADOG_CORPUS_ROOT / "datadog-pypi"
    if not root.is_dir():
        return frozenset()
    return frozenset(
        _strip_prefix(p.name, "datadog_pypi_malicious_intent_").lower()
        for p in root.iterdir()
        if p.is_dir() and p.name.startswith("datadog_pypi_malicious_intent_")
    )


@lru_cache(maxsize=1)
def load_known_bad_npm_packages() -> frozenset[str]:
    """Confirmed malicious npm package names.

    Primary source: DataDog Malicious Software Packages Dataset, human-
    triaged corpus mirrored at ``datadog-npm/datadog_npm_malicious_intent_*``.
    """
    root = DATADOG_CORPUS_ROOT / "datadog-npm"
    if not root.is_dir():
        return frozenset()
    return frozenset(
        _strip_prefix(p.name, "datadog_npm_malicious_intent_").lower()
        for p in root.iterdir()
        if p.is_dir() and p.name.startswith("datadog_npm_malicious_intent_")
    )


# GitHub orgs documented as malicious in published audits / incident reports.
#
# Empty by design. The repo-domain "known bad" signal is already covered by
# two dynamic sources we query per-repo: (1) GitHub Advisory Database's
# malware-category records via ``_query_github_advisories``, and (2) the
# Trust & Safety suspension state (suspended orgs return 404 from
# ``api.github.com/repos/...``, surfaced as ``score_bucket=RED`` via the
# "all sources unreachable" path). A static blocklist of org names would be
# redundant and likely stale.
#
# If a primary-source incident report (e.g. GitHub Security Lab disclosure)
# names a specific GitHub org as malicious, add it here with the citation
# URL and verification date.
KNOWN_BAD_GITHUB_ORGS: frozenset[str] = frozenset()


# Skill author groups documented as malicious in published audits.
KNOWN_BAD_SKILL_AUTHORS: frozenset[str] = frozenset({
    # SkillSieve (arXiv:2604.06550, April 2026) §4.2 + Koi Security
    # ClawHub audit (Jan-Feb 2026), 354 skills attributed. This is a
    # *skill author* (ClawHub publisher), not a GitHub organisation —
    # GitHub repo reputation does not consume this list.
    "hightower6eu",
})


def is_known_bad_pypi(name: str) -> bool:
    return name.lower() in load_known_bad_pypi_packages()


def is_known_bad_npm(name: str) -> bool:
    return name.lower() in load_known_bad_npm_packages()


def is_known_bad_github_org(owner: str) -> bool:
    return owner.lower() in KNOWN_BAD_GITHUB_ORGS
