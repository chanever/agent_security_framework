"""Container image static analyzer — Trivy (aquasec/trivy docker image).

Run an image vulnerability + misconfig scan without pulling the image
locally. Trivy's docker image is publicly available; we invoke it with
``--scanners vuln,misconfig`` and bind /var/run/docker.sock so it can
inspect images already pulled by the host. Misconfig scanning catches
Dockerfile patterns (RUN curl|bash, COPY --chown=root, etc.) and pulls
the OS package CVE feed from Trivy's central DB.

When the artifact node is registry-only (e.g. ``docker pull ubuntu:22.04``
that hasn't been fetched yet), we report ``skipped`` rather than pulling
on the host's behalf — pulling an untrusted image is itself a
side effect the framework wants to gate.
"""

from __future__ import annotations

import json
import subprocess


TRIVY_IMAGE = "aquasec/trivy:latest"
TRIVY_TIMEOUT = 120

# Trivy severity → our normalized bucket.
_SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "LOW",
}


def _run_trivy(image_name: str) -> dict | None:
    """Run trivy against an image already present on the host docker.

    Returns the parsed JSON report or None on failure / image-not-found.
    """
    cmd = [
        "docker", "run", "--rm",
        "--stop-timeout", "10",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        TRIVY_IMAGE,
        "image", "--quiet",
        "--scanners", "vuln,misconfig",
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--exit-code", "0",
        image_name,
    ]
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=TRIVY_TIMEOUT, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if not (completed.stdout or "").strip():
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None


def _normalize_trivy_findings(payload: dict) -> list[dict]:
    findings: list[dict] = []
    for result in payload.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append({
                "rule_id": f"trivy.{vuln.get('VulnerabilityID','CVE')}",
                "severity": _SEV_MAP.get((vuln.get("Severity") or "").upper(), "LOW"),
                "path": target,
                "line": 0,
                "message": (
                    f"{vuln.get('PkgName')} {vuln.get('InstalledVersion','')} → "
                    f"{vuln.get('Title') or vuln.get('Description','')[:120]}"
                ),
                "source": "trivy-vuln",
            })
        for misc in result.get("Misconfigurations") or []:
            findings.append({
                "rule_id": f"trivy.{misc.get('ID','MISC')}",
                "severity": _SEV_MAP.get((misc.get("Severity") or "").upper(), "LOW"),
                "path": target,
                "line": int((misc.get("CauseMetadata") or {}).get("StartLine") or 0),
                "message": misc.get("Title") or misc.get("Description","")[:200],
                "source": "trivy-misconfig",
            })
    return findings


def analyze(node: dict, cfg) -> dict:
    image_name = node.get("name") or node.get("source") or ""
    if not image_name:
        return {"status": "skipped", "findings": [],
                "summary": "no container image name", "analyzer": "container_image"}

    # Check whether the host has the image pulled — we refuse to pull
    # untrusted images from inside the analyzer.
    check = subprocess.run(
        ["docker", "image", "inspect", image_name],
        capture_output=True, text=True, check=False,
    )
    if check.returncode != 0:
        return {
            "status": "skipped",
            "findings": [],
            "summary": (
                f"image {image_name} not present on host; "
                "container_image_analyzer refuses to pull untrusted images. "
                "Pull manually before scanning or rely on reputation lookup."
            ),
            "analyzer": "container_image",
        }

    payload = _run_trivy(image_name)
    if payload is None:
        return {"status": "unavailable", "findings": [],
                "summary": "trivy unavailable or returned no JSON",
                "analyzer": "container_image"}
    findings = _normalize_trivy_findings(payload)
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    return {
        "status": "success",
        "findings": findings,
        "summary": (
            f"trivy {image_name}: {len(findings)} findings "
            f"(CRITICAL={sev_counts['CRITICAL']}, HIGH={sev_counts['HIGH']}, "
            f"MEDIUM={sev_counts['MEDIUM']}, LOW={sev_counts['LOW']})"
        ),
        "analyzer": "container_image",
    }
