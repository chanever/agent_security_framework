"""Configuration for the shadow sandbox security framework."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    return default if value is None or value == "" else int(value)


@dataclass
class SecurityFrameworkConfig:
    """Runtime settings sourced from environment variables."""

    enabled: bool = _bool_env("SECURITY_FRAMEWORK_ENABLED", True)
    shadow_sandbox_enabled: bool = _bool_env("SHADOW_SANDBOX_ENABLED", True)
    sandbox_docker_image: str = os.getenv("SANDBOX_DOCKER_IMAGE", "shadow-agent-sandbox:latest")
    sandbox_timeout: int = _int_env("SANDBOX_TIMEOUT", 30)
    sandbox_network_mode: str = os.getenv("SANDBOX_NETWORK_MODE", "none")
    trace_mode: str = os.getenv("TRACE_MODE", "strace")  # "strace" | "bpftrace"
    bpftrace_image: str = os.getenv("BPFTRACE_IMAGE", "quay.io/iovisor/bpftrace:master")
    bpftrace_attach_timeout: int = _int_env("BPFTRACE_ATTACH_TIMEOUT", 10)
    bpftrace_sentinel_timeout: int = _int_env("BPFTRACE_SENTINEL_TIMEOUT", 2)
    verifier_mode: str = os.getenv("VERIFIER_MODE", "mock")
    semgrep_image: str = os.getenv("SEMGREP_IMAGE", "semgrep/semgrep:latest")
    semgrep_rules: str = os.getenv("SEMGREP_RULES", "p/security-audit")
    semgrep_timeout: int = _int_env("SEMGREP_TIMEOUT", 240)
    focus_mode: str = os.getenv("SECURITY_FOCUS_MODE", "external_only")
    strict_evidence_for_safe_commands: bool = _bool_env("SECURITY_STRICT_EVIDENCE_FOR_SAFE_COMMANDS", False)
    shadow_sandbox_only_for_external_env: bool = _bool_env("SHADOW_SANDBOX_ONLY_FOR_EXTERNAL_ENV", True)
    max_output_chars: int = _int_env("SECURITY_MAX_OUTPUT_CHARS", 12000)
    workspace_copy_parent: str = os.getenv("SANDBOX_WORKSPACE_COPY_PARENT", "")
    artifact_root: str = os.getenv("SECURITY_ARTIFACT_ROOT", "")

    @classmethod
    def from_env(cls) -> "SecurityFrameworkConfig":
        return cls()

    def resolve_paths(self, project_root: Path | None = None) -> "SecurityFrameworkConfig":
        root = project_root or Path(__file__).resolve().parents[1]
        if not self.workspace_copy_parent:
            self.workspace_copy_parent = str(root / "artifacts" / "security_runs")
        if not self.artifact_root:
            self.artifact_root = str(root / "artifacts" / "security_runs")
        self.workspace_copy_parent = str(Path(self.workspace_copy_parent).expanduser().resolve())
        self.artifact_root = str(Path(self.artifact_root).expanduser().resolve())
        Path(self.workspace_copy_parent).mkdir(parents=True, exist_ok=True)
        Path(self.artifact_root).mkdir(parents=True, exist_ok=True)
        return self
