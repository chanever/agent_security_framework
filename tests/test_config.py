"""US-001 acceptance tests — SecurityFrameworkConfig bpftrace + semgrep fields."""

from __future__ import annotations

import importlib
import os
import sys


def _reload_config():
    """Re-evaluate the config module so env-var-driven defaults re-resolve."""
    if "security_framework.config" in sys.modules:
        return importlib.reload(sys.modules["security_framework.config"])
    return importlib.import_module("security_framework.config")


def test_default_trace_mode_is_strace_for_backward_compat(monkeypatch):
    monkeypatch.delenv("TRACE_MODE", raising=False)
    cfg_mod = _reload_config()
    cfg = cfg_mod.SecurityFrameworkConfig()
    assert cfg.trace_mode == "strace"


def test_trace_mode_bpftrace_via_env(monkeypatch):
    monkeypatch.setenv("TRACE_MODE", "bpftrace")
    cfg_mod = _reload_config()
    cfg = cfg_mod.SecurityFrameworkConfig()
    assert cfg.trace_mode == "bpftrace"


def test_bpftrace_image_default(monkeypatch):
    monkeypatch.delenv("BPFTRACE_IMAGE", raising=False)
    cfg_mod = _reload_config()
    cfg = cfg_mod.SecurityFrameworkConfig()
    assert cfg.bpftrace_image == "quay.io/iovisor/bpftrace:master"


def test_bpftrace_image_env_override(monkeypatch):
    monkeypatch.setenv("BPFTRACE_IMAGE", "my-registry/bpftrace:custom")
    cfg_mod = _reload_config()
    cfg = cfg_mod.SecurityFrameworkConfig()
    assert cfg.bpftrace_image == "my-registry/bpftrace:custom"


def test_bpftrace_timeouts_have_sensible_defaults(monkeypatch):
    monkeypatch.delenv("BPFTRACE_ATTACH_TIMEOUT", raising=False)
    monkeypatch.delenv("BPFTRACE_SENTINEL_TIMEOUT", raising=False)
    cfg_mod = _reload_config()
    cfg = cfg_mod.SecurityFrameworkConfig()
    assert cfg.bpftrace_attach_timeout == 10
    assert cfg.bpftrace_sentinel_timeout == 2


def test_semgrep_fields_default(monkeypatch):
    monkeypatch.delenv("SEMGREP_IMAGE", raising=False)
    monkeypatch.delenv("SEMGREP_RULES", raising=False)
    monkeypatch.delenv("SEMGREP_TIMEOUT", raising=False)
    cfg_mod = _reload_config()
    cfg = cfg_mod.SecurityFrameworkConfig()
    assert cfg.semgrep_image == "semgrep/semgrep:latest"
    assert cfg.semgrep_rules == "p/security-audit"
    assert cfg.semgrep_timeout == 240
