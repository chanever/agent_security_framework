"""Compatibility package for the refactored security framework layout."""

from __future__ import annotations

from pathlib import Path

_inner_package = Path(__file__).resolve().parent / "security_framework"
if _inner_package.exists():
    __path__.append(str(_inner_package))

from security_framework.safeguard.shadow_sandbox_safeguard import ShadowSandboxSafeguard

__all__ = ["ShadowSandboxSafeguard"]
