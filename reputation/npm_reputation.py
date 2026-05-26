"""npm package reputation — OSV.dev lookup (registry-download counts deferred)."""

from __future__ import annotations

from . import _osv


def lookup(node: dict, *, timeout: int = 10) -> dict | None:
    name = node.get("name") or ""
    if not name:
        return None
    payload = _osv.query(name, "npm", timeout=timeout)
    if payload is None:
        return {
            "source": "osv",
            "target_type": "package",
            "target_name": name,
            "ecosystem": "npm",
            "status": "unavailable",
            "summary": f"OSV unreachable for npm:{name}",
        }
    return _osv.signal_from_payload(name, "npm", payload)
