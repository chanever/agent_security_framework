"""Fixture for US-006 — contains a deliberate eval() / pickle / subprocess shell=True trio.

Used only by the optional semgrep live test gated on docker availability.
"""

import base64
import os
import pickle
import subprocess


def decode_and_run(payload: str) -> object:
    # eval on attacker-controlled base64 → classic semgrep p/security-audit hit.
    return eval(base64.b64decode(payload))


def unpickle(blob: bytes) -> object:
    # Untrusted deserialization — another p/security-audit favorite.
    return pickle.loads(blob)


def os_shell(user_input: str) -> int:
    # shell=True with user input → command injection.
    return subprocess.call(f"echo {user_input}", shell=True)


def os_system(user_input: str) -> int:
    return os.system(f"echo {user_input}")
