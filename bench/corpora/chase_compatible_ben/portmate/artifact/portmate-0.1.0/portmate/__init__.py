"""
PortMate - A powerful CLI tool to check ports, find processes, and manage port usage
"""

__version__ = "0.1.0"

from .core import (
    check_port,
    find_process_by_port,
    kill_process_by_port,
    scan_ports,
    get_common_ports,
)

__all__ = [
    "check_port",
    "find_process_by_port",
    "kill_process_by_port",
    "scan_ports",
    "get_common_ports",
]
