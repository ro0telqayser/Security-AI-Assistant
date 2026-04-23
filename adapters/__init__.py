"""
adapters/__init__.py
=====================
Security tool adapter package.

Exports the abstract base class and all concrete adapter implementations so
that other modules can import them from a single location:

    from adapters import SemgrepAdapter, HexStrikeAdapter

Each adapter wraps a security tool and implements the SecurityToolAdapter interface,
ensuring they can be plugged into the WorkflowManager without any further changes.
"""

from .adapter_base import SecurityToolAdapter
from .semgrep_adapter import SemgrepAdapter
from .hexstrike_adapter import HexStrikeAdapter

__all__ = [
    "SecurityToolAdapter",
    "SemgrepAdapter",
    "HexStrikeAdapter",
]
