"""
adapters/adapter_base.py
========================
Abstract base class that defines the interface every security tool adapter must implement.

This follows the Adapter design pattern — each security tool (Semgrep, HexStrike, etc.)
has its own adapter class that translates between the tool's native output format and
the common vulnerability schema used throughout the pipeline.

Using an abstract base class here enforces consistency: if a new tool is added later,
it must implement scan(), normalize_results(), tool_name, and version before it can
be plugged into the workflow. This prevents half-finished integrations from silently
producing incorrect results.

Design principle: Program to an interface, not an implementation (OOP principle from
the Secure Software Development module).
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path


class SecurityToolAdapter(ABC):
    """
    Abstract base class for security tool adapters.

    All security tool adapters (Semgrep, HexStrike, etc.) inherit from this class
    and must implement all abstract methods. This guarantees that the WorkflowManager
    can call any adapter in the same way, regardless of which tool it wraps.

    The adapter is responsible for:
    1. Validating that the underlying tool is available (e.g., installed on PATH).
    2. Executing the tool against a target and returning raw results.
    3. Normalising those raw results into the project's common finding schema.
    """

    def __init__(self, tool_path: Optional[str] = None):
        """
        Initialise the adapter.

        Calls _validate_tool() at construction time so that a misconfigured adapter
        fails loudly at startup rather than silently producing no results at scan time.

        Args:
            tool_path: Path or URL pointing to the security tool. For CLI tools this
                       is the binary path; for REST-based tools (HexStrike) this is
                       the base URL of the server.
        """
        self.tool_path = tool_path
        self._validate_tool()

    @abstractmethod
    def _validate_tool(self) -> bool:
        """
        Check that the underlying security tool is available and usable.

        This is called at construction time. Subclasses should raise RuntimeError
        if the tool cannot be found or is misconfigured, so the problem is caught
        before any scan is attempted.

        Returns:
            bool: True if the tool is ready to use.

        Raises:
            RuntimeError: If the tool is not installed or cannot be reached.
        """
        pass

    @abstractmethod
    async def scan(
        self,
        target_path: str,
        options: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a security scan against the given target.

        This method is async because scanning can be a long-running operation —
        using async/await allows the event loop to handle other tasks while waiting
        for the tool to finish, rather than blocking the entire process.

        Args:
            target_path: The directory/file path (SAST) or URL/host (DAST) to scan.
            options: Tool-specific options dict (e.g., Semgrep config, Nuclei severity
                     filter, SQLMap risk level).

        Returns:
            List[Dict]: Raw findings as returned by the tool. The format varies
                        between tools — normalise_results() converts them to the
                        common schema.

        Raises:
            RuntimeError: If the scan fails or times out.
        """
        pass

    @abstractmethod
    def normalize_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert raw tool output into the project's common vulnerability schema.

        Each tool has its own output format. This method maps that format onto the
        standard finding dict used throughout the pipeline:
            {
                "id":          str   — unique identifier for the finding
                "title":       str   — short summary of the issue
                "description": str   — full explanation / tool message
                "severity":    str   — CRITICAL | HIGH | MEDIUM | LOW | INFO
                "source":      str   — name of the tool that found this
                "location":    dict  — file path + line (SAST) or URL + endpoint (DAST)
                "cwe_id":      str   — CWE reference, if the tool provides one
                "confidence":  float — 0.0–1.0 confidence estimate
                "metadata":    dict  — raw tool output for further analysis
            }

        Args:
            raw_results: The list of dicts returned by scan().

        Returns:
            List[Dict]: Normalised findings in the common schema.
        """
        pass

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return a short identifier for this tool (e.g., 'semgrep', 'hexstrike')."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Return the version string for the underlying tool."""
        pass
