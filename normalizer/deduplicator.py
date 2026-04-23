"""
normalizer/deduplicator.py
===========================
Standalone deduplication utility for vulnerability findings.

This module provides a Deduplicator class as a reusable component. The primary
deduplication logic used by the pipeline lives in ResultMerger (orchestrator layer),
but this class is available for cases where deduplication is needed outside the
main scan workflow — for example, when processing imported findings from a file,
or when building a reporting component that combines findings from multiple scan runs.
"""

from typing import List, Dict, Any
from loguru import logger


class Deduplicator:
    """
    Removes duplicate vulnerability findings from a list.

    Deduplication is important in security scanning because:
    - The same vulnerability can be reported by multiple tools.
    - Incremental scans may re-report issues found in previous runs.
    - Without deduplication, metrics (e.g., "42 HIGH findings") overstate the
      actual attack surface and make prioritisation harder.
    """

    def deduplicate(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings from the input list.

        Two findings are considered duplicates if they share the same title (or id),
        source tool, file path, and line number. The first occurrence of each
        unique combination is kept; subsequent duplicates are discarded.

        Args:
            vulnerabilities: List of normalised finding dicts, potentially containing
                             duplicates.

        Returns:
            List[Dict]: Deduplicated findings, in original order of first occurrence.
        """
        logger.info(f"Deduplicating {len(vulnerabilities)} finding(s)")

        seen: set = set()
        deduped: List[Dict[str, Any]] = []

        for v in vulnerabilities:
            loc = v.get("location") or {}
            key = (
                v.get("title") or v.get("id") or "",
                v.get("source") or "",
                loc.get("file_path") or "",
                str(loc.get("line") or ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(v)

        return deduped
