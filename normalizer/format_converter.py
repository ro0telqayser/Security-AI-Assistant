"""
normalizer/format_converter.py
================================
Converts normalised vulnerability findings to different output formats.

Security tools typically produce output in their own proprietary formats (XML,
custom JSON, plain text). This module provides a FormatConverter class that
takes the project's internal finding schema and converts it to common exchange
formats for reporting, further processing, or integration with other tools.

Supported output formats:
  - JSON (implemented): Machine-readable output for API consumers and scripts.

Potential future formats (not yet implemented):
  - SARIF (Static Analysis Results Interchange Format): Used by GitHub Advanced
    Security and many CI/CD platforms to display findings as code annotations.
  - CSV: For import into spreadsheets or project management tools.
  - HTML: For human-readable standalone reports.
"""

import json
from typing import List, Dict, Any
from loguru import logger


class FormatConverter:
    """
    Converts normalised vulnerability findings to various output formats.

    Used by the CLI for printing results and by any component that needs to
    export findings to a file or external system.
    """

    def to_json(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        Serialise findings to a pretty-printed JSON string.

        Produces human-readable JSON (indented 2 spaces) suitable for writing to a
        file, displaying in a terminal, or sending as an API response body.

        Args:
            vulnerabilities: List of normalised finding dicts.

        Returns:
            str: JSON-formatted string representing all findings.

        Example output:
            [
              {
                "id": "semgrep:python.lang.security.audit.eval-detected:app.py:42",
                "title": "python.lang.security.audit.eval-detected",
                "severity": "HIGH",
                ...
              }
            ]
        """
        logger.info(f"Serialising {len(vulnerabilities)} finding(s) to JSON")
        return json.dumps(vulnerabilities, indent=2)
