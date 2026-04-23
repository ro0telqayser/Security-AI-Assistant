"""
adapters/semgrep_adapter.py
============================
Semgrep adapter — wraps the Semgrep SAST tool and normalises its output.

Semgrep is an open-source static analysis tool that matches code patterns against
security rules. It can detect a wide range of issues including:
  - SQL injection (CWE-89)
  - Cross-site scripting / XSS (CWE-79)
  - Hardcoded secrets and credentials (CWE-798)
  - Insecure use of cryptographic functions (CWE-327)
  - Use of dangerous functions (e.g., eval, exec, pickle.loads)

Semgrep is run as a subprocess and its JSON output is parsed. The adapter excludes
third-party directories (node_modules, venv, dist, etc.) to reduce false-positive
noise — these directories contain code that is not under the developer's control
and would clutter results with irrelevant findings.

Reference: https://semgrep.dev/docs/
"""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import List, Dict, Any, Optional
from loguru import logger

from adapters.adapter_base import SecurityToolAdapter


# ---------------------------------------------------------------------------
# Rule-pattern confidence calibration
# ---------------------------------------------------------------------------
# Semgrep rules vary significantly in precision depending on what they match.
# Exact value/string matchers (hardcoded secrets, known dangerous sinks) are
# highly precise. Broad structural patterns (generic object injection for NoSQL,
# eval-shaped calls) fire on many non-exploitable shapes and have higher FP rates.
#
# These adjustments are derived from empirical rule precision data, not from any
# specific target application — they apply to any codebase scanned with these
# rule families.
#
# Key: substring matched against the lowercased rule check_id.
# Value: adjusted confidence score (0.0 – 1.0).
_RULE_CONFIDENCE: Dict[str, float] = {
    # High-precision: pattern matches an exact secret value or known sink
    "hardcoded":       0.85,
    "detected-secret": 0.85,
    "private-key":     0.85,
    "secret":          0.85,
    # Broad/generic patterns — checked BEFORE their substring equivalents.
    # "nosqli" and "nosql" must come before "sqli"/"sql" because "nosqli"
    # contains "sqli" as a substring: without this ordering, express-mongo-nosqli
    # would match the more-confident "sqli" entry instead of the less-confident
    # "nosqli" entry.
    "nosqli":          0.50,
    "nosql":           0.50,
    "mongo":           0.50,
    # Reliable structural patterns: well-defined sink shapes
    "sequelize":       0.75,
    "sql-injection":   0.75,
    "sqli":            0.75,
    "path-traversal":  0.75,
    "sendfile":        0.72,
    # Context-dependent: correctness depends on whether user input reaches the sink
    "open-redirect":   0.65,
    "code-injection":  0.60,
    "code-string":     0.58,
    "eval":            0.62,
}


def _calibrate_confidence(check_id: str) -> float:
    """Return a calibrated confidence score for a Semgrep rule.

    Scans the rule's check_id for known pattern substrings and returns the
    confidence value for the first match found. Falls back to the Semgrep
    tool baseline (0.70) when no known pattern is recognised.

    The matching is done in the order the dict is defined — more specific
    patterns (e.g. 'nosqli') take precedence over generic ones (e.g. 'sql')
    because Python dicts preserve insertion order.

    Args:
        check_id: Semgrep rule identifier (e.g. 'express-mongo-nosqli').

    Returns:
        float: Calibrated confidence in [0.0, 1.0].
    """
    lower = check_id.lower()
    for pattern, conf in _RULE_CONFIDENCE.items():
        if pattern in lower:
            return conf
    return 0.70  # Semgrep tool baseline (§4.4)


def _extract_first_str(value) -> Optional[str]:
    """Return the first element of a list as a string, or the value itself if already a string."""
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _extract_cwe(cwe_value) -> Optional[str]:
    """Normalise Semgrep's cwe metadata field to a plain string like 'CWE-89'.

    Semgrep rules embed CWE as either a bare string ("CWE-89") or a list of
    verbose strings (["CWE-89: Improper Neutralization ..."]). SQLite requires
    a scalar, so we extract just the 'CWE-NNN' prefix from whichever form we
    receive.
    """
    if cwe_value is None:
        return None
    if isinstance(cwe_value, list):
        cwe_value = cwe_value[0] if cwe_value else None
    if not cwe_value:
        return None
    # Trim any verbose description after the first space, e.g. "CWE-89: ..."
    return str(cwe_value).split(":")[0].strip()


class SemgrepAdapter(SecurityToolAdapter):
    """
    Adapter for the Semgrep static analysis tool (SAST).

    Executes Semgrep as a subprocess, waits for results, and converts the JSON
    output into the project's common finding schema. Runs asynchronously so the
    FastAPI event loop is not blocked during long scans.
    """

    def _validate_tool(self) -> bool:
        """
        Verify that Semgrep is installed and available.

        Attempts to locate the Semgrep binary using shutil.which() (equivalent to
        running `which semgrep` in a shell). If a custom path was provided at
        construction, that is used directly.

        Returns:
            bool: True if Semgrep is found.

        Raises:
            RuntimeError: If Semgrep is not on the PATH and no custom path was set.
        """
        if self.tool_path:
            return True

        resolved = shutil.which("semgrep")
        if not resolved:
            raise RuntimeError(
                "Semgrep not found. Install it with `pip install semgrep` or set "
                "SEMGREP_PATH to the binary location."
            )

        self.tool_path = resolved
        return True

    async def scan(
        self,
        target_path: str,
        options: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a Semgrep scan and return the raw JSON findings.

        Builds the Semgrep command with the specified configuration, runs it as an
        async subprocess, and parses the JSON output. A timeout is enforced to
        prevent the scan from hanging indefinitely on very large codebases.

        Third-party directories (node_modules, venv, dist, etc.) are excluded by
        default because they generate high-volume false positives — issues in those
        directories are the responsibility of upstream maintainers, not the project
        under review.

        Args:
            target_path: Path to the directory or file to scan.
            options: Optional dict with the following keys:
                - config (str): Semgrep ruleset to use (default: "auto").
                - timeout_seconds (int): Max seconds before the scan is killed (default: 300).
                - exclude_dirs (list): Additional directories to skip.
                - exclude_patterns (list): Additional file patterns to skip.

        Returns:
            List[Dict]: Raw Semgrep findings from the "results" key of the JSON output.

        Raises:
            RuntimeError: If Semgrep fails, times out, or returns unparseable output.
        """
        options = options or {}

        semgrep_bin = self.tool_path or "semgrep"
        config = options.get("config", "auto")
        timeout_s = int(options.get("timeout_seconds", 300))

        # Directories that are almost always false-positive noise:
        # third-party tools, compiled bundles, Python virtual environments.
        default_exclude_dirs = [
            "node_modules",
            ".claude",
            "dist",
            "build",
            ".next",
            ".nuxt",
            "vendor",
            "venv",
            ".venv",
        ]
        # Allow callers to extend the exclusion list without overriding defaults.
        extra_exclude_dirs: list = options.get("exclude_dirs") or []
        all_exclude_dirs = default_exclude_dirs + [
            d for d in extra_exclude_dirs if d not in default_exclude_dirs
        ]

        # Also skip minified/compiled JS files — these generate high false-positive volume
        # and are not code the developer wrote.
        default_exclude_patterns = ["*.min.js", "*.bundle.js"]
        extra_exclude_patterns: list = options.get("exclude_patterns") or []
        all_exclude_patterns = default_exclude_patterns + extra_exclude_patterns

        # Build the semgrep command. --json and --quiet give us machine-readable output
        # without banner noise. --config determines which rule set to use (auto = Semgrep
        # chooses based on detected languages). Multiple configs can be passed as a
        # comma-separated string (e.g. "p/owasp-top-ten,p/security-audit").
        configs = [c.strip() for c in str(config).split(",") if c.strip()]
        cmd = [semgrep_bin, "--json", "--quiet"]
        for c in configs:
            cmd += ["--config", c]
        for d in all_exclude_dirs:
            cmd += ["--exclude", d]
        for p in all_exclude_patterns:
            cmd += ["--exclude", p]
        cmd.append(target_path)

        logger.info(f"Running Semgrep on: {target_path}")

        # Run Semgrep as an async subprocess. Using asyncio.create_subprocess_exec
        # avoids blocking the event loop while the scan runs.
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError as e:
            # Kill the process cleanly to avoid zombie processes or leaked file handles.
            try:
                proc.kill()
            except Exception:
                pass
            try:
                await proc.communicate()
            except Exception:
                pass
            raise RuntimeError(f"Semgrep timed out after {timeout_s} seconds") from e

        stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr = (stderr_b or b"").decode("utf-8", errors="replace")

        # Semgrep exits non-zero when findings exist (exit code 1) or on error.
        # We only treat it as a real failure if there is no stdout to parse.
        if proc.returncode != 0 and not stdout:
            raise RuntimeError(f"Semgrep failed (exit code {proc.returncode}): {stderr.strip()}")

        try:
            payload = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Could not parse Semgrep JSON output: {e}") from e

        # Semgrep JSON structure: { "results": [...], "errors": [...], ... }
        return payload.get("results", []) or []

    def normalize_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert Semgrep findings into the project's common vulnerability schema.

        Semgrep uses its own severity labels (ERROR, WARNING, INFO) which do not map
        directly to the project's severity scale (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        This method performs that mapping:
            ERROR   → HIGH   (code-breaking or exploitable flaw)
            WARNING → MEDIUM (potential issue worth investigating)
            INFO    → LOW    (style / informational)

        Each finding is assigned a composite ID built from the rule ID, file path,
        and line number. This makes it possible to deduplicate findings across multiple
        runs or tools.

        Args:
            raw_results: List of finding dicts from scan().

        Returns:
            List[Dict]: Findings in the common schema understood by the rest of
                        the pipeline (WorkflowManager, ResultMerger, database layer).
        """
        logger.info(f"Normalising {len(raw_results)} Semgrep findings")

        normalized: List[Dict[str, Any]] = []

        for r in raw_results:
            check_id = r.get("check_id") or "semgrep"
            extra = r.get("extra") or {}
            message = extra.get("message") or r.get("message") or check_id
            severity_raw = (extra.get("severity") or "INFO").upper()

            # Map Semgrep severity labels to our four-level scale.
            severity_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW",
            }
            severity = severity_map.get(severity_raw, "INFO")

            path = (r.get("path") or "").strip() or None
            start = r.get("start") or {}
            end = r.get("end") or {}

            line = start.get("line")
            col = start.get("col")

            # Build a composite ID so duplicate findings (same rule, same file, same line)
            # can be identified and removed by the deduplication stage.
            vuln_id_parts = [check_id]
            if path:
                vuln_id_parts.append(path)
            if line:
                vuln_id_parts.append(str(line))
            if col:
                vuln_id_parts.append(str(col))

            rule_meta = extra.get("metadata") or {}

            normalized.append(
                {
                    "id": ":".join(vuln_id_parts),
                    "title": check_id,
                    "description": message,
                    "severity": severity,
                    "source": "SAST",
                    "location": {
                        "file_path": path,
                        "line": line,
                        "column": col,
                        "end_line": end.get("line"),
                        "end_column": end.get("col"),
                    },
                    # CWE and OWASP taxonomy extracted from Semgrep rule metadata (FR14).
                    # Semgrep rules in p/owasp-top-ten and p/security-audit embed these
                    # under extra.metadata.cwe and extra.metadata.owasp-top-ten.
                    "cwe_id": _extract_cwe(rule_meta.get("cwe")),
                    "owasp_category": _extract_first_str(rule_meta.get("owasp-top-ten")),
                    # Confidence calibrated per rule pattern: broad/generic patterns
                    # (e.g. nosqli, eval) score lower than exact-match patterns
                    # (e.g. hardcoded-secret, sequelize raw query). Falls back to
                    # the 0.70 Semgrep tool baseline when no pattern is recognised.
                    "confidence": _calibrate_confidence(check_id),
                    "metadata": {
                        "semgrep": {
                            "check_id": check_id,
                            "extra": extra,
                        }
                    },
                }
            )

        return normalized

    @property
    def tool_name(self) -> str:
        """Return the tool identifier used in findings and logs."""
        return "semgrep"

    @property
    def version(self) -> str:
        """Return the Semgrep version string."""
        return "0.0.0"
