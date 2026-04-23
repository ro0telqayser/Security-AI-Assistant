"""
orchestrator/workflow_manager.py
=================================
Central coordinator for the security scanning pipeline.

The WorkflowManager is the core of the application. It ties together all the
individual components — adapters, normaliser, merger, and database layer — into a
single coordinated workflow.

Responsibilities:
  1. Validate scan targets (prevent SAST path traversal and unauthorised DAST targets).
  2. Invoke each requested security tool adapter in sequence.
  3. Collect and deduplicate findings across all tools.
  4. Persist results to the database.
  5. Return a structured result dict to the caller (CLI or API endpoint).

Security considerations implemented here:
  - Path traversal prevention (OWASP A03:2021 — Injection):
      SAST targets are validated against SCAN_ROOT to prevent callers from scanning
      arbitrary parts of the filesystem via the API (e.g., /etc/passwd).
  - DAST target allowlisting:
      Dynamic scans are restricted to localhost / 127.0.0.1 by default. Scanning
      external hosts without authorisation is illegal under the Computer Misuse Act
      1990 (UK), so the user must explicitly opt in with --dast-authorized or by
      adding the target to DAST_ALLOWLIST.
"""

from typing import List, Dict, Any, Optional
from uuid import uuid4
from loguru import logger
from pathlib import Path
from urllib.parse import urlparse

from adapters import SemgrepAdapter, HexStrikeAdapter
from adapters.adapter_base import SecurityToolAdapter
from normalizer import VulnerabilityNormalizer
from orchestrator.result_merger import ResultMerger
from orchestrator.correlation_engine import CorrelationEngine
from scoring.risk_scorer import score_findings
from backend.app.core.config import settings
from sqlalchemy.ext.asyncio import AsyncSession

from db.crud import add_findings, complete_scan, create_scan, get_config_by_id


class WorkflowManager:
    """
    Coordinates security scanning across multiple tools.

    This class is instantiated by both the CLI (security_assistant.py) and the
    API endpoint (/api/v1/security/scan). It provides a single execute_scan()
    method that handles the entire pipeline from validation through to persistence.

    The class is designed to be extensible — new tool adapters can be added to
    the adapters dict without changing the core workflow logic.
    """

    def __init__(
        self,
        adapters: Optional[Dict[str, SecurityToolAdapter]] = None,
        normalizer: Optional[VulnerabilityNormalizer] = None,
        merger: Optional[ResultMerger] = None
    ):
        """
        Initialise the workflow manager with the required components.

        Uses dependency injection so that tests or callers can substitute mock
        adapters / normalizers without modifying this class.

        Args:
            adapters: Dict mapping tool names to their adapter instances.
                      Defaults to {semgrep: SemgrepAdapter, hexstrike: HexStrikeAdapter}.
            normalizer: Vulnerability normaliser (currently used as an extension point).
            merger: Result merger for deduplication (defaults to ResultMerger).
        """
        self.adapters = adapters or {
            "semgrep": SemgrepAdapter(None),
            "hexstrike": HexStrikeAdapter(settings.hexstrike_url)
        }
        self.normalizer = normalizer or VulnerabilityNormalizer()
        self.merger = merger or ResultMerger()
        self.correlation_engine = CorrelationEngine()
        logger.info("WorkflowManager ready")

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    def _validate_path(self, target_path: str, *, allow_any_path: bool = False) -> bool:
        """
        Validate a SAST target path against security controls.

        This method enforces two key security controls:

        1. **Null byte rejection**: Null bytes in file paths are a classic injection
           technique used to bypass extension checks. For example, `file.php\x00.txt`
           would appear to end in `.txt` to some checks but be treated as `file.php`
           by the OS. Rejecting null bytes prevents this class of attack.

        2. **Path confinement**: The resolved path must lie within SCAN_ROOT. This
           prevents API callers from scanning arbitrary locations on the server's
           filesystem by submitting paths like `../../../../etc/passwd`.

        The CLI can bypass SCAN_ROOT with --allow-any-path to support scanning
        projects located outside the repository (e.g., a different project on the
        developer's machine). This flag is intentionally absent from the API.

        Reference: OWASP A03:2021 — Injection (path traversal variant)

        Args:
            target_path: The path string to validate.
            allow_any_path: If True, skip the SCAN_ROOT confinement check.

        Returns:
            bool: True if the path passes all checks.

        Raises:
            ValueError: If the path fails any validation check.
        """
        def _is_within(child: Path, parent: Path) -> bool:
            """Python 3.7 compatible replacement for Path.is_relative_to()."""
            try:
                child.relative_to(parent)
                return True
            except Exception:
                return False

        try:
            if not target_path:
                raise ValueError("Target path cannot be empty")

            # Null bytes in paths are almost always an injection attempt.
            if "\x00" in target_path:
                raise ValueError(f"Invalid path (contains null byte): {target_path}")

            requested = Path(target_path)
            resolved = requested.resolve()

            if not allow_any_path:
                # Reject '..' segments in the raw string before resolution — resolve()
                # would silently normalise them, masking the traversal attempt.
                if ".." in target_path:
                    raise ValueError(f"Directory traversal not allowed: {target_path}")

                scan_root = Path(settings.scan_root).resolve()
                if not _is_within(resolved, scan_root):
                    raise ValueError(
                        f"Target path must be inside SCAN_ROOT ({scan_root}). "
                        f"Use --allow-any-path (CLI only) to override."
                    )

            if not resolved.exists():
                raise ValueError(f"Path does not exist: {resolved}")

            return True
        except Exception as e:
            logger.error(f"Path validation failed: {e}")
            raise ValueError(f"Invalid target path: {target_path}")

    def _parse_allowlist(self) -> List[str]:
        """Parse the DAST_ALLOWLIST setting into a list of lowercase hostnames."""
        raw = settings.dast_allowlist or ""
        return [h.strip().lower() for h in raw.split(",") if h.strip()]

    def _validate_dast_target(self, target: str, *, authorized: bool = False) -> None:
        """
        Enforce the DAST target allowlist to prevent unauthorised scanning.

        Dynamic scanning sends real attack traffic to a target system. Scanning
        a system you do not own or have written permission to test is illegal in
        the UK (Computer Misuse Act 1990) and many other jurisdictions.

        This method blocks scans against non-allowlisted targets unless the caller
        explicitly confirms authorisation. The allowlist defaults to localhost and
        127.0.0.1, making it safe to run DAST against local lab environments
        (e.g., DVWA, Juice Shop, WebGoat) without any configuration.

        To scan a staging server or external target, either:
          - Add the hostname to DAST_ALLOWLIST in .env
          - Pass --dast-authorized in the CLI
          - Set DAST_ALLOW_NONLOCAL=true (disables the check entirely — lab use only)

        Args:
            target: The URL or hostname to scan.
            authorized: True if the caller has confirmed authorisation.

        Raises:
            ValueError: If the target is not allowlisted and no authorisation was given.
        """
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        if not host:
            # Bare hostname (no scheme) — extract directly.
            host = target.split("/")[0].split(":")[0].lower()

        allowlist = set(self._parse_allowlist())

        # DAST_ALLOW_NONLOCAL bypasses the check entirely (intended for lab environments).
        if settings.dast_allow_nonlocal:
            return

        if host in allowlist:
            return

        if authorized:
            return

        raise ValueError(
            f"DAST target '{target}' is not in the allowlist. "
            f"Allowed hosts: {sorted(allowlist)}. "
            f"Pass --dast-authorized (CLI) or add the host to DAST_ALLOWLIST to proceed."
        )

    # ------------------------------------------------------------------
    # Core scan workflow
    # ------------------------------------------------------------------

    async def execute_scan(
        self,
        target_path: str,
        tools: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        *,
        allow_any_path: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a coordinated security scan using one or more tools.

        This is the main entry point for running scans. It:
          1. Validates the target against security controls.
          2. Calls each tool adapter, collecting all findings.
          3. Merges and deduplicates findings across tools.
          4. Returns a structured summary dict.

        Errors from individual tools are captured and included in the result rather
        than aborting the entire scan — this ensures that a failing DAST tool does
        not prevent SAST results from being returned.

        Args:
            target_path: Filesystem path (SAST) or URL/hostname (DAST) to scan.
            tools: List of tool names to run (defaults to all configured adapters).
            options: Optional dict of scan options. Can contain global options and
                     per-tool option dicts keyed by tool name.
            allow_any_path: (CLI only) Bypass SCAN_ROOT for SAST scans.

        Returns:
            Dict with keys:
              - vulnerabilities: List of normalised finding dicts
              - total_count: Total number of unique findings
              - summary: Count of findings by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
              - tools_used: List of tools that were run
              - errors: Dict of tool_name -> error_message (None if no errors)

        Raises:
            ValueError: If the target path fails validation.
        """
        logger.info(f"Starting scan: {target_path}")

        tools = tools or list(self.adapters.keys())
        options = options or {}

        # Only apply filesystem validation for SAST tools (semgrep scans directories).
        filesystem_tools = {"semgrep"}
        if any(t in filesystem_tools for t in tools):
            self._validate_path(target_path, allow_any_path=allow_any_path)

        # Apply DAST target validation before hitting any external system.
        if "hexstrike" in tools:
            authorized = bool(options.get("dast_authorized", False))
            self._validate_dast_target(target_path, authorized=authorized)

        # Inject HexStrike API key from config if not already provided.
        if settings.hexstrike_api_key and "api_key" not in options:
            options["api_key"] = settings.hexstrike_api_key

        all_results = []
        scan_errors = {}

        # Run each tool independently so a failure in one does not affect others.
        for tool_name in tools:
            try:
                normalized_results = await self.call_adapter(tool_name, target_path, options)
                all_results.extend(normalized_results)
                logger.info(f"{tool_name}: found {len(normalized_results)} finding(s)")
            except Exception as e:
                error_msg = f"{tool_name} scan failed: {str(e)}"
                logger.error(error_msg)
                scan_errors[tool_name] = str(e)

        # Remove duplicate findings before returning (same rule, same file, same line).
        merged_results = self.merger.merge_and_deduplicate(all_results)
        logger.info(f"After deduplication: {len(merged_results)} unique finding(s)")

        # Correlate findings across tools — groups same vulnerability detected by
        # multiple tools and computes a boosted composite_confidence where warranted.
        correlated_groups = self.correlation_engine.correlate(merged_results)
        # Extract primary findings; apply composite_confidence back onto each primary.
        merged_results = []
        for g in correlated_groups:
            finding = g.primary
            finding["confidence"] = g.composite_confidence
            merged_results.append(finding)

        # Annotate each finding with a composite risk score.
        score_findings(merged_results)

        summary = self._generate_summary(merged_results)

        return {
            "vulnerabilities": merged_results,
            "total_count": len(merged_results),
            "summary": summary,
            "tools_used": tools,
            "errors": scan_errors if scan_errors else None
        }

    async def call_adapter(
        self,
        tool_name: str,
        target_path: str,
        options: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Invoke a single tool adapter and return its normalised findings.

        Supports per-tool option overrides: if options contains a dict under the
        tool's name (e.g., options["semgrep"] = {"config": "p/owasp-top-ten"}),
        those options take precedence over any global options for that tool.

        Args:
            tool_name: Key into self.adapters (e.g., "semgrep", "hexstrike").
            target_path: Scan target (path or URL).
            options: Combined global + per-tool options dict.

        Returns:
            List[Dict]: Normalised findings from the tool.

        Raises:
            ValueError: If no adapter is registered for tool_name.
        """
        adapter = self.adapters.get(tool_name)
        if not adapter:
            raise ValueError(f"No adapter registered for tool: {tool_name}")

        # Per-tool options override global options for that tool.
        tool_opts = {}
        if isinstance(options.get(tool_name), dict):
            tool_opts = dict(options[tool_name])

        # Strip nested tool-option dicts from the global options before merging.
        global_opts = {k: v for k, v in options.items() if k not in self.adapters.keys()}
        merged_opts = {**global_opts, **tool_opts}

        logger.info(f"Running {tool_name}...")
        raw_results = await adapter.scan(target_path, merged_opts)
        return adapter.normalize_results(raw_results)

    def normalize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Central normalisation hook for post-scan processing.

        Currently a pass-through — each adapter normalises its own output during
        scan execution. This method exists as an extension point for adding
        cross-tool normalisation logic (e.g., mapping CWE IDs to OWASP categories,
        enriching findings with CVE data).

        Args:
            findings: List of normalised finding dicts from one or more adapters.

        Returns:
            List[Dict]: The same findings (or enriched findings if logic is added).
        """
        return findings

    # ------------------------------------------------------------------
    # Database persistence
    # ------------------------------------------------------------------

    async def save_to_db(
        self,
        db: AsyncSession,
        *,
        scan_id: str,
        target_path: str,
        tools: List[str],
        options: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        project_id: Optional[int] = None,
        status: str = "completed",
        error: Optional[str] = None,
    ) -> None:
        """
        Persist scan metadata and all findings to the database.

        Creates a Scan record, adds all finding rows linked to that scan, and marks
        the scan as completed. Uses a DB flush (not commit) for each step to keep
        the records visible within the same transaction — the caller is responsible
        for the final commit.

        Args:
            db: Active async database session.
            scan_id: Unique identifier for this scan run (e.g., "scan_<uuid>").
            target_path: The path or URL that was scanned.
            tools: List of tool names that were run.
            options: Scan options (stored for audit purposes).
            vulnerabilities: Normalised findings to persist.
            project_id: Optional project ID for associating the scan with a project.
            status: Final scan status ("completed" or "completed_with_errors").
            error: Error message if the scan encountered a critical failure.
        """
        scan_row = await create_scan(
            db,
            scan_id=scan_id,
            target_path=target_path,
            tools=tools,
            options=options,
            project_id=project_id,
        )
        await add_findings(db, scan=scan_row, vulnerabilities=vulnerabilities)
        await complete_scan(db, scan=scan_row, status=status, error=error)
        await db.commit()

    async def run_scan(
        self,
        db: AsyncSession,
        *,
        project_id: int,
        config_id: int,
        target_path: str,
    ) -> Dict[str, Any]:
        """
        Run a scan using a stored project configuration.

        Loads the tool list and options from a saved Config record in the database,
        then executes the scan and persists results. This allows the API to support
        named configurations (e.g., "nightly SAST + full web DAST") without
        requiring callers to repeat the same options on every request.

        Args:
            db: Active async database session.
            project_id: ID of the project this scan belongs to.
            config_id: ID of the Config record containing tools/options.
            target_path: The actual target path or URL to scan (runtime input).

        Returns:
            Dict: Same structure as execute_scan(), plus a "scan_id" key.

        Raises:
            ValueError: If no matching Config is found.
        """
        cfg = await get_config_by_id(db, config_id=config_id, project_id=project_id)
        if not cfg:
            raise ValueError(
                f"Config not found (project_id={project_id}, config_id={config_id})"
            )

        tools = list(cfg.tools or [])
        options = dict(cfg.options or {})

        scan_id = f"scan_{uuid4().hex}"
        results = await self.execute_scan(
            target_path=target_path,
            tools=tools,
            options=options,
            allow_any_path=False
        )

        vulns = self.normalize_findings(results.get("vulnerabilities") or [])
        status = "completed" if not results.get("errors") else "completed_with_errors"
        await self.save_to_db(
            db,
            scan_id=scan_id,
            target_path=target_path,
            tools=tools,
            options=options,
            vulnerabilities=vulns,
            project_id=project_id,
            status=status,
        )

        results["scan_id"] = scan_id
        return results

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Count findings by severity to produce a quick overview.

        The summary is included in every scan response so callers can see the
        overall risk picture at a glance without iterating over all findings.

        Args:
            vulnerabilities: List of normalised finding dicts.

        Returns:
            Dict: Counts keyed by severity level
                  e.g. {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 7, "LOW": 12, "INFO": 2}
        """
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO").upper()
            if severity in summary:
                summary[severity] += 1

        return summary
