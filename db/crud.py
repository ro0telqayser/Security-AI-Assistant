"""
db/crud.py
===========
CRUD helper functions for interacting with the database.

CRUD stands for Create, Read, Update, Delete — the four fundamental operations
performed on database records. Rather than writing raw SQL or scattering SQLAlchemy
query logic across the application, all database interactions are centralised here.
This makes the code easier to test, maintain, and reason about.

All functions are async and accept an AsyncSession as their first argument. The
session is provided by the FastAPI dependency injection system (get_db() in
database.py) or by the CLI's session context manager.

Naming convention:
  - create_*   — insert a new record and return the ORM object
  - get_*      — retrieve a single record (returns None if not found)
  - add_*      — insert multiple related records (e.g., findings for a scan)
  - complete_* — update the status of an existing record
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AIExplanation, Config, Finding, FixSuggestion, Project, Scan


async def create_scan(
    db: AsyncSession,
    *,
    scan_id: str,
    target_path: str,
    tools: List[str],
    options: Dict[str, Any],
    project_id: Optional[int] = None,
) -> Scan:
    """
    Create a new Scan record and flush it to the session.

    Sets the initial status to "running" so that incomplete scans (e.g., ones
    interrupted by a crash) can be identified and cleaned up. The scan_id is the
    public UUID identifier returned in API responses; the auto-increment id is the
    internal foreign key used by Finding records.

    Args:
        db: Active async database session.
        scan_id: UUID-based public identifier (e.g., "scan_abc123...").
        target_path: Filesystem path or URL that was scanned.
        tools: List of tool names used in this scan.
        options: Scan options dict (stored for audit / reproducibility).
        project_id: Optional project this scan belongs to.

    Returns:
        Scan: The newly created (unflushed commit) Scan ORM object.
    """
    scan = Scan(
        scan_id=scan_id,
        project_id=project_id,
        target_path=target_path,
        tools=tools,
        options=options,
        status="running",
    )
    db.add(scan)
    await db.flush()  # Populate scan.id without committing the transaction
    return scan


async def complete_scan(
    db: AsyncSession,
    *,
    scan: Scan,
    status: str,
    error: Optional[str] = None,
) -> Scan:
    """
    Mark a scan as finished and record the completion time.

    Called after all tools have run (successfully or not). The status should be
    "completed" if all tools ran without errors, or "completed_with_errors" if
    one or more tools failed (but others may have returned findings).

    Args:
        db: Active async database session.
        scan: The Scan ORM object to update.
        status: Final status string ("completed" or "completed_with_errors").
        error: Optional error message for scan-level failures.

    Returns:
        Scan: The updated Scan ORM object.
    """
    scan.status = status
    scan.error = error
    scan.finished_at = datetime.utcnow()
    await db.flush()
    return scan


async def add_findings(
    db: AsyncSession,
    *,
    scan: Scan,
    vulnerabilities: List[Dict[str, Any]],
) -> List[Finding]:
    """
    Insert all findings from a scan into the database.

    Converts each normalised finding dict into a Finding ORM object and adds it
    to the session. SAST findings typically have file_path and line populated;
    DAST findings use the JSON location field.

    The raw tool metadata is stored in the 'meta' column so that analysts can
    inspect the original tool output without needing to re-run the scan.

    Args:
        db: Active async database session.
        scan: The parent Scan object (provides the scan_id foreign key).
        vulnerabilities: List of normalised finding dicts from the adapters.

    Returns:
        List[Finding]: The list of newly created Finding ORM objects.
    """
    created: List[Finding] = []

    for v in vulnerabilities:
        location = v.get("location") or {}
        finding = Finding(
            scan_id=scan.id,
            external_id=str(v.get("id") or ""),
            source=str(v.get("source") or ""),
            severity=str(v.get("severity") or "INFO"),
            title=str(v.get("title") or ""),
            description=str(v.get("description") or ""),
            # SAST location (null for DAST findings)
            file_path=location.get("file_path"),
            line=location.get("line"),
            column=location.get("column"),
            end_line=location.get("end_line"),
            end_column=location.get("end_column"),
            # Security classification
            cwe_id=v.get("cwe_id"),
            owasp_category=v.get("owasp_category"),
            confidence=v.get("confidence"),
            # Full location object (includes URL/endpoint for DAST)
            location=location,
            meta=v.get("metadata") or {},
        )
        db.add(finding)
        created.append(finding)

    await db.flush()
    return created


async def get_scan_by_scan_id(db: AsyncSession, scan_id: str) -> Optional[Scan]:
    """
    Retrieve a Scan by its public UUID identifier.

    Used by the CLI's LLM explanation step to look up the scan just completed
    and fetch its findings for processing.

    Args:
        db: Active async database session.
        scan_id: The public UUID string (e.g., "scan_abc123...").

    Returns:
        Scan | None: The matching Scan object, or None if not found.
    """
    res = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    return res.scalar_one_or_none()


async def create_project(
    db: AsyncSession,
    *,
    name: str,
    description: Optional[str] = None,
    owner_id: Optional[int] = None,
) -> Project:
    """
    Create a new Project record.

    Args:
        db: Active async database session.
        name: Project name (must be unique per owner).
        description: Optional project description.
        owner_id: Optional ID of the owning User.

    Returns:
        Project: The newly created Project ORM object.
    """
    project = Project(owner_id=owner_id, name=name, description=description)
    db.add(project)
    await db.flush()
    return project


async def create_config(
    db: AsyncSession,
    *,
    project_id: int,
    name: str,
    tools: List[str],
    options: Dict[str, Any],
) -> Config:
    """
    Create a saved scan configuration for a project.

    Args:
        db: Active async database session.
        project_id: ID of the project this configuration belongs to.
        name: Configuration name (must be unique within the project).
        tools: List of tool names to use in this config.
        options: Tool-specific options dict.

    Returns:
        Config: The newly created Config ORM object.
    """
    cfg = Config(project_id=project_id, name=name, tools=tools, options=options)
    db.add(cfg)
    await db.flush()
    return cfg


async def get_config_by_id(
    db: AsyncSession,
    *,
    config_id: int,
    project_id: Optional[int] = None,
) -> Optional[Config]:
    """
    Retrieve a Config record by its ID.

    Optionally scopes the lookup to a specific project to prevent one project
    from using another project's configurations.

    Args:
        db: Active async database session.
        config_id: Primary key of the Config record.
        project_id: Optional project ID to scope the lookup.

    Returns:
        Config | None: The matching Config, or None if not found.
    """
    stmt = select(Config).where(Config.id == config_id)
    if project_id is not None:
        stmt = stmt.where(Config.project_id == project_id)
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def get_findings_for_scan(db: AsyncSession, scan: Scan) -> List[Finding]:
    """
    Retrieve all findings associated with a scan.

    Used by the LLM explanation step to fetch the findings that need processing.

    Args:
        db: Active async database session.
        scan: The parent Scan object.

    Returns:
        List[Finding]: All Finding records belonging to the scan.
    """
    res = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
    return res.scalars().all()


async def create_ai_explanation(
    db: AsyncSession,
    *,
    finding: Finding,
    explanation: str,
) -> AIExplanation:
    """
    Store an LLM-generated explanation for a finding.

    Args:
        db: Active async database session.
        finding: The Finding object this explanation relates to.
        explanation: The plain-English explanation text from the LLM.

    Returns:
        AIExplanation: The newly created explanation record.
    """
    obj = AIExplanation(
        finding_id=finding.id,
        model="deepseek",
        explanation=explanation,
        metadata={},
    )
    db.add(obj)
    await db.flush()
    return obj


async def create_fix_suggestion(
    db: AsyncSession,
    *,
    finding: Finding,
    suggestion: str,
) -> FixSuggestion:
    """
    Store an LLM-generated remediation suggestion for a finding.

    Args:
        db: Active async database session.
        finding: The Finding object this suggestion relates to.
        suggestion: The remediation advice text from the LLM.

    Returns:
        FixSuggestion: The newly created fix suggestion record.
    """
    obj = FixSuggestion(
        finding_id=finding.id,
        model="deepseek",
        suggestion=suggestion,
        patch=None,
        metadata={},
    )
    db.add(obj)
    await db.flush()
    return obj
