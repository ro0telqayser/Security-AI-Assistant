"""
backend/app/api/v1/endpoints/security.py
==========================================
Security scanning API endpoint — POST /api/v1/security/scan.

This module defines the REST API endpoint for initiating security scans. It acts
as a thin orchestration layer between the HTTP request and the WorkflowManager:
  1. Receive and validate the scan request (Pydantic handles schema validation).
  2. Delegate the actual scanning to WorkflowManager.
  3. Persist results to the database.
  4. Return a structured ScanResponse.

Two modes of operation are supported:

  **Ad-hoc scan** (no project_id/config_id):
    The caller provides a target_path, list of tools, and any options directly
    in the request body. Results are saved to the database under a new scan_id.

  **Config-based scan** (project_id + config_id provided):
    Tools and options are loaded from a previously saved Config record in the
    database. This allows named, repeatable scan configurations without needing
    to repeat all options on every API call.

Error handling:
  - Path validation errors and DAST allowlist violations return 500 with a
    descriptive message. These should be 400 errors in a production system;
    the 500 is used here for simplicity.
  - Database errors trigger a rollback to prevent partial writes.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrator import WorkflowManager
from db.database import get_db
from schemas.security import ScanRequest, ScanResponse, Vulnerability

router = APIRouter(prefix="/security", tags=["security"])


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_200_OK, summary="Initiate a SAST or DAST security scan")
async def scan_codebase(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db)
) -> ScanResponse:
    """
    Initiate a security scan on the specified target.

    Accepts a target path (for SAST) or URL (for DAST), a list of tools to run,
    and optional tool-specific options. Runs the scan, saves results, and returns
    a structured response containing all findings.

    Request body (ScanRequest):
        target_path (str):  Directory/file path for SAST, URL for DAST.
        tools (list[str]):  Tool names to run (e.g., ["semgrep"], ["hexstrike"]).
        options (dict):     Tool-specific options (see adapter documentation).
        project_id (int):   Optional — use with config_id for config-based scans.
        config_id (int):    Optional — ID of saved Config to load tools/options from.

    Returns:
        ScanResponse: Scan ID, status, list of vulnerabilities, severity summary.

    Raises:
        HTTPException 500: If the scan fails due to a validation error, tool failure,
                           or database error.

    Example request:
        POST /api/v1/security/scan
        {
          "target_path": "/path/to/project",
          "tools": ["semgrep"],
          "options": {"semgrep": {"config": "p/owasp-top-ten"}}
        }
    """
    logger.info(f"Scan request received: target={request.target_path}, tools={request.tools}")

    try:
        manager = WorkflowManager()

        if request.project_id is not None and request.config_id is not None:
            # Config-based scan: load tools and options from the saved Config record.
            results = await manager.run_scan(
                db,
                project_id=request.project_id,
                config_id=request.config_id,
                target_path=request.target_path,
            )
            scan_id = results.get("scan_id")
            raw_vulns = results.get("vulnerabilities") or []

        else:
            # Ad-hoc scan: use the tools and options from the request body directly.
            scan_id = f"scan_{__import__('uuid').uuid4().hex}"
            results = await manager.execute_scan(
                target_path=request.target_path,
                tools=request.tools,
                options=request.options,
            )
            raw_vulns = results.get("vulnerabilities") or []

            # Persist the results immediately for ad-hoc scans.
            status_text = "completed" if not results.get("errors") else "completed_with_errors"
            await manager.save_to_db(
                db,
                scan_id=scan_id,
                target_path=request.target_path,
                tools=request.tools,
                options=request.options,
                vulnerabilities=raw_vulns,
                status=status_text,
            )

        # Convert raw dicts to Pydantic Vulnerability objects for response validation.
        vulns = [Vulnerability(**v) for v in raw_vulns]

        return ScanResponse(
            scan_id=scan_id,
            status="completed" if not results.get("errors") else "completed_with_errors",
            vulnerabilities=vulns,
            total_count=results.get("total_count", len(vulns)),
            summary=results.get("summary") or {
                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
            },
            tools_used=results.get("tools_used"),
            errors=results.get("errors"),
        )

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        # Roll back any partial writes to keep the database consistent.
        try:
            await db.rollback()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )
