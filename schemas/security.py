"""
schemas/security.py
=====================
Pydantic schemas for the security scanning API.

These models define the public API contract — the exact shape of request bodies
and response objects for the /scan endpoint. Pydantic validates incoming requests
automatically before they reach the endpoint handler, returning a 422 Unprocessable
Entity response with a detailed error message if the data does not match the schema.

Using separate Pydantic schemas (rather than SQLAlchemy models directly) for the API
is a deliberate design choice that follows the separation of concerns principle:
  - SQLAlchemy models represent the database schema.
  - Pydantic schemas represent the API interface.
  - Changes to the database structure do not automatically affect the API, and vice versa.

Schemas defined here:
  - VulnerabilityLocation: Where a finding was detected (file+line for SAST, URL for DAST)
  - Vulnerability:         A single security finding (the core data object)
  - ScanRequest:           The body of a POST /scan request
  - ScanResponse:          The response body after a scan completes
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VulnerabilityLocation(BaseModel):
    """
    The location of a vulnerability finding.

    SAST findings (from Semgrep) use file_path, line, and column.
    DAST findings (from HexStrike) use url, endpoint, and parameter.
    All fields are optional because a given tool may not provide all of them.
    """

    # SAST location fields
    file_path: Optional[str] = Field(
        default=None,
        description="Path to the file containing the vulnerability (SAST findings)"
    )
    line: Optional[int] = Field(
        default=None,
        description="1-based line number within the file"
    )
    column: Optional[int] = Field(
        default=None,
        description="1-based column number on the line"
    )
    end_line: Optional[int] = Field(
        default=None,
        description="End line of the vulnerable code range"
    )
    end_column: Optional[int] = Field(
        default=None,
        description="End column of the vulnerable code range"
    )

    # DAST location fields
    url: Optional[str] = Field(
        default=None,
        description="URL where the vulnerability was found (DAST findings)"
    )
    endpoint: Optional[str] = Field(
        default=None,
        description="Endpoint path on the target (DAST findings)"
    )
    parameter: Optional[str] = Field(
        default=None,
        description="Request parameter that is vulnerable (e.g., SQLi parameter)"
    )


class Vulnerability(BaseModel):
    """
    A single security vulnerability finding.

    This is the central data object passed between all layers of the application.
    The Severity field follows a standard 5-level scale:
      - CRITICAL: Remote code execution, authentication bypass, data breach risk
      - HIGH:     SQL injection, significant information disclosure, privilege escalation
      - MEDIUM:   XSS, CSRF, security misconfiguration, insecure direct object reference
      - LOW:      Missing security headers, information leakage, minor misconfigurations
      - INFO:     Informational findings, fingerprinting results, recon data

    The confidence field (0.0–1.0) indicates how likely the finding is to be a
    real vulnerability rather than a false positive. SAST tools generate more
    false positives than DAST tools because they cannot observe runtime behaviour.
    """

    id: str = Field(
        ...,
        description="Unique identifier for this finding (e.g., rule_id:file:line)"
    )
    title: str = Field(
        ...,
        description="Short name for the vulnerability (e.g., 'SQL Injection (sqlmap)')"
    )
    description: str = Field(
        ...,
        description="Detailed description of the vulnerability and its risk"
    )
    severity: str = Field(
        ...,
        description="Severity level: CRITICAL | HIGH | MEDIUM | LOW | INFO"
    )
    source: str = Field(
        ...,
        description="Name of the tool that detected this finding (e.g., semgrep, hexstrike)"
    )
    location: VulnerabilityLocation = Field(
        default_factory=VulnerabilityLocation,
        description="Where the vulnerability was found (file path or URL)"
    )
    cwe_id: Optional[str] = Field(
        default=None,
        description="CWE identifier if available (e.g., 'CWE-89' for SQL Injection)"
    )
    owasp_category: Optional[str] = Field(
        default=None,
        description="OWASP Top 10 category (e.g., 'A03:2021 - Injection')"
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        default=0.5,
        description="Confidence score: 0.0 = uncertain, 1.0 = confirmed"
    )
    metadata: Optional[dict] = Field(
        default=None,
        description="Raw tool output for detailed investigation"
    )


class ScanRequest(BaseModel):
    """
    Request body for POST /api/v1/security/scan.

    The caller specifies what to scan, which tools to use, and any options.
    Optionally, a saved project configuration can be referenced by providing
    project_id and config_id — in that case, tools and options are loaded from
    the database and the request-level tools/options are ignored.
    """

    target_path: str = Field(
        ...,
        description="Path/target to scan. Use a filesystem path for SAST (Semgrep) "
                    "or a URL/hostname for DAST (HexStrike)."
    )
    tools: List[str] = Field(
        default_factory=lambda: ["semgrep"],
        description="List of tools to run. Options: 'semgrep' (SAST), 'hexstrike' (DAST)."
    )
    options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific options. Use tool name as key, options dict as value. "
                    "E.g., {'semgrep': {'config': 'p/owasp-top-ten', 'timeout_seconds': 300}}"
    )
    # Optional: use a saved project configuration instead of specifying tools/options inline
    project_id: Optional[int] = Field(
        default=None,
        description="Project ID — use with config_id to run a saved configuration."
    )
    config_id: Optional[int] = Field(
        default=None,
        description="Config ID — loads tools/options from a previously saved Config record."
    )


class ScanResponse(BaseModel):
    """
    Response body for POST /api/v1/security/scan.

    Returns the scan results including all findings, a severity summary, and
    information about which tools were run.
    """

    scan_id: str = Field(
        ...,
        description="Unique scan identifier (e.g., 'scan_abc123...')"
    )
    status: str = Field(
        ...,
        description="Scan completion status: 'completed' or 'completed_with_errors'"
    )
    vulnerabilities: List[Vulnerability] = Field(
        ...,
        description="List of all unique vulnerability findings from this scan"
    )
    total_count: int = Field(
        ...,
        description="Total number of unique findings after deduplication"
    )
    summary: Dict[str, int] = Field(
        ...,
        description="Count of findings by severity level "
                    "(e.g., {'CRITICAL': 0, 'HIGH': 3, 'MEDIUM': 7, 'LOW': 12, 'INFO': 2})"
    )
    tools_used: Optional[List[str]] = Field(
        default=None,
        description="List of tools that were run during this scan"
    )
    errors: Optional[Dict[str, str]] = Field(
        default=None,
        description="Per-tool error messages if any tools failed "
                    "(null if all tools completed successfully)"
    )
