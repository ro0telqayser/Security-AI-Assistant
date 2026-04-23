"""
backend/app/core/security.py
==============================
Security utility functions for input validation and sanitisation.

Input validation is a fundamental principle of secure software development.
All data received from external sources (API requests, CLI arguments, file paths)
should be validated and sanitised before use. This is especially important in a
security scanning tool — if the scanner itself is vulnerable to injection, it
undermines the entire purpose of the tool.

This module focuses on path validation, which is the most critical input type
in this application. Malformed paths can lead to directory traversal attacks
(CWE-22 — Path Traversal), allowing attackers to read or scan files outside
the intended scan scope.

Reference: OWASP A03:2021 — Injection (includes path traversal as a sub-category)
           CWE-22: Improper Limitation of a Pathname to a Restricted Directory
"""

from pathlib import Path
from loguru import logger
from fastapi import HTTPException, status


def sanitize_path(file_path: str) -> str:
    """
    Sanitise a user-supplied file path to prevent directory traversal attacks.

    Performs the following checks and transformations:
      1. Rejects empty paths.
      2. Removes null bytes (used in some traversal payloads to truncate strings
         at the OS level — e.g., `safe.txt\x00.php` is treated as `safe.txt`
         by Python's open() but may be truncated to `safe.txt` by the OS).
      3. Rejects paths containing `..` or starting with `/` (absolute paths)
         — both are common traversal vectors.
      4. Resolves and normalises the path using pathlib.

    This function is used at the API layer before passing paths to the scanner.
    The WorkflowManager also has its own path validation (_validate_path) which
    enforces SCAN_ROOT confinement. Having validation at both layers provides
    defence in depth.

    Reference: CWE-22 Path Traversal
               OWASP Testing Guide — Testing for Path Traversal (OTG-AUTHZ-001)

    Args:
        file_path: The raw path string received from the API request or user input.

    Returns:
        str: The resolved, normalised path string if all checks pass.

    Raises:
        HTTPException 400: If the path is empty, contains traversal sequences,
                           or cannot be resolved.
    """
    if not file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path cannot be empty"
        )

    # Remove null bytes — these are used in some injection attacks to truncate
    # strings at the OS level, bypassing extension checks.
    file_path = file_path.replace("\x00", "")

    # Reject directory traversal sequences and absolute paths.
    # '..' allows navigating up the directory tree (e.g., ../../etc/passwd).
    # Absolute paths starting with '/' bypass relative root restrictions.
    if ".." in file_path or file_path.startswith("/"):
        logger.warning(f"Path traversal attempt detected and blocked: {file_path}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid path: directory traversal sequences are not permitted"
        )

    # Resolve to an absolute path for consistent handling downstream.
    try:
        path = Path(file_path).resolve()
        return str(path)
    except Exception as e:
        logger.error(f"Path resolution failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid path: {str(e)}"
        )
