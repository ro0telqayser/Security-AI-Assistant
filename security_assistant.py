#!/usr/bin/env python3
"""
security_assistant.py
======================
Command-line interface for the Security AI Assistant.

This is the primary entry point for running security scans from the terminal.
It supports three scan modes:
  - SAST  — Static Application Security Testing using Semgrep
  - DAST  — Dynamic Application Security Testing using HexStrike
  - SAST,DAST — Both modes combined in a single run

Usage examples:
  # Scan a local project for code vulnerabilities
  python3 security_assistant.py --scan SAST --sast-path "/path/to/project" --allow-any-path

  # Scan a running web application for vulnerabilities
  python3 security_assistant.py --scan DAST --dast-target "http://127.0.0.1:3000" --dast-tool nuclei --dast-authorized

  # Run both SAST and DAST together
  python3 security_assistant.py --scan SAST,DAST --sast-path "/path" --dast-target "http://127.0.0.1:3000" --allow-any-path --dast-tool all-web --dast-authorized

  # Generate LLM explanations and fix suggestions after scanning
  python3 security_assistant.py --scan SAST --sast-path "/path" --allow-any-path --llm-explain

The CLI:
  1. Validates scan types and resolves target paths.
  2. Auto-starts the HexStrike server if a DAST scan is requested (unless --no-start-hexstrike).
  3. Checks that required tools are installed (Semgrep, Nuclei, etc.).
  4. Delegates scanning to WorkflowManager.
  5. Persists results to the SQLite database.
  6. Optionally queries the local LLM for explanations and fixes.
  7. Prints findings to stdout sorted by severity.

Important: Only scan systems you own or have explicit written permission to test.
Unauthorised scanning is illegal under the Computer Misuse Act 1990 (UK).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import urllib.request
import subprocess
import time
import os
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List
import socket
from uuid import uuid4

from loguru import logger

from db.database import AsyncSessionLocal, init_db
from orchestrator import WorkflowManager
from backend.app.core.config import settings
from ai_engine import generate_explanation_and_fix
from db.crud import (
    get_scan_by_scan_id,
    get_findings_for_scan,
    create_ai_explanation,
    create_fix_suggestion,
)
from scripts.install_tools import ensure_tools, REQUIRED_TOOLS


def _parse_scan_list(raw: str) -> List[str]:
    """
    Parse a comma-separated scan type string into a list of uppercase type names.

    Args:
        raw: Comma-separated string (e.g., "SAST,DAST" or "sast").

    Returns:
        List[str]: Uppercase scan types (e.g., ["SAST", "DAST"]).
    """
    parts = [p.strip().upper() for p in raw.split(",")]
    parts = [p for p in parts if p]
    return parts


def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the argument parser for the CLI.

    Defines all flags for controlling scan type, targets, tools, and options.
    Split into logical groups: core flags, SAST options, DAST/HexStrike options,
    LLM options, and individual tool options (Nuclei, SQLMap, HTTPX, etc.).

    Returns:
        argparse.ArgumentParser: Configured parser ready to call parse_args() on.
    """
    p = argparse.ArgumentParser(description="Security AI Assistant (CLI)")
    p.add_argument(
        "--scan",
        required=True,
        help="Comma-separated scan types: SAST,DAST (e.g. SAST or SAST,DAST)",
    )
    p.add_argument("--path", required=False, help="Legacy path (SAST folder or DAST URL). Prefer --sast-path/--dast-target.")
    p.add_argument("--sast-path", default=None, help="Filesystem path for SAST scans")
    p.add_argument("--dast-target", default=None, help="URL/target for DAST scans")
    p.add_argument(
        "--allow-any-path",
        action="store_true",
        help="(Unsafe) Allow scanning any absolute path on this machine for SAST. "
             "By default scans are restricted by SCAN_ROOT for safety.",
    )
    p.add_argument(
        "--no-start-hexstrike",
        action="store_true",
        help="Do not auto-start HexStrike server (default is to start if needed).",
    )
    p.add_argument(
        "--hexstrike-path",
        default=None,
        help="Path to hexstrike-ai directory (overrides HEXSTRIKE_PATH).",
    )
    p.add_argument(
        "--hexstrike-port",
        type=int,
        default=None,
        help="HexStrike port (overrides HEXSTRIKE_URL port).",
    )

    # Semgrep (SAST)
    p.add_argument("--semgrep-config", default="auto", help="Semgrep config (default: auto)")
    p.add_argument("--semgrep-timeout", type=int, default=300, help="Semgrep timeout seconds (default: 300)")

    # HexStrike (DAST)
    p.add_argument(
        "--dast-tool",
        default="nuclei",
        help=(
            "HexStrike web/DAST tool to run. Use a specific tool name (e.g., nuclei, httpx, ffuf) "
            "or 'all-web' to run the full web toolchain sequentially. Use 'runtime' for header/rate checks."
        ),
    )
    p.add_argument("--hexstrike-endpoint", default=None, help="Override HexStrike endpoint (advanced)")
    p.add_argument(
        "--hexstrike-target",
        default=None,
        help="Explicit DAST target (URL/host). If omitted, uses --path.",
    )
    p.add_argument(
        "--dast-authorized",
        action="store_true",
        help="Confirm you are authorized to scan the DAST target. Required for non-allowlisted targets.",
    )
    p.add_argument(
        "--skip-tool-check",
        action="store_true",
        help="Skip automatic tool installation check before scanning.",
    )
    p.add_argument(
        "--llm-explain",
        action="store_true",
        help="Generate DeepSeek explanations and fix suggestions for findings after the scan.",
    )
    p.add_argument(
        "--llm-max-findings",
        type=int,
        default=10,
        help="Maximum number of findings to send to LLM for explanation (default: 10).",
    )
    # Nuclei options
    p.add_argument("--nuclei-severity", default="critical,high,medium,low,info", help="Nuclei severity filter")
    p.add_argument("--nuclei-tags", default="", help="Nuclei tags filter (optional)")
    p.add_argument("--nuclei-template", default="", help="Nuclei template path (optional)")
    # httpx options
    p.add_argument("--httpx-tech", dest="httpx_tech", action="store_true", help="Enable httpx technology detection")
    p.add_argument("--httpx-title", dest="httpx_title", action="store_true", help="Enable httpx title extraction")
    p.add_argument("--httpx-status", dest="httpx_status", action="store_true", help="Enable httpx status code output")
    p.add_argument("--httpx-server", dest="httpx_server", action="store_true", help="Enable httpx web server fingerprinting")
    # wafw00f options
    p.add_argument("--wafw00f-verbose", dest="wafw00f_verbose", action="store_true", help="Verbose WAF detection output")
    # sqlmap options
    p.add_argument("--sqlmap-data", default="", help="SQLMap POST data (e.g., 'a=1&b=2')")
    p.add_argument("--sqlmap-cookies", default="", help="SQLMap cookies string (e.g., 'PHPSESSID=...; security=low')")
    p.add_argument("--sqlmap-headers", default="", help="SQLMap headers string (e.g., 'User-Agent: ...')")
    p.add_argument("--sqlmap-level", type=int, default=1, help="SQLMap level (1-5)")
    p.add_argument("--sqlmap-risk", type=int, default=1, help="SQLMap risk (1-3)")
    p.add_argument("--sqlmap-threads", type=int, default=1, help="SQLMap threads")
    p.add_argument("--sqlmap-args", default="", help="Extra SQLMap args (advanced)")

    return p


def _runtime_security_checks(target: str) -> List[dict]:
    """
    Perform lightweight runtime security checks on the target without HexStrike.

    Checks for missing HTTP security headers and basic rate limiting. These checks
    are implemented directly in Python using urllib so they run even when HexStrike
    is not available.

    Security headers checked:
      - Content-Security-Policy (CSP): Prevents XSS by restricting resource loading.
      - Strict-Transport-Security (HSTS): Forces HTTPS connections.
      - X-Frame-Options: Prevents clickjacking attacks.
      - X-Content-Type-Options: Prevents MIME-type sniffing.
      - Referrer-Policy: Controls what information is sent in the Referer header.

    Rate limiting check: Sends 8 rapid requests and looks for a 429 (Too Many Requests)
    response. Missing rate limiting can facilitate brute-force and DoS attacks.

    Reference: OWASP A05:2021 — Security Misconfiguration

    Args:
        target: URL of the web application to check.

    Returns:
        List[dict]: Normalised findings for each missing header or absent rate limit.
                    Returns an empty list if the target is unreachable.
    """
    findings: List[dict] = []
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "Security-AI-Assistant"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

        # Security headers
        header_checks = [
            ("content-security-policy", "CSP missing", "MEDIUM"),
            ("strict-transport-security", "HSTS missing", "MEDIUM"),
            ("x-frame-options", "X-Frame-Options missing", "LOW"),
            ("x-content-type-options", "X-Content-Type-Options missing", "LOW"),
            ("referrer-policy", "Referrer-Policy missing", "LOW"),
        ]
        for header, desc, sev in header_checks:
            if header not in headers:
                findings.append(
                    {
                        "id": f"runtime:header:{header}",
                        "title": desc,
                        "description": f"Missing response header: {header}",
                        "severity": sev,
                        "source": "runtime",
                        "location": {"url": target},
                        "confidence": 0.6,
                        "metadata": {"header": header},
                    }
                )

        # Basic rate limit check (best-effort)
        rate_limited = False
        for _ in range(8):
            try:
                with urllib.request.urlopen(req, timeout=3) as r2:
                    if r2.status == 429:
                        rate_limited = True
                        break
            except Exception:
                pass
        if not rate_limited:
            findings.append(
                {
                    "id": "runtime:rate-limit:missing",
                    "title": "No rate limiting detected",
                    "description": "Burst requests did not trigger 429/limit response.",
                    "severity": "LOW",
                    "source": "runtime",
                    "location": {"url": target},
                    "confidence": 0.4,
                    "metadata": {},
                }
            )
    except Exception:
        # Don't fail scans on runtime checks
        return []

    return findings


async def run_cli(args: argparse.Namespace) -> int:
    """
    Main CLI logic — runs the scan and outputs results.

    Orchestrates the full scan workflow:
      1. Parses and validates the requested scan types.
      2. Checks that required tools are installed.
      3. Starts HexStrike if a DAST scan is requested.
      4. Initialises the database.
      5. Runs SAST and/or DAST scans via WorkflowManager.
      6. Persists all findings to the database.
      7. Optionally queries the LLM for explanations and fixes.
      8. Prints findings sorted by severity.

    Args:
        args: Parsed argparse.Namespace from build_parser().

    Returns:
        int: Exit code (0 = success, 2 = argument error or startup failure).
    """
    scan_types = _parse_scan_list(args.scan)
    if not scan_types:
        logger.error("No scan types specified.")
        return 2

    allowed = {"SAST", "DAST"}
    unknown = [s for s in scan_types if s not in allowed]
    if unknown:
        logger.error(f"Unknown scan types: {unknown}. Allowed: SAST, DAST")
        return 2

    # Ensure required security tools are installed before running any scan
    if not getattr(args, "skip_tool_check", False):
        dast_tools_needed = REQUIRED_TOOLS if "DAST" in scan_types else []
        sast_tools_needed = ["semgrep"] if "SAST" in scan_types else []
        tools_to_check = list(dict.fromkeys(sast_tools_needed + dast_tools_needed))
        if tools_to_check:
            logger.info("Checking required tools...")
            ensure_tools(tools_to_check, auto_install=True)

    tools: List[str] = []
    if "SAST" in scan_types:
        tools.append("semgrep")
    if "DAST" in scan_types:
        tools.append("hexstrike")

    # Per-tool options
    options: Dict[str, object] = {
        "semgrep": {
            "config": args.semgrep_config,
            "timeout_seconds": args.semgrep_timeout,
        },
        "hexstrike": {
            "dast_tool": args.dast_tool,
            # Allow explicit endpoint override; otherwise adapter uses dast_tool.
            "endpoint": args.hexstrike_endpoint,
            # nuclei
            "severity": args.nuclei_severity,
            "tags": args.nuclei_tags,
            "template": args.nuclei_template,
            # httpx
            "tech_detect": bool(getattr(args, "httpx_tech", False)),
            "title": bool(getattr(args, "httpx_title", False)),
            "status_code": bool(getattr(args, "httpx_status", False)),
            "web_server": bool(getattr(args, "httpx_server", False)),
            # wafw00f
            "verbose": bool(getattr(args, "wafw00f_verbose", False)),
            # sqlmap
            "data": args.sqlmap_data,
            "cookies": args.sqlmap_cookies,
            "headers": args.sqlmap_headers,
            "level": args.sqlmap_level,
            "risk": args.sqlmap_risk,
            "threads": args.sqlmap_threads,
            "additional_args": args.sqlmap_args,
        },
        # Used by orchestrator safety checks
        "dast_authorized": bool(args.dast_authorized),
    }

    # Resolve paths with explicit flags taking priority
    if args.sast_path and args.dast_target:
        target_path = args.sast_path
    else:
        target_path = args.sast_path or args.path

    # DAST-only: target_path must not be None (DB NOT NULL constraint)
    if not target_path and "DAST" in scan_types:
        target_path = args.hexstrike_target or args.dast_target or args.path

    if "SAST" in scan_types and not target_path:
        logger.error("SAST requested but no --sast-path provided (or --path fallback).")
        return 2

    if "DAST" in scan_types and not (args.dast_target or args.path):
        logger.error("DAST requested but no --dast-target provided (or --path fallback).")
        return 2

    # If DAST requested and an explicit DAST target was provided, use it as target_path for the run.
    # Note: if you run both SAST+DAST, keep --path as a filesystem path and pass --hexstrike-target as URL.
    if "DAST" in scan_types and args.hexstrike_target:
        # We'll pass the DAST target via tool-specific options, so SAST still uses filesystem path.
        options["hexstrike"]["target_override"] = args.hexstrike_target

    if "DAST" in scan_types and not args.no_start_hexstrike:
        if not await _ensure_hexstrike_running(args.hexstrike_path, args.hexstrike_port):
            logger.error("Failed to start HexStrike server.")
            return 2

    await init_db()

    scan_id = f"scan_{uuid4().hex}"
    manager = WorkflowManager()

    # If hexstrike target override is set, we'll execute tools one-by-one so each tool gets the right target.
    results_vulns: List[dict] = []
    llm_results: List[dict] = []
    errors: Dict[str, str] = {}
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    async def _merge_into_summary(vulns: List[dict]) -> None:
        for v in vulns:
            sev = str(v.get("severity", "INFO")).upper()
            if sev in summary:
                summary[sev] += 1

    async with AsyncSessionLocal() as db:
        try:
            # Run SAST on filesystem path
            if "SAST" in scan_types:
                r = await manager.execute_scan(
                    target_path=target_path,
                    tools=["semgrep"],
                    options=options,
                    allow_any_path=bool(args.allow_any_path),
                )
                vulns = r.get("vulnerabilities") or []
                results_vulns.extend(vulns)
                if r.get("errors"):
                    errors.update(r["errors"])

            # Run DAST on URL/target
            if "DAST" in scan_types:
                dast_target = args.hexstrike_target or args.dast_target or args.path
                # Use separate call so URL doesn't hit filesystem validator.
                if args.dast_tool in {"all", "all-web"}:
                    if args.hexstrike_endpoint:
                        logger.error("--hexstrike-endpoint cannot be used with --dast-tool all")
                        return 2

                    # Full web toolchain (best-effort).
                    all_web_tools = [
                        "gobuster",
                        "dirsearch",
                        "feroxbuster",
                        "ffuf",
                        "dirb",
                        "httpx",
                        "katana",
                        "hakrawler",
                        "gau",
                        "waybackurls",
                        "nuclei",
                        "nikto",
                        "sqlmap",
                        "wpscan",
                        "arjun",
                        "paramspider",
                        "x8",
                        "jaeles",
                        "dalfox",
                        "wafw00f",
                        "testssl",
                        "sslscan",
                        "sslyze",
                        "anew",
                        "qsreplace",
                        "uro",
                        "whatweb",
                        "jwt-tool",
                        "graphql-voyager",
                        "wfuzz",
                        "commix",
                        "nosqlmap",
                        "tplmap",
                    ]
                    # Only run tools that accept URL targets directly (avoid known 400/404 noise).
                    url_safe_tools = {
                        "gobuster",
                        "dirsearch",
                        "feroxbuster",
                        "ffuf",
                        "dirb",
                        "httpx",
                        "katana",
                        "hakrawler",
                        "nuclei",
                        "nikto",
                        "sqlmap",
                        "wpscan",
                        "arjun",
                        "x8",
                        "jaeles",
                        "dalfox",
                        "wafw00f",
                        "wfuzz",
                    }

                    # Query HexStrike /health to only run installed tools
                    available = None
                    try:
                        url = f"{settings.hexstrike_url.rstrip('/')}/health"
                        with urllib.request.urlopen(url, timeout=5) as resp:
                            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
                        tools_status = payload.get("tools_status") or {}
                        available = {k for k, v in tools_status.items() if v}
                    except Exception as e:
                        logger.warning(f"Could not read HexStrike /health for tool availability: {e}")

                    if available is not None:
                        dast_tools = [t for t in all_web_tools if t in available and t in url_safe_tools]
                        skipped = [t for t in all_web_tools if t not in dast_tools]
                        if skipped:
                            logger.warning(f"Skipping tools not available or not URL-safe: {skipped}")
                    else:
                        # Fallback: only run URL-safe set to avoid obvious 400/404 failures.
                        dast_tools = [t for t in all_web_tools if t in url_safe_tools]
                    # Always run runtime checks before toolchain
                    results_vulns.extend(_runtime_security_checks(dast_target))
                    for tool in dast_tools:
                        # Override tool per run
                        options["hexstrike"]["dast_tool"] = tool
                        options["hexstrike"]["endpoint"] = None

                        r = await manager.execute_scan(target_path=dast_target, tools=["hexstrike"], options=options)
                        vulns = r.get("vulnerabilities") or []
                        results_vulns.extend(vulns)
                        if r.get("errors"):
                            # namespace by tool to avoid overwriting
                            for k, v in r["errors"].items():
                                errors[f"{tool}:{k}"] = v
                else:
                    if args.dast_tool == "runtime":
                        results_vulns.extend(_runtime_security_checks(dast_target))
                    else:
                        r = await manager.execute_scan(target_path=dast_target, tools=["hexstrike"], options=options)
                        vulns = r.get("vulnerabilities") or []
                        results_vulns.extend(vulns)
                        if r.get("errors"):
                            errors.update(r["errors"])

            await _merge_into_summary(results_vulns)
            status = "completed" if not errors else "completed_with_errors"

            await manager.save_to_db(
                db,
                scan_id=scan_id,
                target_path=target_path,
                tools=tools,
                options=options,  # keep full options for audit
                vulnerabilities=results_vulns,
                status=status,
            )
            if args.llm_explain:
                llm_results = await _run_llm_explanations(db, scan_id, limit=args.llm_max_findings)
        except Exception as e:
            logger.error(str(e))
            try:
                await db.rollback()
            except Exception:
                pass
            raise

    logger.info(f"Scan complete: {scan_id}")
    logger.info(f"Total findings: {len(results_vulns)}")
    logger.info(f"Summary: {summary}")
    if errors:
        logger.warning(f"Errors: {errors}")

    if results_vulns:
        print("\nFindings:")
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        def _sev_key(v: dict) -> int:
            return severity_order.get(str(v.get("severity", "INFO")).upper(), 99)

        # Build lookup from title -> LLM result for display
        llm_by_title = {r["title"]: r for r in llm_results}

        for v in sorted(results_vulns, key=lambda x: (_sev_key(x), x.get("source", ""), x.get("title", ""))):
            loc = v.get("location") or {}
            location_text = ""
            if loc.get("file_path"):
                location_text = f"{loc.get('file_path')}:{loc.get('line')}"
            elif loc.get("url"):
                location_text = str(loc.get("url"))
            elif loc.get("endpoint"):
                location_text = str(loc.get("endpoint"))

            title = v.get("title") or "Finding"
            severity = str(v.get("severity") or "INFO").upper()
            source = v.get("source") or "unknown"
            suffix = f" @ {location_text}" if location_text else ""
            print(f"- [{severity}] {source}: {title}{suffix}")

            if title in llm_by_title:
                ai = llm_by_title[title]
                if ai.get("explanation"):
                    print(f"  [Explanation] {ai['explanation']}")
                if ai.get("fix"):
                    print(f"  [Fix] {ai['fix']}")

    return 0


def main() -> int:
    """
    Entry point for the CLI. Parses arguments and runs the async scan workflow.

    Returns:
        int: Exit code passed to sys.exit() (0 = success, non-zero = error).
    """
    parser = build_parser()
    args = parser.parse_args()
    return asyncio.run(run_cli(args))


async def _ensure_hexstrike_running(hexstrike_path_arg: str, hexstrike_port_arg: int) -> bool:
    """
    Start the HexStrike DAST server if it is not already running.

    First checks whether HexStrike is already accepting requests at the configured
    URL. If not, attempts to start it as a background subprocess from the HexStrike
    repo directory. Waits up to 15 seconds for the server to become ready.

    Args:
        hexstrike_path_arg: Override path to the hexstrike-ai directory (or None to
                            use the HEXSTRIKE_PATH environment variable / default).
        hexstrike_port_arg: Override port number (or None to use the port from
                            HEXSTRIKE_URL).

    Returns:
        bool: True if HexStrike is running and healthy, False if it could not be started.
    """
    parsed = urlparse(settings.hexstrike_url)
    host = parsed.hostname or "127.0.0.1"
    port = hexstrike_port_arg or (parsed.port or 4444)

    health_url = f"http://{host}:{port}/health"
    if _hexstrike_health_ok(health_url):
        logger.info(f"HexStrike already running at {health_url}")
        return True

    hexstrike_path = hexstrike_path_arg or settings.hexstrike_path
    if not hexstrike_path:
        logger.error("HexStrike path not set. Use --hexstrike-path or HEXSTRIKE_PATH.")
        return False

    # If a relative path was provided, resolve it relative to this file.
    if not os.path.isabs(hexstrike_path):
        here = Path(__file__).resolve().parent
        hexstrike_path = str((here / hexstrike_path).resolve())

    if not os.path.exists(hexstrike_path):
        # Try default location next to this repo.
        fallback = Path(__file__).resolve().parent.parent / "hexstrike-ai"
        if fallback.exists():
            hexstrike_path = str(fallback.resolve())
        else:
            logger.error(f"HexStrike path not found: {hexstrike_path}")
            return False

    server_py = os.path.join(hexstrike_path, "hexstrike_server.py")
    if not os.path.exists(server_py):
        logger.error(f"HexStrike server not found: {server_py}")
        return False

    venv_py = os.path.join(hexstrike_path, "venv", "bin", "python3")
    python_bin = venv_py if os.path.exists(venv_py) else "python3"

    logger.info(f"Starting HexStrike server on {host}:{port}...")
    try:
        log_path = os.path.join(Path(__file__).resolve().parent, "hexstrike_startup.log")
        log_file = open(log_path, "a", encoding="utf-8")
        env = dict(os.environ)
        env["HEXSTRIKE_PORT"] = str(port)
        env["HEXSTRIKE_HOST"] = host
        subprocess.Popen(
            [python_bin, server_py, "--port", str(port)],
            cwd=hexstrike_path,
            stdout=log_file,
            stderr=log_file,
            env=env,
        )
    except Exception as e:
        logger.error(f"Failed to start HexStrike: {e}")
        return False

    # wait for readiness
    for _ in range(15):
        if _hexstrike_health_ok(health_url):
            logger.info(f"HexStrike running at {health_url}")
            return True
        time.sleep(1)
    # If port is already in use, it may already be running but health not ready yet.
    if _port_open(host, port):
        logger.warning(f"HexStrike port {port} is open but /health not ready yet. Continuing anyway.")
        return True
    return False


def _hexstrike_health_ok(url: str) -> bool:
    """Return True if HexStrike's /health endpoint responds with HTTP 200."""
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def _port_open(host: str, port: int) -> bool:
    """Return True if a TCP connection can be established to the given host:port."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except Exception:
        return False


async def _run_llm_explanations(db: AsyncSessionLocal, scan_id: str, limit: int = 10) -> List[dict]:
    """
    Generate LLM explanations and fix suggestions for the highest-severity findings.

    Retrieves findings for the given scan from the database, sorts them by severity
    (CRITICAL first), selects the top N, and queries the local DeepSeek model via
    Ollama for each one. Stores the results as AIExplanation and FixSuggestion
    records in the database.

    Only the top N findings are sent to the LLM to keep response time reasonable.
    CRITICAL and HIGH findings are processed first as they represent the greatest risk.

    Args:
        db: Active async database session.
        scan_id: Public UUID of the scan to process (e.g., "scan_abc123...").
        limit: Maximum number of findings to explain (default: 10).

    Returns:
        List[dict]: One dict per processed finding with keys:
                    - title (str): Finding title
                    - explanation (str): LLM-generated explanation
                    - fix (str): LLM-generated remediation advice
    """
    scan = await get_scan_by_scan_id(db, scan_id)
    if not scan:
        logger.warning(f"No scan found for scan_id={scan_id} when running LLM explanations.")
        return []

    findings = await get_findings_for_scan(db, scan)
    if not findings:
        logger.info(f"No findings to explain for scan_id={scan_id}.")
        return []

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def _rk(f) -> int:
        return sev_rank.get((f.severity or "INFO").upper(), 99)

    selected = sorted(findings, key=_rk)[: max(1, limit)]
    logger.info(f"Running DeepSeek explanations for {len(selected)} findings (scan_id={scan_id})")

    results: List[dict] = []
    for f in selected:
        finding_dict = {
            "title": f.title,
            "severity": f.severity,
            "source": f.source,
            "description": f.description,
            "location": f.location or {},
            "metadata": f.meta or {},
        }
        res = generate_explanation_and_fix(finding_dict)
        await create_ai_explanation(db, finding=f, explanation=res.get("explanation", ""))
        if res.get("fix"):
            await create_fix_suggestion(db, finding=f, suggestion=res["fix"])
        results.append({"title": f.title, "explanation": res.get("explanation", ""), "fix": res.get("fix", "")})

    await db.commit()
    return results

if __name__ == "__main__":
    raise SystemExit(main())
