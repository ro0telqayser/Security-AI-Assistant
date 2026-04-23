"""
adapters/hexstrike_adapter.py
==============================
HexStrike adapter — communicates with the HexStrike DAST server and normalises results.

HexStrike is a separate Python server that wraps a collection of popular DAST (Dynamic
Application Security Testing) tools behind a unified REST API. This adapter sends HTTP
POST requests to HexStrike endpoints and converts the raw tool output into the project's
common finding schema.

Supported tools (via HexStrike):
  - nuclei       — Template-based vulnerability scanner (best structured output)
  - sqlmap       — SQL injection detection and exploitation
  - nikto        — Web server misconfiguration / vulnerability scanner
  - ffuf         — Directory and endpoint fuzzing
  - dalfox       — XSS (Cross-Site Scripting) scanner (CWE-79)
  - httpx        — HTTP probing and fingerprinting
  - wafw00f      — Web Application Firewall (WAF) fingerprinting
  - gobuster     — Directory and DNS brute-forcing
  - wpscan       — WordPress vulnerability scanner
  - testssl      — TLS/SSL configuration analysis
  ...and many more (see endpoint_map below)

The adapter uses Python's standard urllib library (no third-party HTTP client needed)
and runs the blocking HTTP call in a thread via asyncio.to_thread() to avoid blocking
the async event loop while waiting for long-running tool responses.

Each tool produces output in a different format. The normalize_results() method
handles tool-specific parsing where possible (nuclei, sqlmap, nikto, ffuf, dalfox)
and falls back to storing raw stdout as an INFO finding for tools without a parser.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional

import asyncio
import json
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse
import tempfile
from pathlib import Path
from uuid import uuid4
import re
from loguru import logger

from adapters.adapter_base import SecurityToolAdapter


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _nikto_title(description: str) -> str:
    """Derive a finding-specific title from a Nikto output line.

    Nikto findings must have unique titles for deduplication to work correctly.
    Using the generic string "Nikto finding" for every line causes the deduplicator
    to collapse all findings into one because the key (title, source, location) is
    identical for every entry.

    Priority:
      1. OSVDB-NNN reference → "Nikto: OSVDB-NNN"
      2. CVE-YYYY-NNN reference → "Nikto: CVE-YYYY-NNN"
      3. First clause of description (before first full stop or opening paren),
         truncated to 70 chars → "Nikto: <clause>"
    """
    # OSVDB-NNN
    m = re.match(r'(OSVDB-\d+)', description)
    if m:
        return f"Nikto: {m.group(1)}"
    # CVE
    m = re.match(r'(CVE-\d{4}-\d+)', description)
    if m:
        return f"Nikto: {m.group(1)}"
    # First meaningful clause
    clause = re.split(r'[.(]', description)[0].strip()[:70]
    return f"Nikto: {clause}" if clause else "Nikto finding"


def _httpx_finding(
    url: str,
    status: int,
    title: str,
    tech: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a normalised finding dict for a single httpx probed host."""
    parts = [f"HTTP {status}"]
    if title:
        parts.append(f"title: {title}")
    if tech:
        parts.append(f"tech: {tech}")
    description = f"httpx probed {url} — {' | '.join(parts)}"

    return {
        "id": f"hexstrike:httpx:{uuid4().hex}",
        "title": f"HTTP probe: {url} [{status}]",
        "description": description,
        "severity": "INFO",
        "source": "hexstrike",
        "location": {"url": url},
        "confidence": 0.9,
        "metadata": {"hexstrike": payload, "status": status, "title": title, "tech": tech},
    }


class HexStrikeAdapter(SecurityToolAdapter):
    """
    Adapter for the HexStrike DAST toolchain.

    Communicates with a running HexStrike REST server, submitting scan requests
    and parsing the responses into normalised vulnerability findings.

    HexStrike must be running before any DAST scan is initiated. The CLI handles
    auto-starting it; when using the API directly the server must be started manually
    (see README for instructions).
    """

    def _validate_tool(self) -> bool:
        """
        Check that a HexStrike URL is configured.

        Unlike CLI-based adapters, HexStrike is accessed over HTTP so there is no
        binary to locate. This method simply warns if no URL is set — the actual
        connectivity check happens at scan time.

        Returns:
            bool: Always True (connectivity is verified when a scan is attempted).
        """
        if not self.tool_path:
            logger.warning(
                "HexStrike URL not configured. Set HEXSTRIKE_URL in .env or pass it "
                "via the HEXSTRIKE_URL environment variable."
            )
        return True

    async def scan(
        self,
        target_path: str,
        options: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Submit a DAST scan request to HexStrike and return the raw response.

        Determines the correct HexStrike API endpoint based on the requested tool,
        builds an appropriate payload for that endpoint, and POSTs the request.
        The response is returned as a single-item list so the pipeline can treat it
        the same as other adapters (normalize_results handles the inner parsing).

        The blocking HTTP call is run in a thread using asyncio.to_thread() so the
        async event loop is not blocked during the (potentially long) scan.

        Args:
            target_path: URL or hostname of the web application to scan.
            options: Dict with the following keys:
                - dast_tool (str): Which tool to run (default: "nuclei").
                - endpoint (str): Override the HexStrike API endpoint directly.
                - api_key (str): HexStrike API key, if authentication is enabled.
                - target_override / target_url (str): Alternative target URL.
                - Additional tool-specific options (severity, tags, cookies, etc.)

        Returns:
            List[Dict]: A single-item list containing the raw HexStrike response dict.
                        normalize_results() unpacks and parses the actual findings.

        Raises:
            RuntimeError: If HexStrike is not configured, returns an HTTP error, or
                          the connection is refused.
        """
        options = options or {}

        base_url = (self.tool_path or "").rstrip("/")
        if not base_url:
            raise RuntimeError(
                "HexStrike URL is not configured. Set HEXSTRIKE_URL in your .env file."
            )

        dast_tool = str(options.get("dast_tool") or "nuclei").lower()

        # Map tool names to their HexStrike API endpoints.
        # Each tool in HexStrike has its own endpoint that accepts tool-specific options.
        endpoint = options.get("endpoint") or ""
        if not endpoint:
            endpoint_map = {
                "nuclei":       "/api/tools/nuclei",
                "httpx":        "/api/tools/httpx",
                "wafw00f":      "/api/tools/wafw00f",
                "ffuf":         "/api/tools/ffuf",
                "wpscan":       "/api/tools/wpscan",
                "sqlmap":       "/api/tools/sqlmap",
                "gobuster":     "/api/tools/gobuster",
                "dirsearch":    "/api/tools/dirsearch",
                "feroxbuster":  "/api/tools/feroxbuster",
                "dirb":         "/api/tools/dirb",
                "katana":       "/api/tools/katana",
                "hakrawler":    "/api/tools/hakrawler",
                "gau":          "/api/tools/gau",
                "waybackurls":  "/api/tools/waybackurls",
                "nikto":        "/api/tools/nikto",
                "arjun":        "/api/tools/arjun",
                "paramspider":  "/api/tools/paramspider",
                "x8":           "/api/tools/x8",
                "jaeles":       "/api/tools/jaeles",
                "dalfox":       "/api/tools/dalfox",
                "testssl":      "/api/tools/testssl",
                "sslscan":      "/api/tools/sslscan",
                "sslyze":       "/api/tools/sslyze",
                "anew":         "/api/tools/anew",
                "qsreplace":    "/api/tools/qsreplace",
                "uro":          "/api/tools/uro",
                "whatweb":      "/api/tools/whatweb",
                "jwt-tool":     "/api/tools/jwt-tool",
                "graphql-voyager": "/api/tools/graphql-voyager",
                "wfuzz":        "/api/tools/wfuzz",
                "commix":       "/api/tools/commix",
                "nosqlmap":     "/api/tools/nosqlmap",
                "tplmap":       "/api/tools/tplmap",
            }
            endpoint = endpoint_map.get(dast_tool, f"/api/tools/{dast_tool}")

        api_key = options.get("api_key")

        # Resolve the actual scan target — callers can pass it in several ways.
        target = options.get("target_override") or options.get("target_url") or target_path

        # Ensure the target has a URL scheme so tools like nuclei receive a valid URL.
        if isinstance(target, str) and "://" not in target:
            target = f"http://{target}"

        # Strip internal option keys that should not be forwarded to HexStrike.
        payload_base = {k: v for k, v in options.items() if k not in {"endpoint", "api_key"}}

        # Build the request payload. Different tools expect slightly different field names.
        if endpoint in {"/api/tools/ffuf", "/api/tools/sqlmap", "/api/tools/wpscan"}:
            payload = {"url": target, "target": target, **payload_base}
        elif endpoint == "/api/tools/httpx":
            # The httpx HexStrike endpoint expects a file containing a list of targets
            # rather than a bare URL. Write the target to a temp file.
            tmpfile = Path(tempfile.gettempdir()) / f"hexstrike_httpx_{int(time.time())}.txt"
            tmpfile.write_text(str(target) + "\n", encoding="utf-8")
            payload = {"target": str(tmpfile), **payload_base}
        else:
            # nuclei, wafw00f, and most other tools accept a "target" field.
            payload = {"target": target, "url": target, **payload_base}

        # Nuclei defaults: ensure JSON output is requested for structured parsing.
        if endpoint == "/api/tools/nuclei":
            payload.setdefault("severity", "critical,high,medium,low,info")
            additional_args = str(payload.get("additional_args") or "").strip()
            # Ensure JSON flag is present so we can parse structured output.
            additional_args = additional_args.replace("-jsonl", "").strip()
            if "-json" not in additional_args:
                additional_args = (additional_args + " -json").strip()
            if "-silent" not in additional_args:
                additional_args = (additional_args + " -silent").strip()
            payload["additional_args"] = additional_args

        def _post() -> Dict[str, Any]:
            """Blocking HTTP POST — run in a thread to avoid blocking the event loop."""
            url = f"{base_url}{endpoint}"
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["X-API-Key"] = str(api_key)

            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            # 600-second timeout to allow slow tools (e.g., full Nuclei scans) to complete.
            with urllib.request.urlopen(req, timeout=600) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return json.loads(body) if body.strip() else {}

        logger.info(f"HexStrike DAST scan: target={target}, tool={dast_tool}")

        # Run the blocking HTTP call in a thread pool so the async event loop is free.
        try:
            result = await asyncio.to_thread(_post)
        except AttributeError:
            # asyncio.to_thread is Python 3.9+; fall back for older environments.
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _post)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HexStrike returned HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Could not connect to HexStrike at {base_url}: {e.reason}"
            ) from e

        # Attach context so normalize_results() knows which tool produced this output
        # without needing to re-parse the endpoint URL.
        if isinstance(result, dict):
            result["_hexstrike_endpoint"] = endpoint
            result["_dast_tool"] = dast_tool
            result["_dast_target"] = target

        return [result] if result else []

    def normalize_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse HexStrike tool output and convert it to the common finding schema.

        Each DAST tool produces output in a different format. Parsers are implemented
        for the most important tools; the fallback path handles the rest.

        Parsers implemented:
          Nuclei     — JSONL, one JSON object per line. Richest structured output.
          SQLMap     — Text output; looks for injection-confirmed phrases.
          FFUF       — Text output; parses "STATUS  NL  NW  NC  URL" lines.
          Nikto      — Text output; parses "+ <finding>" lines with unique titles.
          Dalfox     — Text output; lines containing "VULN" or "POC".
          Wafw00f    — Text output; detects WAF name from "is behind ... WAF" pattern.
          Httpx      — Text/JSON output; parses host/status/title/tech per line.
          Katana     — Text output; one discovered URL per line.
          Hakrawler  — Text output; one discovered URL per line.
          Arjun      — Text output; "[+] Found: <param>" lines.
          Gobuster   — Text output; parses "/<path>  (Status: NNN)" lines.
          Feroxbuster — Text output; parses status/size/word/line/url lines.
          Dirsearch  — Text output; parses "  NNN  SIZE  PATH" lines.

        Fallback behaviour (tools without a dedicated parser):
          - Tool failed AND produced no stdout (binary not found, wordlist missing,
            etc.) → no finding is created. Failures are logged, not fabricated.
          - Tool ran with output that couldn't be parsed → one LOW/INFO finding
            is created containing the raw stdout so output is not silently discarded.

        Args:
            raw_results: List returned by scan() — typically a single-item list
                         containing the HexStrike JSON response.

        Returns:
            List[Dict]: Normalised findings in the project's common schema.
        """
        logger.info(f"Normalising {len(raw_results)} HexStrike tool response(s)")

        normalized: List[Dict[str, Any]] = []
        now = int(time.time())

        for idx, payload in enumerate(raw_results):
            stdout = payload.get("stdout") or ""
            tool = str(payload.get("_dast_tool") or "hexstrike").lower()
            target = payload.get("_dast_target") or ""
            return_code = payload.get("return_code")
            tool_success = payload.get("success", True)

            findings = self._parse_tool_output(
                tool=tool,
                stdout=stdout,
                target=target,
                payload=payload,
                return_code=return_code,
                tool_success=tool_success,
                now=now,
                idx=idx,
            )
            normalized.extend(findings)

        return normalized

    # ------------------------------------------------------------------
    # Per-tool parsers
    # ------------------------------------------------------------------

    def _parse_tool_output(
        self,
        *,
        tool: str,
        stdout: str,
        target: str,
        payload: Dict[str, Any],
        return_code: Optional[int],
        tool_success: bool,
        now: int,
        idx: int,
    ) -> List[Dict[str, Any]]:
        """Dispatch to the correct parser for each tool and return findings."""

        parsers = {
            "nuclei":      self._parse_nuclei,
            "sqlmap":      self._parse_sqlmap,
            "ffuf":        self._parse_ffuf,
            "nikto":       self._parse_nikto,
            "dalfox":      self._parse_dalfox,
            "wafw00f":     self._parse_wafw00f,
            "httpx":       self._parse_httpx,
            "katana":      self._parse_url_list,
            "hakrawler":   self._parse_url_list,
            "arjun":       self._parse_arjun,
            "gobuster":    self._parse_gobuster,
            "feroxbuster": self._parse_feroxbuster,
            "dirsearch":   self._parse_dirsearch,
        }

        parser = parsers.get(tool)
        if parser:
            # Pass 'tool' as a kwarg so parsers like _parse_url_list can use
            # the tool name in finding titles without needing a separate method
            # per crawler tool.
            results = parser(
                stdout=stdout, target=target, payload=payload,
                now=now, idx=idx, tool=tool,
            )
            if results is not None:
                return results

        # Fallback for tools without a dedicated parser.
        return self._fallback(
            tool=tool,
            stdout=stdout,
            target=target,
            payload=payload,
            return_code=return_code,
            tool_success=tool_success,
        )

    def _parse_nuclei(self, *, stdout, target, payload, now, idx, **_) -> Optional[List]:
        """Parse Nuclei JSONL output — one JSON object per line."""
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue

            info = item.get("info") or {}
            severity = str(info.get("severity") or "info").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                severity = "INFO"

            template_id = item.get("template-id") or item.get("templateID") or "nuclei"
            name = info.get("name") or template_id
            matched = item.get("matched-at") or item.get("host") or ""
            parsed = urlparse(matched) if isinstance(matched, str) else None
            matched_endpoint = parsed.path if parsed and parsed.path else None

            cwe_id = None
            classification = info.get("classification") or {}
            cwe_ids = classification.get("cwe-id") or []
            if isinstance(cwe_ids, list) and cwe_ids:
                cwe_id = str(cwe_ids[0])
            elif isinstance(cwe_ids, str) and cwe_ids:
                cwe_id = cwe_ids

            findings.append({
                "id": f"hexstrike:nuclei:{template_id}:{matched}:{now}:{idx}",
                "title": str(name),
                "description": f"Nuclei template '{template_id}' matched on {matched}",
                "severity": severity,
                "source": "hexstrike",
                "location": {"url": matched, "endpoint": matched_endpoint},
                "cwe_id": cwe_id,
                "confidence": 0.8,
                "metadata": {"hexstrike": payload, "nuclei": item},
            })

        return findings if findings else None

    def _parse_sqlmap(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse SQLMap text output — detect injection-confirmed phrases."""
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        indicators = [
            "back-end dbms",
            "sql injection",
            "identified the following injection point",
            "the back-end dbms",
        ]
        if not any(i in stdout.lower() for i in indicators):
            return None

        param = None
        for line in stdout.splitlines():
            if line.strip().lower().startswith("parameter:"):
                param = line.split(":", 1)[-1].strip()
                break

        return [{
            "id": f"hexstrike:sqlmap:{uuid4().hex}",
            "title": "SQL Injection (sqlmap)",
            "description": (
                "SQLMap confirmed at least one injectable parameter. "
                "SQL injection allows an attacker to read, modify, or delete "
                "database content and may escalate to OS-level access."
            ),
            "severity": "HIGH",
            "source": "hexstrike",
            "location": {"url": target, "parameter": param},
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2025 - Injection",
            "confidence": 0.85,
            "metadata": {"hexstrike": payload, "sqlmap_stdout": stdout[:8000]},
        }]

    def _parse_ffuf(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse FFUF text output — 'STATUS  NL  NW  NC  URL' lines."""
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        # Standard FFUF text output: "200      14l       20w      200c  http://host/path"
        pattern = re.compile(
            r"^(?P<status>\d{3})\s+\d+[lL]\s+\d+[wW]\s+\d+[cC]\s+(?P<url>https?://\S+)"
        )
        for line in stdout.splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue
            url = m.group("url")
            status = m.group("status")
            findings.append({
                "id": f"hexstrike:ffuf:{uuid4().hex}",
                "title": f"Exposed endpoint (HTTP {status})",
                "description": f"FFUF discovered accessible path: {url}",
                "severity": "LOW",
                "source": "hexstrike",
                "location": {"url": url},
                "confidence": 0.6,
                "metadata": {"hexstrike": payload},
            })

        return findings if findings else None

    def _parse_nikto(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse Nikto text output — lines beginning with '+ '.

        Each line is a distinct finding. The deduplication key (title, source,
        location) must be unique per finding; using "Nikto finding" as the title
        for every line causes the deduplicator to collapse all findings into one.

        Fix: derive a specific title from OSVDB/CVE references in the line, or
        use the first meaningful clause of the description.
        """
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        skip_patterns = {
            "start time", "target ip", "target hostname", "target port",
            "end time", "1 host(s) tested",
        }

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            description = line[2:].strip()
            desc_lower = description.lower()
            if any(p in desc_lower for p in skip_patterns):
                continue
            if not description:
                continue

            title = _nikto_title(description)

            findings.append({
                "id": f"hexstrike:nikto:{uuid4().hex}",
                "title": title,
                "description": description,
                "severity": "MEDIUM",
                "source": "hexstrike",
                "location": {"url": target},
                "confidence": 0.5,
                "metadata": {"hexstrike": payload},
            })

        return findings if findings else None

    def _parse_dalfox(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse Dalfox output — lines containing VULN or POC indicate confirmed XSS."""
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if "VULN" in line or "POC" in line:
                # Extract the URL from the line if present.
                url_match = re.search(r'https?://\S+', line)
                vuln_url = url_match.group(0) if url_match else target
                findings.append({
                    "id": f"hexstrike:dalfox:{uuid4().hex}",
                    "title": "Cross-Site Scripting / XSS (dalfox)",
                    "description": line,
                    "severity": "MEDIUM",
                    "source": "hexstrike",
                    "location": {"url": vuln_url},
                    "cwe_id": "CWE-79",
                    "owasp_category": "A03:2025 - Injection",
                    "confidence": 0.75,
                    "metadata": {"hexstrike": payload},
                })

        return findings if findings else None

    def _parse_wafw00f(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse wafw00f output — detects WAF presence and name.

        Wafw00f output patterns:
          [+] The site ... is behind <WAF Name> (Vendor) WAF.
          [-] No WAF detected by the fingerprinting technique
          [~] The site ... seems to be behind a WAF ...
        """
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        waf_detected = re.search(
            r'is behind\s+(.+?)\s+(?:\(.+?\)\s+)?WAF', stdout, re.IGNORECASE
        )
        no_waf = re.search(
            r'no waf detected|does not seem to be behind', stdout, re.IGNORECASE
        )

        if waf_detected:
            waf_name = waf_detected.group(1).strip()
            return [{
                "id": f"hexstrike:wafw00f:{uuid4().hex}",
                "title": f"WAF Detected: {waf_name}",
                "description": (
                    f"Web Application Firewall detected: {waf_name}. "
                    "WAF presence may affect exploit reliability and should be noted "
                    "for planning bypass techniques during authorised testing."
                ),
                "severity": "INFO",
                "source": "hexstrike",
                "location": {"url": target},
                "confidence": 0.8,
                "metadata": {"hexstrike": payload, "waf_name": waf_name},
            }]

        if no_waf:
            return [{
                "id": f"hexstrike:wafw00f:{uuid4().hex}",
                "title": "No WAF Detected",
                "description": (
                    "Wafw00f found no Web Application Firewall protecting the target. "
                    "Attack traffic will reach the application directly."
                ),
                "severity": "INFO",
                "source": "hexstrike",
                "location": {"url": target},
                "confidence": 0.7,
                "metadata": {"hexstrike": payload},
            }]

        return None  # output present but pattern unrecognised → fallback

    def _parse_httpx(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse httpx text output — one probed host per line.

        Standard httpx text output:
          http://host:port [STATUS] [Title] [tech,tech2] [IP]
        JSON mode (httpx -json) is parsed if lines start with '{'.
        """
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # JSON mode
            if line.startswith("{"):
                try:
                    item = json.loads(line)
                    url = item.get("url") or item.get("input") or target
                    status = item.get("status-code") or item.get("status") or 0
                    title = item.get("title") or ""
                    tech = ", ".join(item.get("tech") or item.get("technologies") or [])
                    findings.append(_httpx_finding(url, status, title, tech, payload))
                    continue
                except Exception:
                    pass

            # Text mode: http://host [200] [Title] [tech]
            m = re.match(
                r'(?P<url>https?://\S+)\s+\[(?P<status>\d+)\]'
                r'(?:\s+\[(?P<title>[^\]]*)\])?'
                r'(?:\s+\[(?P<tech>[^\]]*)\])?',
                line,
            )
            if m:
                findings.append(_httpx_finding(
                    m.group("url"), int(m.group("status") or 0),
                    m.group("title") or "", m.group("tech") or "", payload
                ))

        return findings if findings else None

    def _parse_url_list(self, *, stdout, target, payload, **kwargs) -> Optional[List]:
        """Parse tools that output one URL per line (katana, hakrawler).

        Consolidates all discovered URLs into a single finding so the result is
        actionable (a list of endpoints to investigate) rather than dozens of
        identical-severity INFO findings that flood the output.
        """
        tool = kwargs.get("tool") or "crawler"
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        urls = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)

        if not urls:
            return None

        return [{
            "id": f"hexstrike:{tool}:{uuid4().hex}",
            "title": f"Crawled endpoints ({tool})",
            "description": (
                f"{tool} discovered {len(urls)} endpoint(s) on {target}. "
                f"First 10: {', '.join(urls[:10])}"
                + (" ..." if len(urls) > 10 else "")
            ),
            "severity": "INFO",
            "source": "hexstrike",
            "location": {"url": target},
            "confidence": 0.9,
            "metadata": {"hexstrike": payload, "discovered_urls": urls},
        }]

    def _parse_arjun(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse Arjun parameter discovery output.

        Arjun output:
          [*] Checking for the following GET parameters:
          [+] Found: id
          [+] Found: search
        """
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        params = []
        for line in stdout.splitlines():
            m = re.match(r'\[\+\]\s+Found:\s+(\S+)', line.strip())
            if m:
                params.append(m.group(1))

        if not params:
            return None

        return [{
            "id": f"hexstrike:arjun:{uuid4().hex}",
            "title": f"Parameters discovered ({len(params)} found)",
            "description": (
                f"Arjun identified {len(params)} HTTP parameter(s) on {target}: "
                f"{', '.join(params)}. "
                "These parameters are candidate injection points for further testing."
            ),
            "severity": "INFO",
            "source": "hexstrike",
            "location": {"url": target},
            "confidence": 0.8,
            "metadata": {"hexstrike": payload, "parameters": params},
        }]

    def _parse_gobuster(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse Gobuster dir output — '/<path>  (Status: NNN)  [...]' lines."""
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        # Gobuster dir: "/admin                (Status: 200) [Size: 1234]"
        pattern = re.compile(
            r'(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)'
        )
        for line in stdout.splitlines():
            m = pattern.search(line)
            if not m:
                continue
            path = m.group("path")
            status = m.group("status")
            url = target.rstrip("/") + path
            findings.append({
                "id": f"hexstrike:gobuster:{uuid4().hex}",
                "title": f"Exposed path (HTTP {status}): {path}",
                "description": f"Gobuster found accessible path {url} (HTTP {status})",
                "severity": "LOW",
                "source": "hexstrike",
                "location": {"url": url, "endpoint": path},
                "confidence": 0.65,
                "metadata": {"hexstrike": payload},
            })

        return findings if findings else None

    def _parse_feroxbuster(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse feroxbuster output — 'STATUS  SIZE  WORDS  LINES  URL' lines."""
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        # feroxbuster: "200      14l       20w      200c  http://host/path"
        pattern = re.compile(
            r'^(?P<status>\d{3})\s+\d+\w\s+\d+\w\s+\d+\w\s+(?P<url>https?://\S+)'
        )
        for line in stdout.splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue
            url = m.group("url")
            status = m.group("status")
            parsed = urlparse(url)
            findings.append({
                "id": f"hexstrike:feroxbuster:{uuid4().hex}",
                "title": f"Exposed path (HTTP {status}): {parsed.path or '/'}",
                "description": f"Feroxbuster discovered accessible URL: {url}",
                "severity": "LOW",
                "source": "hexstrike",
                "location": {"url": url, "endpoint": parsed.path or "/"},
                "confidence": 0.65,
                "metadata": {"hexstrike": payload},
            })

        return findings if findings else None

    def _parse_dirsearch(self, *, stdout, target, payload, **_) -> Optional[List]:
        """Parse dirsearch output — '  STATUS  SIZE  PATH' lines."""
        if not isinstance(stdout, str) or not stdout.strip():
            return None

        findings = []
        # dirsearch text: "  200     1.2KB  /admin/login"
        pattern = re.compile(
            r'^\s*(?P<status>\d{3})\s+[\d.]+\w*\s+(?P<path>/\S*)'
        )
        for line in stdout.splitlines():
            m = pattern.match(line)
            if not m:
                continue
            path = m.group("path")
            status = m.group("status")
            url = target.rstrip("/") + path
            findings.append({
                "id": f"hexstrike:dirsearch:{uuid4().hex}",
                "title": f"Exposed path (HTTP {status}): {path}",
                "description": f"Dirsearch found accessible path: {url} (HTTP {status})",
                "severity": "LOW",
                "source": "hexstrike",
                "location": {"url": url, "endpoint": path},
                "confidence": 0.65,
                "metadata": {"hexstrike": payload},
            })

        return findings if findings else None

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def _fallback(
        self,
        *,
        tool: str,
        stdout: str,
        target: str,
        payload: Dict[str, Any],
        return_code: Optional[int],
        tool_success: bool,
    ) -> List[Dict[str, Any]]:
        """Handle tools without a dedicated parser.

        Two distinct cases require different treatment:

        1. Tool failed and produced no output (binary not found, wordlist path
           wrong, invocation error, etc.) — `return_code != 0` and `stdout` is
           empty. Creating a synthetic finding here would pollute the result set
           with fabricated data. Instead: log the failure and return nothing.

        2. Tool ran and produced output that couldn't be parsed — stdout is
           present but no parser matched. The raw output is preserved as a single
           LOW/INFO finding so it is not silently discarded.
        """
        has_output = isinstance(stdout, str) and bool(stdout.strip())
        failed_silently = (not tool_success or return_code not in (None, 0)) and not has_output

        if failed_silently:
            # Don't fabricate a finding for a tool that never ran properly.
            logger.warning(
                f"HexStrike tool '{tool}' failed without output "
                f"(return_code={return_code}, success={tool_success}). "
                "No finding created — check tool installation and invocation config."
            )
            return []

        # Tool ran (or we can't tell) and produced some stdout.
        tool_severity_map = {
            # Exploitation tools — unparsed output still warrants MEDIUM
            "nikto": "MEDIUM", "dalfox": "MEDIUM", "wpscan": "MEDIUM",
            "jaeles": "MEDIUM", "commix": "MEDIUM", "nosqlmap": "MEDIUM",
            "tplmap": "MEDIUM", "sqlmap": "MEDIUM",
            # Recon / discovery — LOW
            "httpx": "LOW", "wafw00f": "LOW", "whatweb": "LOW",
            "katana": "LOW", "hakrawler": "LOW", "gobuster": "LOW",
            "dirsearch": "LOW", "feroxbuster": "LOW", "ffuf": "LOW",
            "dirb": "LOW", "arjun": "LOW", "x8": "LOW",
            "paramspider": "LOW", "gau": "LOW", "waybackurls": "LOW",
        }

        severity = tool_severity_map.get(tool, "INFO") if has_output else "INFO"

        return [{
            "id": f"hexstrike:{tool}:{uuid4().hex}",
            "title": f"{tool} output (unparsed)",
            "description": (
                f"Raw output from '{tool}' could not be parsed into structured findings. "
                "Review the metadata.hexstrike field for the full stdout."
            ) if has_output else (
                f"'{tool}' ran but produced no output. "
                "The target may have no findings for this tool, "
                "or the tool may need additional configuration (wordlist, flags, etc.)."
            ),
            "severity": severity,
            "source": "hexstrike",
            "location": {"url": target} if target else {},
            "confidence": 0.3,
            "metadata": {"hexstrike": payload},
        }]

    @property
    def tool_name(self) -> str:
        """Return the tool identifier used in findings and logs."""
        return "hexstrike"

    @property
    def version(self) -> str:
        """Return the HexStrike version string."""
        return "0.0.0"
