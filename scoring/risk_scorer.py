"""
scoring/risk_scorer.py
=======================
Composite risk scoring for normalised vulnerability findings.

Implements the three-layer prioritisation model required by FR8 (§3.1.2):
  Layer 1 — OWASP Top 10:2025 category assignment (vulnerability taxonomy)
  Layer 2 — CVSS v4.0-inspired severity scoring (impact assessment)
  Layer 3 — Evidence confidence weighting (contextual modifier)

Formula (Code Listing 4.7):
  composite_score = round(min(base * owasp_w * conf_w, 10.0), 1)

Where:
  base    — BASE_SCORE[finding.severity]     (Table 4.6)
  owasp_w — OWASP_WEIGHT[finding.owasp_category] (category modifier)
  conf_w  — finding.confidence               (adapter-supplied, 0.0–1.0)

The composite score and its rationale are stored in the risk_scores table (Table 4.4).
Three-component column persistence (individual base/owasp/conf columns) is identified
as a planned enhancement to fully satisfy NFR7 (Transparency).

Reference: Wunder et al. (2024) demonstrated that 68% of CVSS-trained analysts assign
different severity ratings for identical vulnerabilities — reinforcing the need for
contextual modifiers that adjust raw severity with evidence quality.
"""

from __future__ import annotations

from typing import Any, Dict, List

from loguru import logger


# ------------------------------------------------------------------
# Layer 2: CVSS-inspired base scores by severity (Table 4.6)
# ------------------------------------------------------------------

BASE_SCORE: Dict[str, float] = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.0,
    "info":     0.0,
}


# ------------------------------------------------------------------
# Layer 1: OWASP Top 10:2025 category modifiers
# ------------------------------------------------------------------
# Weights > 1.0 amplify the base score; < 1.0 dampen it.
# Unlisted categories fall back to "other" (0.95 — slight dampening for
# categories with lower average real-world exploitability).

OWASP_WEIGHT: Dict[str, float] = {
    "A01:2025": 1.10,   # Broken Access Control — #1 on OWASP list
    "A02:2025": 1.10,   # Cryptographic Failures — credential/data breach risk
    "A03:2025": 1.05,   # Injection — SQLi, command injection, etc.
    "A05:2025": 1.05,   # Security Misconfiguration — common, often trivial to exploit
    "A06:2025": 1.00,   # Vulnerable and Outdated Components — supply chain risk
    "other":    0.95,   # Uncategorised / unknown category
}


# ------------------------------------------------------------------
# Layer 1b: CWE-level modifiers (applied after OWASP weight)
# ------------------------------------------------------------------
# OWASP categories are broad; CWEs are specific vulnerability classes.
# This layer fine-tunes the score within a category: for example,
# CWE-89 (SQLi) within A03:Injection is more consistently exploitable
# than CWE-943 (NoSQL Injection), which has a much higher FP rate in
# Semgrep scans because rules match broad object-injection shapes.
#
# Weights are deliberately kept in a narrow band (0.85–1.15) so that
# a single CWE modifier cannot dominate the score — it nudges rank
# rather than overriding the base severity.
#
# These weights are derived from CWE exploitability data and known rule
# precision characteristics, not from any specific target application.

CWE_WEIGHT: Dict[str, float] = {
    # Direct, high-frequency exploitation paths
    "CWE-89":   1.12,  # SQL Injection — canonical, consistently exploitable
    "CWE-798":  1.15,  # Hardcoded Credentials — immediate account/system exposure
    "CWE-22":   1.08,  # Path Traversal — often directly exploitable via request
    "CWE-502":  1.10,  # Deserialization — RCE risk, consistently critical
    "CWE-94":   1.08,  # Code Injection (eval/exec) — direct RCE path
    "CWE-78":   1.10,  # OS Command Injection — RCE
    "CWE-306":  1.05,  # Missing Authentication for Critical Function
    # Context-dependent exploitation paths
    "CWE-79":   1.00,  # XSS — impact depends on context (reflected vs stored vs DOM)
    "CWE-601":  0.92,  # Open Redirect — low direct impact; rule overlap common
    "CWE-327":  0.92,  # Weak Cryptographic Algorithm — rarely directly exploitable
    "CWE-319":  0.90,  # Cleartext Transmission — depends on network position
    # Broad/generic patterns with elevated FP rates
    "CWE-943":  0.85,  # NoSQL Injection — Semgrep rules match non-Mongo patterns
    "CWE-915":  0.88,  # Mass Assignment — FP rate high with ORM-heavy codebases
}


def compute_composite_score(finding: Dict[str, Any]) -> float:
    """
    Four-layer scoring: severity × OWASP modifier × CWE modifier × confidence.

    FR8: OWASP taxonomy (layer 1) + CWE specificity (layer 1b) +
    CVSS-inspired severity (layer 2) + evidence confidence (layer 3).

    The CWE modifier is a narrow-band nudge (0.85–1.15) applied after the OWASP
    weight. It distinguishes vulnerability classes within the same OWASP category
    that have meaningfully different real-world exploitability or rule precision.
    For example, CWE-89 (SQL Injection) is consistently exploitable; CWE-943
    (NoSQL Injection) has a high SAST false-positive rate due to broad rule patterns.

    Args:
        finding: Normalised finding dict with at least 'severity'. Optionally
                 includes 'owasp_category' (e.g. "A03:2025 - Injection"),
                 'cwe_id' (e.g. "CWE-89"), and 'confidence' (float 0.0–1.0).

    Returns:
        float: Composite score in [0.0, 10.0], rounded to one decimal place.
    """
    severity = (finding.get("severity") or "info").lower().strip()
    base = BASE_SCORE.get(severity, 0.0)

    owasp_raw = (finding.get("owasp_category") or "").strip()
    owasp_key = _extract_owasp_key(owasp_raw)
    owasp_w = OWASP_WEIGHT.get(owasp_key, OWASP_WEIGHT["other"])

    # CWE modifier: extract the "CWE-NNN" prefix and look up the weight.
    # Falls back to 1.0 (neutral) when the CWE is unknown or absent so that
    # findings without CWE metadata are not unfairly penalised.
    cwe_raw = (finding.get("cwe_id") or "").strip().split(":")[0].upper()
    cwe_w = CWE_WEIGHT.get(cwe_raw, 1.0)

    conf_w = finding.get("confidence")
    if conf_w is None:
        conf_w = 0.5  # default when adapter does not supply confidence
    conf_w = max(0.0, min(1.0, float(conf_w)))

    score = round(min(base * owasp_w * cwe_w * conf_w, 10.0), 1)

    logger.debug(
        f"Risk score for '{finding.get('title', '?')}': "
        f"base={base} × owasp_w={owasp_w} × cwe_w={cwe_w} × conf={conf_w:.2f} = {score}"
    )
    return score


def score_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Annotate each finding in the list with a 'risk_score' field.

    Iterates over all findings, calls compute_composite_score() for each, and
    stores the result under 'risk_score'. Returns the same list so callers can
    use this in a pipeline without capturing the return value.

    Args:
        findings: List of normalised finding dicts.

    Returns:
        The same list, with 'risk_score' populated on each entry.
    """
    for f in findings:
        f["risk_score"] = compute_composite_score(f)
    return findings


# ------------------------------------------------------------------
# Helper
# ------------------------------------------------------------------

def _extract_owasp_key(owasp_category: str) -> str:
    """
    Extract the short OWASP category key from a full category string.

    Examples:
        "A03:2025 - Injection"  → "A03:2025"
        "A03:2025"              → "A03:2025"
        ""                      → ""
    """
    if not owasp_category:
        return ""
    return owasp_category.split()[0].rstrip("-").strip()
