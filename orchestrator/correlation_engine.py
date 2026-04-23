"""
orchestrator/correlation_engine.py
====================================
Cross-tool vulnerability correlation for the security scanning pipeline.

FR5 (§3.1.2) requires the system to correlate SAST and DAST results when there
is significant overlap regarding vulnerability type, affected endpoint, or file path.
This is semantically distinct from FR6 (deduplication), which removes identical
findings from the same tool.

Correlation is the design problem of deciding when a Semgrep SQL injection finding
in auth.py and a SQLMap finding on /api/auth/login constitute evidence for the same
underlying vulnerability. Without correlation, the system's value proposition —
that integrating SAST and DAST produces better evidence than either alone — cannot
be substantiated.

Matching logic (Table 4.3 — two-tier):
  Tier 1 — CWE match (mandatory prerequisite):
    sast.cwe_id == dast.cwe_id (neither null)
  Tier 2 — at least one secondary criterion must hold:
    - Endpoint–Path Overlap: module name derived from SAST file path appears in
      DAST URL path segment (e.g. auth in /api/auth/login matches auth.py)
    - Parameter Match: DAST finding's parameter name appears in SAST finding's
      affected code description

The composite confidence is the mean of the two source confidences, boosted by
+15% per corroborating source (evidence_boost = 1.15). This directly addresses
trust calibration concerns — a finding corroborated by both SAST and DAST carries
higher confidence than either source alone (Parasuraman and Riley, 1997).

Reference: Code Listing 4.4 (orchestrator/correlation_engine.py)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Any, Dict, List, Set

from loguru import logger


@dataclass
class CorrelatedFinding:
    """
    A primary finding bundled with its corroborating evidence.

    Attributes:
        primary:              The lead finding dict (highest confidence or first seen).
        supporting_evidence:  All findings (including primary) grouped under this record.
        evidence_count:       Total number of evidence sources in this group.
        composite_confidence: Boosted confidence derived from all supporting evidence.
    """
    primary: Dict[str, Any]
    supporting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    evidence_count: int = 1
    composite_confidence: float = 0.0


class CorrelationEngine:
    """
    Groups SAST and DAST findings that describe the same underlying vulnerability
    and computes a boosted composite confidence when cross-tool evidence is found.

    Usage::

        engine = CorrelationEngine()
        groups = engine.correlate(merged_findings)
    """

    def correlate(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[CorrelatedFinding]:
        """
        FR5: Correlate SAST and DAST evidence packs into unified groups.

        Deduplication (FR6) must run first.

        Separates findings into SAST (source == "SAST") and DAST (source == "DAST")
        buckets, then pairs each SAST finding against each DAST finding. When
        _matches() returns True, the pair is merged into a CorrelatedFinding with
        a boosted composite_confidence. Unmatched findings are returned as
        single-source CorrelatedFinding objects preserving completeness.

        Args:
            findings: Deduplicated list of normalised finding dicts.

        Returns:
            List[CorrelatedFinding]: One entry per primary finding.
        """
        if not findings:
            return []

        sast = [f for f in findings if (f.get("source") or "").upper() == "SAST"]
        dast = [f for f in findings if (f.get("source") or "").upper() == "DAST"]

        matched_ids: Set[str] = set()
        correlated: List[CorrelatedFinding] = []

        for s in sast:
            for d in dast:
                if self._matches(s, d):
                    primary = max([s, d], key=lambda f: f.get("confidence") or 0.0)
                    evidence_boost = 1.0 + (0.15 * 1)  # +15% per corroborating source
                    composite_conf = round(
                        min(1.0, mean([
                            s.get("confidence") or 0.5,
                            d.get("confidence") or 0.5,
                        ]) * evidence_boost),
                        2,
                    )
                    correlated.append(CorrelatedFinding(
                        primary=primary,
                        supporting_evidence=[s, d],
                        evidence_count=2,
                        composite_confidence=composite_conf,
                    ))
                    matched_ids.update([
                        s.get("id") or id(s),
                        d.get("id") or id(d),
                    ])
                    logger.debug(
                        f"Correlated '{s.get('title')}' (SAST) ↔ '{d.get('title')}' (DAST) "
                        f"— composite_confidence={composite_conf}"
                    )

        # Findings that did not correlate are returned as single-source evidence packs.
        unmatched = [f for f in findings if (f.get("id") or id(f)) not in matched_ids]
        for f in unmatched:
            correlated.append(CorrelatedFinding(
                primary=f,
                supporting_evidence=[f],
                evidence_count=1,
                composite_confidence=round(f.get("confidence") or 0.5, 2),
            ))

        cross_tool_count = sum(1 for g in correlated if g.evidence_count > 1)
        if cross_tool_count:
            logger.info(
                f"Correlation complete: {cross_tool_count} cross-tool group(s) found "
                f"among {len(findings)} finding(s)."
            )

        return correlated

    def _matches(
        self,
        sast: Dict[str, Any],
        dast: Dict[str, Any],
    ) -> bool:
        """
        CWE match mandatory; at least one secondary criterion required.

        Two-tier matching (Table 4.3):
          Tier 1 — CWE prerequisite gate:
            Both findings must carry a non-empty cwe_id and they must be equal.
          Tier 2 — at least one secondary must hold:
            a) Endpoint–Path Overlap: module name from SAST file_path appears in
               DAST URL path (e.g. "auth" in "/api/auth/login" matches "auth.py")
            b) Parameter Match: DAST parameter name appears in SAST description

        Args:
            sast: Normalised SAST finding dict.
            dast: Normalised DAST finding dict.

        Returns:
            bool: True if the findings should be correlated.
        """
        # --- Tier 1: CWE mandatory gate ---
        if not sast.get("cwe_id") or sast.get("cwe_id") != dast.get("cwe_id"):
            return False

        sast_loc = sast.get("location") or {}
        dast_loc = dast.get("location") or {}

        # (a) Endpoint–path overlap: strip extension from SAST filename, check DAST URL
        file_path = sast_loc.get("file_path") or ""
        module = file_path.split("/")[-1].replace(".py", "").replace(".js", "").replace(".ts", "")
        dast_url = (dast_loc.get("url") or dast_loc.get("endpoint") or "").lower()
        path_overlap = bool(module and module.lower() in dast_url)

        # (b) Parameter match: DAST parameter name appears in SAST description
        dast_param = (dast_loc.get("parameter") or "").strip()
        sast_desc = (sast.get("description") or "").lower()
        param_match = bool(dast_param and dast_param.lower() in sast_desc)

        return path_overlap or param_match
