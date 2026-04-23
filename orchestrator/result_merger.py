"""
orchestrator/result_merger.py
==============================
Deduplicates vulnerability findings from multiple security tools.

When running SAST and DAST together, or running multiple DAST tools against the
same target, the same vulnerability can be reported multiple times. Two distinct
scenarios require different deduplication strategies:

1. **Same-rule duplicates**: The same rule fires twice at the same location (e.g.,
   two Semgrep runs, or a tool that emits duplicate JSON entries). Removed by the
   first pass keyed on (title, source, file, line).

2. **Overlapping-rule duplicates**: Multiple different rules from the same tool all
   fire at the same (file, line) and belong to the same vulnerability class (same
   CWE). This is rule overlap, not multiple distinct vulnerabilities. For example,
   three open-redirect rules firing at the same line represent one issue, not three.
   Removed by the second pass keyed on (source, file, line, cwe_id), keeping only
   the highest-severity finding at that location for that CWE.

Note: DAST findings use URL as their location key rather than file_path/line, so
duplicate DAST results (e.g., nuclei running the same template twice) are also
caught by pass 1 since they share the same title, source, and URL.
"""

from typing import List, Dict, Any, Optional
from loguru import logger

# Severity order used when choosing which finding to keep during overlap dedup.
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class ResultMerger:
    """
    Merges vulnerability findings from multiple sources and removes duplicates.

    Two-pass deduplication:
      Pass 1 — (title/id, source, file_path, line): removes exact-rule duplicates.
      Pass 2 — (source, file_path, line, cwe_id):   removes overlapping-rule duplicates
                                                      within the same vulnerability class.
    """

    def merge_and_deduplicate(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings from a combined list of vulnerabilities.

        Args:
            vulnerabilities: Combined list of normalised findings from all tools.

        Returns:
            List[Dict]: Deduplicated findings, preserving order of first occurrence
                        (or highest severity when overlapping rules are collapsed).
        """
        logger.info(f"Deduplicating {len(vulnerabilities)} finding(s)...")

        after_pass1 = self._deduplicate_same_rule(vulnerabilities)
        after_pass2 = self._deduplicate_overlapping_rules(after_pass1)

        removed = len(vulnerabilities) - len(after_pass2)
        if removed:
            logger.info(
                f"Removed {removed} duplicate(s) "
                f"({len(vulnerabilities)} → {len(after_pass2)} unique finding(s))."
            )

        return after_pass2

    # ------------------------------------------------------------------
    # Pass 1: same-rule duplicates
    # ------------------------------------------------------------------

    def _deduplicate_same_rule(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove findings where the same rule fires at the same location twice.

        Key: (title or id, source tool, file_path, line).
        The first occurrence is kept; duplicates are discarded.
        """
        seen: set = set()
        deduped: List[Dict[str, Any]] = []

        for v in vulnerabilities:
            loc = v.get("location") or {}
            key = (
                v.get("title") or v.get("id") or "",
                v.get("source") or "",
                loc.get("file_path") or "",
                str(loc.get("line") or ""),
            )

            if key in seen:
                logger.debug(f"Pass-1 duplicate removed: {key[0]} @ {key[2]}:{key[3]}")
                continue

            seen.add(key)
            deduped.append(v)

        return deduped

    # ------------------------------------------------------------------
    # Pass 2: overlapping-rule duplicates (same location, same CWE)
    # ------------------------------------------------------------------

    def _deduplicate_overlapping_rules(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Collapse multiple rules that fire at the same location for the same CWE.

        When several Semgrep rules all match the same (file, line) and share the
        same CWE identifier, they represent the same underlying vulnerability
        reported through different rule lenses (e.g., three open-redirect rules
        that all trigger on the same redirect call). Keeping all of them inflates
        the finding count without providing additional information.

        Strategy:
          - Group by (source, file_path, line, cwe_id).
          - Within each group, keep the finding with the highest severity.
          - When severity is equal, keep the one with the higher confidence.
          - Findings with no CWE (cwe_id is None) are never collapsed — we
            cannot safely assume different-CWE-less rules are reporting the
            same issue.
          - DAST findings (no file_path) are passed through unchanged since
            URL-based deduplication was already handled in pass 1.

        Args:
            vulnerabilities: Pass-1-deduplicated findings.

        Returns:
            List[Dict]: Further deduplicated findings, in original order.
        """
        # Bucket by overlap key; track best (highest severity) per bucket.
        # bucket_best: key -> (severity_rank, confidence, finding)
        bucket_best: Dict[tuple, tuple] = {}
        # Preserve insertion order: track which keys appeared and in what order.
        key_order: List[tuple] = []
        # Findings that are not eligible for overlap dedup (no CWE or DAST).
        passthrough: List[Dict[str, Any]] = []
        passthrough_indices: List[int] = []

        indexed: List[tuple] = []  # (original_index, overlap_key_or_None, finding)

        for i, v in enumerate(vulnerabilities):
            loc = v.get("location") or {}
            file_path: str = loc.get("file_path") or ""
            line: str = str(loc.get("line") or "")
            cwe_id: Optional[str] = v.get("cwe_id") or None
            source: str = v.get("source") or ""

            # Only collapse SAST findings with a known CWE.
            if not cwe_id or not file_path:
                indexed.append((i, None, v))
                continue

            overlap_key = (source, file_path, line, cwe_id)
            indexed.append((i, overlap_key, v))

        # Process in original order so we can reconstruct order at the end.
        result_map: Dict[tuple, Dict[str, Any]] = {}

        for orig_idx, overlap_key, v in indexed:
            if overlap_key is None:
                # Not eligible — always kept.
                continue

            sev_rank = _SEVERITY_RANK.get((v.get("severity") or "INFO").upper(), 0)
            conf = float(v.get("confidence") or 0.0)

            if overlap_key not in result_map:
                key_order.append(overlap_key)
                result_map[overlap_key] = v
                bucket_best[overlap_key] = (sev_rank, conf)
            else:
                best_sev, best_conf = bucket_best[overlap_key]
                if (sev_rank, conf) > (best_sev, best_conf):
                    old_title = result_map[overlap_key].get("title", "?")
                    new_title = v.get("title", "?")
                    logger.debug(
                        f"Pass-2 overlap collapse: kept '{new_title}' over '{old_title}' "
                        f"at {overlap_key[1]}:{overlap_key[2]} (CWE {overlap_key[3]})"
                    )
                    result_map[overlap_key] = v
                    bucket_best[overlap_key] = (sev_rank, conf)
                else:
                    logger.debug(
                        f"Pass-2 overlap removed: '{v.get('title','?')}' "
                        f"at {overlap_key[1]}:{overlap_key[2]} (CWE {overlap_key[3]})"
                    )

        # Reconstruct in original insertion order.
        deduped: List[Dict[str, Any]] = []
        emitted_keys: set = set()

        for orig_idx, overlap_key, v in indexed:
            if overlap_key is None:
                deduped.append(v)
            elif overlap_key not in emitted_keys:
                deduped.append(result_map[overlap_key])
                emitted_keys.add(overlap_key)
            # else: this key was already emitted (a lower-severity duplicate)

        return deduped
