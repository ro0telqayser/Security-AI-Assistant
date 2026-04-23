"""
ai_engine/prompt.py
====================
Prompt engineering for the AI explanation engine.

The prompt template is a primary design artefact of the AI engine (§4.9.2),
directly determining what context reaches the model and what structure the
response must take.

The template constrains the model in two ways:
  1. An embedded system role instructs it to act as a security expert helping
     a student understand vulnerabilities, scoping output to educational explanation.
  2. The evidence block injects the finding title, severity, location, description,
     and a metadata string truncated to 1,500 characters to prevent context overflow.

Response parsing splits on the [Fix] marker, yielding separate explanation and
fix strings. The [Confidence] output section is identified as a planned evaluation
enhancement (§4.9.2) — it is not present in the current implementation.

An AI explanation is operationally defined as correct if it satisfies all three
evaluation criteria (§4.9.3):
  1. Groundedness   — references only information present in the evidence pack.
  2. Specificity    — fix is specific to the identified CWE and file/URL location.
  3. Confidence Calibration — [Confidence] field (planned) aligns with adapter-supplied
                              confidence float.
"""

from __future__ import annotations

from typing import Any, Dict


def build_prompt(finding: Dict[str, Any]) -> str:
    """
    Build the structured prompt for the DeepSeek LLM from a normalised finding.

    Formats all relevant evidence pack fields (title, severity, location,
    description, metadata) into the prompt template defined in Code Listing 4.6.
    Metadata is truncated to 1,500 characters to prevent context overflow.

    Args:
        finding: A normalised vulnerability finding dict containing at minimum:
                 - title (str): Short name of the vulnerability.
                 - severity (str): Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO).
                 - location (dict): Where the finding was detected.
                 - description (str): Full description / tool message.
                 - metadata (dict): Raw tool output for additional context.

    Returns:
        str: Fully formatted prompt string ready to send to the Ollama API.
    """
    title = finding.get("title") or ""
    severity = finding.get("severity") or ""
    description = finding.get("description") or ""
    location = finding.get("location") or {}
    meta = finding.get("metadata") or {}

    # Format the location for readability in the prompt.
    if location.get("file_path"):
        location_str = f"{location['file_path']}:{location.get('line', '')}"
    elif location.get("url"):
        location_str = str(location["url"])
    else:
        location_str = "unknown"

    prompt = (
        f"You are a security expert helping a student understand vulnerabilities.\n\n"
        f"Vulnerability: {title}\n"
        f"Severity: {severity}\n"
        f"Location: {location_str}\n"
        f"Description: {description}\n"
        f"Evidence: {str(meta)[:1500]}\n\n"
        f"Please provide:\n\n"
        f"[Explanation]\n"
        f"Explain this vulnerability in simple terms. "
        f"What is it and why is it dangerous?\n\n"
        f"[Fix]\n"
        f"How can this vulnerability be fixed? "
        f"Provide specific code-level guidance.\n"
    )

    return prompt


def parse_response(raw_response: str) -> Dict[str, str]:
    """
    Parse the LLM response into separate explanation and fix sections.

    Splits the response on the [Fix] marker. If the marker is absent, the
    full response is returned as the explanation.

    Args:
        raw_response: Raw text output from the Ollama API.

    Returns:
        Dict with keys:
          - "explanation" (str): Plain-English vulnerability explanation.
          - "fix" (str): Concrete remediation guidance. Empty if not present.
    """
    output = raw_response.strip()
    explanation = output
    fix = ""

    if "[Fix]" in output:
        parts = output.split("[Fix]", 1)
        explanation = parts[0].replace("[Explanation]", "").strip()
        fix = parts[1].strip()

    return {
        "explanation": explanation,
        "fix": fix,
    }
