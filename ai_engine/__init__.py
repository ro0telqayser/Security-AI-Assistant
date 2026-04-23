"""
ai_engine/__init__.py
======================
LLM integration — generates vulnerability explanations and fix suggestions.

This module connects to a locally-running Ollama instance to query the DeepSeek
language model. For each vulnerability finding, it asks the model to:
  1. Explain the vulnerability in plain English — what it is and how an attacker
     could exploit it.
  2. Suggest a concrete fix or mitigation.

Why a local LLM rather than a cloud API?
  Security findings often contain sensitive information (file paths, code snippets,
  internal URLs, server version strings). Sending this data to a cloud API risks
  data leakage. Running DeepSeek locally via Ollama keeps all data on the machine.

Prerequisites:
  - Ollama installed and running: https://ollama.ai/
  - DeepSeek model pulled: `ollama pull deepseek-r1:8b`
  - Ollama API accessible at http://localhost:11434

The model is configurable via the DEEPSEEK_MODEL environment variable. Smaller
models (e.g., deepseek-r1:1.5b) run faster on hardware without a dedicated GPU
but may produce less detailed explanations.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Dict, Any

from backend.app.core.config import settings
from ai_engine.prompt import build_prompt, parse_response

# Ollama's local HTTP API for generating text completions.
OLLAMA_API_URL = "http://localhost:11434/api/generate"


def generate_explanation_and_fix(finding: Dict[str, Any]) -> Dict[str, str]:
    """
    Call the DeepSeek model via Ollama to explain a vulnerability and suggest a fix.

    Builds a structured prompt from the finding's details, sends it to Ollama's
    /api/generate endpoint, and parses the response into separate explanation and
    fix sections.

    The prompt is designed to produce output in a consistent two-section format:
        [Explanation]
        ... plain English explanation ...
        [Fix]
        ... concrete remediation steps ...

    If the model does not follow this format exactly, the full response is returned
    as the explanation and the fix is left empty.

    Args:
        finding: A normalised vulnerability dict containing at minimum:
                 - title (str): Short name of the vulnerability
                 - severity (str): Severity level
                 - source (str): Tool that found it
                 - description (str): Full description/message
                 - location (dict): Where it was found
                 - metadata (dict): Raw tool output

    Returns:
        Dict with keys:
          - "explanation" (str): Plain-English description of the vulnerability,
                                 its impact, and how an attacker could exploit it.
          - "fix" (str): Concrete code or configuration changes to remediate the issue.
                         Empty string if the LLM call fails or no fix section is found.

    Note:
        This function makes a blocking HTTP call (not async). It should be run in
        a thread when called from async code. The CLI handles this by calling it
        synchronously in an async helper that is already wrapped in asyncio.run().
    """
    model = settings.deepseek_model

    # Build the structured prompt from the evidence pack (ai_engine/prompt.py).
    prompt = build_prompt(finding)

    try:
        # Send the prompt to Ollama. stream=False waits for the full response before
        # returning, rather than streaming tokens. This simplifies parsing.
        payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(
            OLLAMA_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        # 3-minute timeout — large models on CPU can take a while to respond.
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode())
        output = data.get("response", "").strip()

    except Exception as e:
        # Do not raise — an LLM failure should not prevent scan results from being returned.
        return {
            "explanation": f"LLM explanation unavailable: {e}",
            "fix": "",
        }

    # Parse the [Explanation] / [Fix] sections from the model's response.
    return parse_response(output)
