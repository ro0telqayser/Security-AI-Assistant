"""
normalizer/__init__.py
=======================
Normaliser package.

Exports the core normalisation components so they can be imported from a
single location:

    from normalizer import VulnerabilityNormalizer, Deduplicator, FormatConverter

- VulnerabilityNormalizer: Defines the common finding schema and provides a
  central hook for cross-tool enrichment.
- Deduplicator: Removes duplicate findings from a list.
- FormatConverter: Converts findings to output formats (JSON, etc.).
"""

from .vulnerability_normalizer import VulnerabilityNormalizer
from .deduplicator import Deduplicator
from .format_converter import FormatConverter

__all__ = [
    "VulnerabilityNormalizer",
    "Deduplicator",
    "FormatConverter",
]
