"""
schemas/__init__.py
====================
Pydantic schemas package — exports all request/response models.

These schemas define the shape of data flowing through the API. Pydantic validates
all incoming requests against these models before the endpoint handler runs, and
serialises outgoing responses to match the defined output schema.
"""

from .common import HealthResponse
from .security import (
    ScanRequest,
    ScanResponse,
    Vulnerability,
    VulnerabilityLocation,
)

__all__ = [
    "HealthResponse",
    "ScanRequest",
    "ScanResponse",
    "Vulnerability",
    "VulnerabilityLocation",
]
