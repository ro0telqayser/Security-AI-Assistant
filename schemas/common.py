"""
schemas/common.py
==================
Shared Pydantic schemas used across multiple API endpoints.

This module contains data models that are not specific to any single endpoint.
Keeping shared schemas in a separate module avoids circular imports and makes it
clear which schemas are part of the general API contract versus those that are
specific to a single feature area.
"""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """
    Response schema for the GET /health endpoint.

    Used by monitoring tools, load balancers, and the CLI's HexStrike auto-start
    logic to verify that the server is running and accepting requests.

    Example response:
        {"status": "healthy", "service": "security-ai-assistant"}
    """

    status: str = Field(..., examples=["healthy"])
    service: str = Field(..., examples=["security-ai-assistant"])
