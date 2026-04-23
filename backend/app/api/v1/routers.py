"""
backend/app/api/v1/routers.py
==============================
API version 1 router — aggregates all v1 endpoint routers.

This file is the central registration point for all API v1 routes. Each feature
area has its own router in the endpoints/ directory. Adding a new feature means
creating a new endpoint module and including its router here.

Currently registered routes:
  /api/v1/security/scan   — POST — Run a security scan
"""

from fastapi import APIRouter

from backend.app.api.v1.endpoints import security

api_router = APIRouter()

# Register the security scanning endpoints under /api/v1/security/
api_router.include_router(security.router)
