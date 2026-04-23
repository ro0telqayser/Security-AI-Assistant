"""
backend/app/main.py
====================
FastAPI application entry point.

This module creates and configures the FastAPI application instance. It is the
starting point when the API server is launched with uvicorn:

    uvicorn backend.app.main:app --reload

Responsibilities:
  - Create the FastAPI app with metadata (title, version, docs URLs).
  - Configure structured logging via Loguru.
  - Register CORS middleware to allow the frontend to communicate with the API.
  - Define startup / shutdown lifecycle hooks (database initialisation).
  - Mount the v1 API router under /api/v1.
  - Expose a root endpoint and a health check endpoint.

CORS (Cross-Origin Resource Sharing) is configured to allow the frontend
(typically running on localhost:3000) to make API requests. In production this
should be tightened to the specific frontend domain rather than wildcards.

Reference: FastAPI documentation — https://fastapi.tiangolo.com/
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
import sys

from backend.app.api.v1.routers import api_router
from backend.app.core.config import settings
from schemas.common import HealthResponse
from db.database import init_db

# Configure Loguru to write structured logs to stderr.
# In debug mode, all log levels are shown; in production only INFO and above.
logger.remove()
logger.add(
    sys.stderr,
    format=(
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan> - "
        "<level>{message}</level>"
    ),
    level="INFO" if not settings.debug else "DEBUG"
)

# Create the FastAPI application instance.
# The docs_url and redoc_url expose Swagger UI and ReDoc interfaces respectively,
# which are extremely useful for manual API testing during development.
app = FastAPI(
    title="Security AI Assistant API",
    version="0.1.0",
    description=(
        "Unified SAST + DAST security scanning pipeline with LLM-powered explanations. "
        "Third-year project — Liverpool John Moores University."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configure CORS middleware.
# This allows the frontend (running on a different port) to make API requests.
# Without this, browsers block cross-origin requests for security reasons.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event() -> None:
    """
    Perform startup tasks when the API server starts.

    Initialises the database (creates tables if missing) so the server is ready
    to accept scan requests immediately after startup without a manual setup step.
    """
    logger.info("Security AI Assistant API starting up...")
    logger.info(f"Debug mode: {settings.debug}")
    await init_db()


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """
    Perform cleanup tasks when the API server shuts down.

    Currently logs the shutdown event. In a production system this would be the
    place to close connection pools, flush metrics, or cancel background tasks.
    """
    logger.info("Security AI Assistant API shutting down.")


@app.get("/", tags=["root"])
async def root() -> dict:
    """
    Root endpoint — returns basic API information.

    Useful for verifying the server is running and discovering the documentation URL.
    """
    return {
        "message": "Security AI Assistant API",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["health"], summary="Liveness probe — NFR3 Reliability")
async def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Returns a simple status response so monitoring tools, load balancers, and
    the CLI's HexStrike auto-start logic can verify the server is accepting requests.

    Returns:
        HealthResponse: {"status": "healthy", "service": "security-ai-assistant"}
    """
    return HealthResponse(
        status="healthy",
        service="security-ai-assistant"
    )


# Register the v1 API router — all scan endpoints are under /api/v1/
app.include_router(api_router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="info"
    )
