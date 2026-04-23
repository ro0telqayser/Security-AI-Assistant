"""
backend/app/core/config.py
===========================
Application configuration — loads settings from environment variables and .env.

All configurable values are defined here as Pydantic Settings fields. Pydantic reads
the values from environment variables (or a .env file) and validates their types
automatically. This means the application fails fast at startup if a required
setting is missing or has the wrong type, rather than failing later during a scan.

Configuration is split into logical groups:
  - API:        Host, port, debug mode
  - Tools:      Paths/URLs for Semgrep and HexStrike
  - Safety:     SCAN_ROOT (SAST filesystem restriction) and DAST allowlist
  - AI/LLM:     Ollama model name for LLM explanations
  - Database:   SQLite URL (or PostgreSQL URL for production)
  - CORS:       Allowed frontend origins

The global `settings` object at the bottom of this file is imported by the rest
of the application. All components access configuration through this single object,
making it easy to change defaults or inject test configuration.

Usage:
    from backend.app.core.config import settings

    print(settings.hexstrike_url)  # "http://127.0.0.1:4444"

Reference: Pydantic Settings — https://docs.pydantic.dev/latest/concepts/pydantic_settings/
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables / .env file.

    Each field can be overridden by setting the corresponding environment variable
    (the alias, e.g., API_HOST=0.0.0.0). The .env file is loaded automatically
    if it exists at the project root.
    """

    # ------------------------------------------------------------------
    # API server settings
    # ------------------------------------------------------------------
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    debug: bool = Field(default=False, alias="API_DEBUG")

    # ------------------------------------------------------------------
    # Security tool settings
    # ------------------------------------------------------------------

    # Semgrep: default to finding the binary on PATH.
    # Override with SEMGREP_PATH=/absolute/path/to/semgrep if needed.
    semgrep_path: str = Field(default="semgrep", alias="SEMGREP_PATH")

    # HexStrike: the REST API server running the DAST toolchain.
    # Port 4444 is used as default to avoid conflicts with Jupyter (8888) or other tools.
    hexstrike_url: str = Field(default="http://127.0.0.1:4444", alias="HEXSTRIKE_URL")
    hexstrike_api_key: str = Field(default="", alias="HEXSTRIKE_API_KEY")

    # Path to the HexStrike repo on disk — used by the CLI to auto-start the server.
    hexstrike_path: str = Field(default="../hexstrike-ai", alias="HEXSTRIKE_PATH")

    # ------------------------------------------------------------------
    # SAST safety settings
    # ------------------------------------------------------------------

    # SCAN_ROOT restricts filesystem scans to this directory when using the API.
    # This prevents attackers from using the API to scan sensitive parts of the
    # server filesystem (e.g., /etc, /home, /var).
    # The CLI can override this with --allow-any-path for local development use.
    scan_root: str = Field(default=".", alias="SCAN_ROOT")

    # ------------------------------------------------------------------
    # DAST safety settings
    # ------------------------------------------------------------------

    # DAST_ALLOWLIST: comma-separated hostnames that are safe to scan.
    # Defaults to localhost only — safe for OWASP lab apps (DVWA, Juice Shop, etc.)
    # running on the developer's own machine.
    dast_allowlist: str = Field(default="localhost,127.0.0.1", alias="DAST_ALLOWLIST")

    # If True, skip the allowlist check entirely. Intended for lab/testing scenarios
    # where many different external targets need to be scanned. Use with caution.
    dast_allow_nonlocal: bool = Field(default=False, alias="DAST_ALLOW_NONLOCAL")

    # ------------------------------------------------------------------
    # AI / LLM settings
    # ------------------------------------------------------------------

    # The Ollama model to use for generating vulnerability explanations and fixes.
    # The model must be pulled locally before use: `ollama pull deepseek-r1:8b`
    deepseek_model: str = Field(default="deepseek-r1:8b", alias="DEEPSEEK_MODEL")

    # ------------------------------------------------------------------
    # Database settings
    # ------------------------------------------------------------------

    # SQLite (aiosqlite driver) is the default — zero setup required.
    # Can be changed to PostgreSQL (asyncpg) for production:
    #   DATABASE_URL=postgresql+asyncpg://user:pass@localhost/dbname
    database_url: str = Field(
        default="sqlite+aiosqlite:///./security_assistant.db",
        alias="DATABASE_URL"
    )

    # ------------------------------------------------------------------
    # CORS settings
    # ------------------------------------------------------------------

    # Allowed origins for CORS. In production, replace with the actual frontend domain.
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        alias="ALLOWED_ORIGINS"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"  # Ignore unknown env vars rather than raising an error
    )


# Single global settings instance — imported by all modules that need configuration.
settings = Settings()
