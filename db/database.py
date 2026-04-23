"""
db/database.py
===============
Async database engine, session factory, and initialisation helpers.

This module sets up SQLAlchemy's async engine using aiosqlite as the underlying
SQLite driver. Using an async engine is important here because the application uses
FastAPI with async endpoints — a synchronous database driver would block the event
loop during queries, defeating the purpose of async Python.

Key components:
  - engine: The async SQLAlchemy engine (connection pool + dialect).
  - AsyncSessionLocal: Session factory — call this to get a database session.
  - init_db(): Creates all tables if they do not exist (startup helper).
  - get_db(): FastAPI dependency that yields a session per request.

SQLite is used for simplicity in this student project. The DATABASE_URL in .env
could be changed to PostgreSQL (with asyncpg) for a production deployment without
changing any other application code, as SQLAlchemy abstracts the dialect.
"""

from __future__ import annotations

from typing import AsyncGenerator

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.core.config import settings
from db.base import Base


def _normalize_async_sqlite_url(url: str) -> str:
    """
    Upgrade a synchronous SQLite URL to its async equivalent.

    SQLAlchemy requires `sqlite+aiosqlite:///` for async operation. If an older
    synchronous `sqlite:///` URL is present in the config, this function silently
    upgrades it so the application does not break when running with an older .env.

    Args:
        url: DATABASE_URL string from settings.

    Returns:
        str: URL with the aiosqlite driver prefix, unchanged if already correct.
    """
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    if url.startswith("sqlite:////"):
        return url.replace("sqlite:////", "sqlite+aiosqlite:////", 1)
    return url


DATABASE_URL = _normalize_async_sqlite_url(settings.database_url)

# Create the async engine. echo=False suppresses SQL statement logging in production;
# set to True temporarily for debugging database query issues.
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
)

# Session factory — produces AsyncSession instances.
# expire_on_commit=False keeps ORM objects usable after a commit without re-querying,
# which is important in async code where re-querying would require another await.
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """
    Create all database tables if they do not already exist.

    Called at application startup (FastAPI lifespan event) and at the start of each
    CLI run. Uses SQLAlchemy's create_all() with checkfirst semantics — it will not
    drop or recreate tables that already exist, so it is safe to call repeatedly.

    For schema changes (adding/removing columns), use Alembic migrations
    (`alembic upgrade head`) rather than modifying models and relying on create_all().
    """
    # Importing models here registers their table definitions on Base.metadata
    # so that create_all() knows which tables to create.
    from db import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialised — all tables verified/created.")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session per request.

    Used with FastAPI's Depends() system. Each incoming request gets its own
    session; the session is automatically closed when the request completes.
    If an unhandled exception occurs, the session is closed without committing,
    which effectively rolls back any pending changes.

    Usage in an endpoint:
        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(Scan))
            ...

    Yields:
        AsyncSession: An active database session.
    """
    async with AsyncSessionLocal() as session:
        yield session
