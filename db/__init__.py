"""
db/__init__.py
===============
Database package — exports the session dependency and initialisation helper.

The async SQLAlchemy setup (engine, session factory, table creation) is defined
in database.py. This __init__ re-exports the two functions used most widely:

  - init_db(): Called at startup to ensure all tables exist.
  - get_db(): FastAPI dependency that provides a per-request database session.
"""

from .database import get_db, init_db

__all__ = ["get_db", "init_db"]

