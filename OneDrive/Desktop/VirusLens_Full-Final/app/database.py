# BEGIN: ensure project root is importable
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# END: ensure project root is importable

# app/database.py
"""
Database bootstrap for VirusLens.

- Exports: engine, SessionLocal, Base, get_db, init_db
- Default DB: sqlite file at project root named virustlens.db (change via DATABASE_URL env var)
"""

import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# PROJECT ROOT (one level up from this file)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Default database URL (sqlite file placed in project root)
DEFAULT_SQLITE_PATH = os.path.join(PROJECT_ROOT, "virustlens.db")
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_SQLITE_PATH}"

DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

# SQLite needs this connect_args for SQLAlchemy thread-safety on the same connection
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# Create engine and sessionmaker
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=Session)

# Declarative base class for models to inherit
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a SQLAlchemy Session and closes it after use.

    Use in routes as:
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(create_if_missing: bool = True) -> None:
    """
    Initialize the database: import models and create tables.

    - If models cannot be imported this prints a helpful warning.
    - `create_if_missing` kept for compatibility (currently unused specially).
    """
    try:
        # Import models lazily to avoid circular imports (models should import Base from here)
        import app.models  # noqa: F401
    except Exception as e:
        # Provide a helpful message if models.py is missing or errors during import
        raise RuntimeError(
            "Unable to import app.models while initializing DB. "
            "Make sure app/models.py exists and imports Base from app.database.\n"
            f"Original import error: {e}"
        ) from e

    # Create all tables declared on Base (models should have created their classes already)
    Base.metadata.create_all(bind=engine)


# Optional: simple CLI support so you can run `python -m app.database` to create DB/tables.
if __name__ == "__main__":  # pragma: no cover
    print("Initializing database...")
    print(f" DATABASE_URL = {DATABASE_URL}")
    # Ensure folder for sqlite exists
    if DATABASE_URL.startswith("sqlite"):
        db_file = DEFAULT_SQLITE_PATH
        parent_dir = os.path.dirname(db_file)
        if not os.path.isdir(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            print(f" Created directory for DB: {parent_dir}")
        print(f" SQLite DB path: {db_file}")
    try:
        init_db()
        print("Database initialized (tables created).")
    except Exception as exc:
        print("ERROR initializing database:", exc)
        raise
