"""
database.py — PostgreSQL engine via Supabase.
Phase 2: Switched from SQLite to PostgreSQL. DATABASE_URL loaded from .env
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

# Loaded by load_dotenv() in main.py before this module is imported.
# Falls back to SQLite so unit tests work without a real DB.
DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./fallback_dev.db")

_is_sqlite = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    # SQLite needs check_same_thread=False; PostgreSQL doesn't accept it
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    pool_pre_ping=True,   # verify connection health before use
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session and closes it after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
