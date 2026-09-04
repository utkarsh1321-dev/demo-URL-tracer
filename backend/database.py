"""
database.py — PostgreSQL engine via Supabase connection pooler.

Supports two configuration modes (checked in order):

Mode 1 — Individual components (RECOMMENDED for Render):
    DB_HOST      = aws-0-ap-northeast-2.pooler.supabase.com
    DB_PORT      = 6543
    DB_NAME      = postgres
    DB_USER      = postgres.ellixsfnmklvqirrcvvq
    DB_PASSWORD  = (your raw password — no URL encoding needed)

Mode 2 — Full connection string (legacy / local dev):
    DATABASE_URL = postgresql://user:pass@host:port/db

Falls back to SQLite so unit tests work without a real DB.
"""

import os
import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine import URL

logger = logging.getLogger(__name__)

# ─── Mode 1: build URL from individual components ────────────────────────────
# Each value is set as its own env var in Render — no URL construction needed.
# SQLAlchemy's URL.create() handles special characters in passwords safely.

_DB_HOST     = os.environ.get("DB_HOST", "")
_DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
_DB_PORT     = int(os.environ.get("DB_PORT", "6543"))
_DB_NAME     = os.environ.get("DB_NAME", "postgres")
_DB_USER     = os.environ.get("DB_USER", f"postgres.ellixsfnmklvqirrcvvq")

# ─── Mode 2: full DATABASE_URL (legacy) ──────────────────────────────────────
_DATABASE_URL_RAW = os.environ.get("DATABASE_URL", "")

# ─── Pick the right engine config ────────────────────────────────────────────

if _DB_HOST and _DB_PASSWORD:
    # Mode 1 — individual components (preferred)
    _engine_url = URL.create(
        drivername="postgresql+psycopg2",
        username=_DB_USER,
        password=_DB_PASSWORD,      # URL.create() handles special chars safely
        host=_DB_HOST,
        port=_DB_PORT,
        database=_DB_NAME,
    )
    _is_sqlite = False
    logger.info("DB: using component-based connection to %s:%s/%s", _DB_HOST, _DB_PORT, _DB_NAME)

elif _DATABASE_URL_RAW and not _DATABASE_URL_RAW.startswith("sqlite"):
    # Mode 2 — full URL string
    _engine_url = _DATABASE_URL_RAW
    _is_sqlite = False
    logger.info("DB: using DATABASE_URL connection string")

else:
    # Fallback — SQLite for local tests / no DB configured
    _engine_url = _DATABASE_URL_RAW or "sqlite:///./fallback_dev.db"
    _is_sqlite = True
    logger.warning("DB: no PostgreSQL config found — falling back to SQLite")


engine = create_engine(
    _engine_url,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    pool_pre_ping=True,    # verify connection health before use
    pool_size=5,           # safe for Supabase free tier (max 15 conns)
    max_overflow=5,
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
