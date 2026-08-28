"""
db_utils.py — Database session helpers.
Phase 2: Sets the PostgreSQL session variable that RLS policies read.

The pattern per-request:
    set_rls_user(db, current_user.id)
    # all subsequent queries on this session are RLS-filtered
"""

from sqlalchemy import text
from sqlalchemy.orm import Session


def set_rls_user(db: Session, user_id: str) -> None:
    """
    Set app.current_user_id for this DB session/transaction.

    RLS policies are defined as:
        USING (user_id = current_setting('app.current_user_id', true)::uuid)

    This call must be the first statement in every protected endpoint,
    before any SELECT / INSERT / UPDATE / DELETE.

    Works with both PostgreSQL (full RLS) and SQLite (no-op, app-level
    filtering is the security control in that case).
    """
    try:
        db.execute(text("SET LOCAL app.current_user_id = :uid"), {"uid": str(user_id)})
    except Exception:
        # SQLite does not support SET LOCAL — silently skip.
        # Application-level user_id filtering is still enforced.
        pass
