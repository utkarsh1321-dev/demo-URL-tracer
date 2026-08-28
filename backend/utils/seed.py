"""
utils/seed.py — REMOVED in Phase 1 (Remove Synthetic Data).

This module previously auto-seeded the SQLite database with ~200 synthetic
HTTP request records on every application startup.

It has been replaced with an empty database state as part of the transition
to a production system with real user data.

The seed_database stub below exists only to prevent import errors in any
code that may still reference it. It is safe to remove this file entirely
once all imports have been cleaned up.
"""


def seed_database(db) -> None:
    """No-op. Synthetic data seeding has been removed in Phase 1."""
    pass
