"""
auth.py — JWT verification middleware.
Phase 2: Verifies Supabase-issued JWTs on every protected endpoint.

Security rules:
- user_id is ALWAYS extracted from the verified JWT (sub claim)
- user_id is NEVER accepted from request body or query parameters
- Expired or tampered tokens raise HTTP 401 immediately
"""

import os
from dataclasses import dataclass

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

# Loaded from .env via load_dotenv() in main.py
_JWT_SECRET: str = os.environ.get("SUPABASE_JWT_SECRET", "")
_ALGORITHM = "HS256"

# Supabase signs tokens with aud="authenticated" for logged-in users
_AUDIENCE = "authenticated"

_bearer = HTTPBearer(auto_error=True)


@dataclass(frozen=True)
class CurrentUser:
    """Verified identity extracted from the Supabase JWT."""
    id: str     # UUID string — the user's auth.users.id
    email: str


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> CurrentUser:
    """
    FastAPI dependency. Verifies Bearer token and returns the authenticated user.

    Usage:
        @router.get("/protected")
        def endpoint(current_user: CurrentUser = Depends(get_current_user)):
            ...
    """
    _raise = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not _JWT_SECRET:
        # SUPABASE_JWT_SECRET not configured — block all protected requests
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service not configured.",
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            _JWT_SECRET,
            algorithms=[_ALGORITHM],
            audience=_AUDIENCE,
        )
    except JWTError:
        raise _raise

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise _raise

    return CurrentUser(
        id=user_id,
        email=payload.get("email", ""),
    )
