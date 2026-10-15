"""Portal auth helpers: JWT bearer tokens (the React frontend sends ``Authorization: Bearer``)."""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request
import jwt
import redis as _redis_sync


# JWT Configuration
JWT_SECRET_KEY = "change-me"  # Will be configured at runtime
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24


def configure_serializer(secret_key: str) -> None:
    """Set the JWT signing secret at runtime (called by config.load_config)."""
    global JWT_SECRET_KEY
    JWT_SECRET_KEY = secret_key


# --- JWT revocation blocklist (Redis-backed) -----------------------------------

_revocation_client: Optional["_redis_sync.Redis"] = None


def _get_revocation_redis() -> Optional["_redis_sync.Redis"]:
    global _revocation_client
    if _revocation_client is None:
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url:
            try:
                _revocation_client = _redis_sync.from_url(redis_url, decode_responses=True)
            except Exception:
                pass
    return _revocation_client


def is_jti_revoked(jti: str) -> bool:
    """Return True if this JWT ID is on the revocation blocklist."""
    try:
        r = _get_revocation_redis()
        if r:
            return bool(r.exists(f"revoked:jti:{jti}"))
    except Exception:
        pass
    return False  # Fail open — Redis unavailable should not lock everyone out


def revoke_jti(jti: str, ttl_seconds: int) -> None:
    """Add a JWT ID to the blocklist; entry expires when the token would have expired."""
    try:
        r = _get_revocation_redis()
        if r and jti and ttl_seconds > 0:
            r.set(f"revoked:jti:{jti}", "1", ex=ttl_seconds)
            r.delete(f"jti:active:{jti}")  # Clean up idle tracking key on logout
    except Exception:
        pass


# --- Session idle timeout (N9) -------------------------------------------------

def _get_idle_timeout_seconds() -> int:
    """Return the configured idle timeout in seconds, or 0 if disabled."""
    raw = os.getenv("PORTAL_SESSION_IDLE_TIMEOUT", "0")
    try:
        minutes = max(0, int(raw))
        return minutes * 60
    except (ValueError, TypeError):
        return 0


def _check_and_refresh_idle(jti: str, iat: float, idle_timeout_seconds: int) -> None:
    """Enforce idle timeout for a JTI. Raises HTTPException if the session has been idle too long.

    On each call the active-tracking key TTL is refreshed so the window slides
    forward. Fails open if Redis is unavailable (same policy as revocation).
    """
    try:
        r = _get_revocation_redis()
        if not r:
            return
        key = f"jti:active:{jti}"
        if r.exists(key):
            r.expire(key, idle_timeout_seconds)
        else:
            # Key absent: either this is the first request after login, or the
            # session has been idle for longer than idle_timeout_seconds.
            token_age = time.time() - iat
            if token_age <= idle_timeout_seconds:
                # Token is fresh enough — first use, start tracking.
                r.set(key, "1", ex=idle_timeout_seconds)
            else:
                raise HTTPException(
                    status_code=401,
                    detail="Session expired due to inactivity. Please log in again.",
                )
    except HTTPException:
        raise
    except Exception:
        pass  # Fail open — Redis unavailable must not lock everyone out


@dataclass
class SessionUser:
    """Authenticated user record."""

    username: str
    is_admin: bool = False
    user_id: Optional[str] = None


# JWT Token Functions (for React API authentication)

def create_jwt_token(username: str, is_admin: bool = False, user_id: str | None = None) -> str:
    """Create a JWT token for API authentication."""
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "username": username,
        "is_admin": is_admin,
        "roles": ["admin"] if is_admin else [],
        "user_id": user_id,
        "jti": str(uuid.uuid4()),  # Unique token ID — used for server-side revocation
        "exp": expiration,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    """Decode and verify a JWT token, including revocation and idle-timeout checks."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti and is_jti_revoked(jti):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        idle_timeout = _get_idle_timeout_seconds()
        if jti and idle_timeout > 0:
            _check_and_refresh_idle(jti, float(payload.get("iat", 0)), idle_timeout)
        return payload
    except HTTPException:
        raise
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Looks a user up by id in the portal DB; set by the app at startup. Tokens
# are checked against it on every request so deactivating, deleting or
# demoting a user takes effect immediately rather than when the JWT expires.
_user_lookup: Optional[Callable[[str], Optional[dict]]] = None


def configure_user_lookup(lookup: Optional[Callable[[str], Optional[dict]]]) -> None:
    global _user_lookup
    _user_lookup = lookup


def session_user_from_payload(payload: dict) -> SessionUser:
    """Build the request's user from a verified token payload, using the
    current DB record (not the token's copy) for status and admin rights."""
    username = payload.get("username")
    user_id = payload.get("user_id")
    is_admin = bool(payload.get("is_admin", False))
    if _user_lookup is not None:
        record = _user_lookup(user_id) if user_id else None
        if not record or not record.get("is_active", False):
            raise HTTPException(status_code=401, detail="Account is disabled or no longer exists")
        username = record["username"]
        is_admin = bool(record["is_admin"])
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    return SessionUser(username=username, is_admin=is_admin, user_id=user_id)


def get_current_user_from_token(request: Request) -> SessionUser:
    """Retrieve user from JWT Bearer token (for API requests)."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = auth_header.split(" ")[1]
    payload = decode_jwt_token(token)
    return session_user_from_payload(payload)
