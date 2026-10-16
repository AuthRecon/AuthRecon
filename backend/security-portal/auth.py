"""Portal auth helpers: JWT session tokens.

The web UI's session is an HttpOnly cookie (SESSION_COOKIE), so page scripts
never see a token; requests authenticated by that cookie must also carry
CSRF_HEADER, which a cross-site form or request cannot add without passing
CORS. Scripts and tests may still send ``Authorization: Bearer``."""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, Response
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

def create_jwt_token(username: str, is_admin: bool = False, user_id: str | None = None,
                     mfa_enroll: bool = False) -> str:
    """Create a JWT token for API authentication.

    ``mfa_enroll``: the account must set up MFA first; the token is accepted only
    by the MFA endpoints (MFA_ENROLL_PATHS) until it does (see mfa.py)."""
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
    if mfa_enroll:
        payload["mfa_enroll"] = True
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


MFA_PENDING_TTL_SECONDS = 300
# Paths an MFA-enrollment-only session may use (everything else answers 403).
MFA_ENROLL_PATHS = ("/api/auth/mfa", "/api/auth/me", "/api/auth/logout", "/api/auth/status")


def create_mfa_pending_token(username: str, user_id: str) -> str:
    """Proof that the password step passed; exchanged for a session at
    /api/auth/mfa/verify. Never accepted as a session (session_user_from_payload)."""
    now = datetime.utcnow()
    payload = {
        "typ": "mfa_pending",
        "username": username,
        "user_id": user_id,
        "jti": str(uuid.uuid4()),
        "exp": now + timedelta(seconds=MFA_PENDING_TTL_SECONDS),
        "iat": now,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_mfa_pending_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Sign-in expired. Enter your password again.") from None
    if payload.get("typ") != "mfa_pending" or is_jti_revoked(payload.get("jti") or ""):
        raise HTTPException(status_code=401, detail="Sign-in expired. Enter your password again.")
    return payload


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


def session_user_from_payload(payload: dict, path: str | None = None) -> SessionUser:
    """Build the request's user from a verified token payload, using the
    current DB record (not the token's copy) for status and admin rights.

    Only session tokens qualify: an MFA-pending token (password step only) is
    refused, and an MFA-enrollment session only reaches the MFA endpoints."""
    if payload.get("typ") not in (None, "session"):
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("mfa_enroll") and not (path and path.startswith(MFA_ENROLL_PATHS)):
        raise HTTPException(status_code=403, detail="Set up two-factor authentication to continue.")
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


# --- Session cookies (web UI) --------------------------------------------------

SESSION_COOKIE = "ar_session"
# The AuthRecon API token, set by /api/auth/authrecon-session and turned into
# an Authorization header by the /apps/authrecon proxy.
AUTHRECON_COOKIE = "ar_api"
AUTHRECON_COOKIE_PATH = "/apps/authrecon"
CSRF_HEADER = "X-Requested-With"


def _cookie_secure(request: Request) -> bool:
    """Secure cookies need HTTPS. SESSION_COOKIE_SECURE=true|false overrides;
    the default follows the request (or X-Forwarded-Proto behind a TLS proxy)."""
    setting = (os.getenv("SESSION_COOKIE_SECURE") or "auto").strip().lower()
    if setting in ("1", "true", "yes", "on"):
        return True
    if setting in ("0", "false", "no", "off"):
        return False
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto.split(",")[0].strip().lower() == "https"


def set_cookie(response: Response, request: Request, name: str, value: str, max_age: int,
               path: str = "/") -> None:
    response.set_cookie(name, value, max_age=max_age, path=path, httponly=True,
                        secure=_cookie_secure(request), samesite="strict")


def set_session_cookie(response: Response, request: Request, token: str) -> None:
    set_cookie(response, request, SESSION_COOKIE, token, JWT_EXPIRATION_HOURS * 3600)
    # A new session never inherits the previous one's AuthRecon token.
    response.delete_cookie(AUTHRECON_COOKIE, path=AUTHRECON_COOKIE_PATH)


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(AUTHRECON_COOKIE, path=AUTHRECON_COOKIE_PATH)


def session_token_from_request(request: Request) -> str | None:
    """The caller's session token: a bearer header, else the session cookie.

    Cookie-authenticated requests must carry CSRF_HEADER (403 otherwise).
    Records the source in ``request.state.auth_source`` ("bearer" | "cookie")."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        request.state.auth_source = "bearer"
        return auth_header[7:]
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        if not request.headers.get(CSRF_HEADER):
            raise HTTPException(status_code=403, detail="Missing X-Requested-With header")
        request.state.auth_source = "cookie"
        return token
    return None


def authenticated_by_cookie(request: Request) -> bool:
    return getattr(request.state, "auth_source", None) == "cookie"


def get_current_user_from_token(request: Request) -> SessionUser:
    """The signed-in user, from the bearer header or the session cookie."""
    token = session_token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not signed in")
    payload = decode_jwt_token(token)
    return session_user_from_payload(payload, request.url.path)
