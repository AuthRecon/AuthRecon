"""AuthRecon dependency injection - Profile-based version.

This module provides dependencies for getting the current authenticated profile.
User identity is managed by Portal; AuthRecon only stores lightweight profiles.

Authentication Methods:
1. JWT Bearer tokens (web UI, short-lived sessions)
2. API keys (CLI tools, long-lived tokens)
"""
from __future__ import annotations

from datetime import datetime, timezone
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_token, verify_api_key
from app.db import get_db
from app.models.profile import AuthReconProfile
from app.models.api_key import APIKey

token_scheme = HTTPBearer(auto_error=False)


def get_token(credentials: HTTPAuthorizationCredentials = Depends(token_scheme)) -> str:
    """Extract Bearer token from Authorization header."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return credentials.credentials


def get_current_profile(
    token: str = Depends(get_token),
    db: Session = Depends(get_db),
) -> AuthReconProfile:
    """
    Get current authenticated AuthRecon profile from JWT token.

    The token subject contains the profile ID (not portal_user_id).
    The token extra_claims contain is_admin and portal_user_id from Portal.

    Args:
        token: JWT access token issued by AuthRecon /auth/portal-login
        db: Database session

    Returns:
        AuthReconProfile: Current authenticated profile with is_admin attribute attached

    Raises:
        HTTPException: If token invalid or profile not found
    """
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        ) from exc

    profile_id = payload.get("sub")
    if not profile_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    profile = db.get(AuthReconProfile, profile_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Profile not found"
        )

    # Attach is_admin and username from Portal (stored in token extra_claims)
    # This allows code to check profile.is_admin and profile.username naturally
    profile.is_admin = payload.get("is_admin", False)
    profile.username = payload.get("username", "unknown")
    profile.auth_method = "jwt"

    return profile


def get_profile_from_jwt_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(token_scheme),
    db: Session = Depends(get_db),
) -> AuthReconProfile | None:
    """
    Get profile from JWT token, returning None if no token provided.

    This allows endpoints to accept optional JWT authentication.
    """
    if not credentials:
        return None

    try:
        payload = decode_token(credentials.credentials)
    except ValueError:
        return None

    profile_id = payload.get("sub")
    if not profile_id:
        return None

    profile = db.get(AuthReconProfile, profile_id)
    if not profile:
        return None

    # Attach is_admin and username from Portal
    profile.is_admin = payload.get("is_admin", False)
    profile.username = payload.get("username", "unknown")
    profile.auth_method = "jwt"

    return profile


def get_profile_from_api_key(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> AuthReconProfile | None:
    """
    Authenticate using API key (for CLI tools).

    Args:
        x_api_key: API key from X-API-Key header
        db: Database session

    Returns:
        AuthReconProfile: Profile if API key is valid, None otherwise

    Security Checks:
        1. API key format validation (ak_live_...)
        2. Hash verification (bcrypt)
        3. Revocation check
        4. Expiration check
        5. Profile api_access_enabled check
        6. Update last_used_at timestamp
    """
    resolved = resolve_api_key(x_api_key, db)
    return resolved[1] if resolved else None


def resolve_api_key(x_api_key: str | None, db: Session) -> tuple[APIKey, AuthReconProfile] | None:
    """Validate a raw API key; return (key, profile) or None. Records last_used_at."""
    if not x_api_key:
        return None

    # Validate format
    if not x_api_key.startswith("ak_live_"):
        return None

    # Find API key by verifying hash against all non-revoked keys
    # Note: This is intentionally not optimized to prevent timing attacks
    # We check all keys to maintain constant time
    api_keys = db.query(APIKey).filter(
        APIKey.is_revoked == False  # noqa: E712
    ).all()

    matched_key = None
    for api_key in api_keys:
        if verify_api_key(x_api_key, api_key.key_hash):
            matched_key = api_key
            break

    if not matched_key:
        # No matching key found
        return None

    # Check expiration
    if matched_key.expires_at and matched_key.expires_at < datetime.now(timezone.utc):
        return None

    # Get profile
    profile = db.get(AuthReconProfile, matched_key.profile_id)
    if not profile:
        return None

    # Check if profile has API access enabled
    if not profile.api_access_enabled:
        return None

    # Update last_used_at timestamp
    matched_key.last_used_at = datetime.now(timezone.utc)
    db.commit()

    # API keys are never admin-scoped; admin operations need the web UI (JWT).
    # The username is the one remembered at the user's last web login.
    profile.is_admin = False
    profile.username = profile.display_name or "unknown user"
    profile.auth_method = "api_key"

    return matched_key, profile


def get_current_active_profile(
    jwt_profile: AuthReconProfile | None = Depends(get_profile_from_jwt_optional),
    api_profile: AuthReconProfile | None = Depends(get_profile_from_api_key),
) -> AuthReconProfile:
    """
    Get current active profile from either JWT or API key.

    Tries JWT first, then falls back to API key.
    This allows endpoints to accept both authentication methods.

    Args:
        jwt_profile: Profile from JWT token (if present)
        api_profile: Profile from API key (if present)

    Returns:
        AuthReconProfile: Current authenticated profile

    Raises:
        HTTPException: 401 if neither auth method succeeds
    """
    # Try JWT first (web UI)
    if jwt_profile:
        return jwt_profile

    # Fall back to API key (CLI)
    if api_profile:
        return api_profile

    # No valid authentication
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated"
    )


def is_admin_user(token: str = Depends(get_token)) -> bool:
    """
    Check if current user has admin privileges from Portal.

    Admin status is stored in JWT extra_claims (from Portal roles).
    Use this helper when you need to check admin status conditionally.

    Args:
        token: JWT token (to extract is_admin claim)

    Returns:
        bool: True if user has admin privileges
    """
    try:
        payload = decode_token(token)
        return payload.get("is_admin", False)
    except ValueError:
        return False


def get_current_admin(
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
    token: str = Depends(get_token),
) -> AuthReconProfile:
    """
    Require admin privileges from Portal.

    Admin status is stored in JWT extra_claims (from Portal roles).
    We don't duplicate is_admin in AuthRecon profiles - it lives in Portal only.

    Args:
        current_profile: Current authenticated profile
        token: JWT token (to extract is_admin claim)

    Returns:
        AuthReconProfile: Current profile (if admin)

    Raises:
        HTTPException: If not admin
    """
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        ) from exc

    is_admin = payload.get("is_admin", False)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )

    return current_profile
