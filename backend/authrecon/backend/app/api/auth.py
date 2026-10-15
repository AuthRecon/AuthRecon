"""AuthRecon authentication endpoints - Portal-centric version.

This module handles authentication via Portal SSO. User identity lives in Portal database.
AuthRecon only stores lightweight profiles with service-specific settings.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import create_access_token
from app.core.portal_token import decode_portal_token, PortalTokenError
from app.db import get_db
from app.models.profile import AuthReconProfile
from app.schemas.auth import PortalLoginRequest, Token
from app.services.profiles import sync_portal_profile, update_last_login
from app.api.deps import get_current_profile

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/portal-login", response_model=Token)
async def portal_login(payload: PortalLoginRequest, db: Session = Depends(get_db)) -> Token:
    """
    Authenticate via Portal service token (SSO).

    This is the ONLY authentication path for AuthRecon. User identity is verified
    by Portal, and we create/retrieve a lightweight profile for this user.

    Args:
        payload: Portal login request with service token
        db: Database session

    Returns:
        Token: AuthRecon access token

    Raises:
        HTTPException: If Portal integration not configured or token invalid
    """
    settings = get_settings()
    if not settings.portal_api_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Portal integration not configured."
        )

    # Decode and validate Portal service token
    try:
        claims = decode_portal_token(payload.token, settings.portal_api_secret)
    except PortalTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc)
        ) from exc

    # Verify token is for this service
    expected_service = (settings.portal_service_id or "").strip().lower()
    if expected_service and claims.service and claims.service != expected_service:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Portal token issued for another service"
        )

    # Get or create AuthRecon profile for this Portal user
    # portal_user_id comes from Portal's JWT claims (user_id field)
    profile = sync_portal_profile(
        db,
        portal_user_id=claims.user_id,  # Use user_id from Portal token
        llm_enabled=False  # Default LLM disabled for new profiles
    )

    # Create AuthRecon access token
    # Store profile.id in token subject, plus admin flag and username from Portal
    is_admin = "admin" in claims.roles
    expires_minutes = settings.access_token_expire_minutes
    access_token = create_access_token(
        subject=profile.id,  # Store profile ID, not portal_user_id
        expires_minutes=expires_minutes,
        extra_claims={
            "is_admin": is_admin,
            "portal_user_id": profile.portal_user_id,
            "username": claims.username,  # Include username for display purposes
        },
    )

    # Remember the display name so API-key/MCP actions can be attributed to
    # this user (API keys carry no username of their own).
    if claims.username and profile.display_name != claims.username:
        profile.display_name = claims.username
    update_last_login(db, profile)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)

    return Token(access_token=access_token, expires_at=expires_at)


@router.get("/me")
async def get_me(current_profile: AuthReconProfile = Depends(get_current_profile)) -> dict:
    """
    Get current authenticated profile information.

    Returns AuthRecon-specific profile data. For full user identity (username, email, etc),
    frontend should query Portal API.

    Args:
        current_profile: Current authenticated profile from dependency

    Returns:
        dict: Profile information including portal_user_id reference
    """
    return {
        "id": current_profile.id,
        "portal_user_id": current_profile.portal_user_id,
        "llm_enabled": current_profile.llm_enabled,
        "created_at": current_profile.created_at.isoformat(),
        "last_login_at": current_profile.last_login_at.isoformat() if current_profile.last_login_at else None,
    }
