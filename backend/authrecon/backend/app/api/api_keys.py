"""API Key management endpoints for CLI/programmatic authentication."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_profile
from app.core.security import (
    create_api_key_prefix,
    generate_api_key,
    hash_api_key,
)
from app.db import get_db
from app.models.api_key import APIKey
from app.models.profile import AuthReconProfile
from app.schemas.api_key import APIKeyCreate, APIKeyCreated, APIKeyRead, APIKeyRevoke

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


def _ensure_api_access_enabled(profile: AuthReconProfile, db: Session | None = None) -> None:
    """
    Verify that the profile has API access enabled.

    Admins always have it (granted on first use, so their keys authenticate);
    for everyone else an admin turns it on in Settings > AI & MCP.

    Raises:
        HTTPException: 403 if API access is not enabled for this profile
    """
    if not profile.api_access_enabled and getattr(profile, "is_admin", False) and db is not None:
        profile.api_access_enabled = True
        db.add(profile)
        db.commit()
    if not profile.api_access_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API access not enabled. Contact administrator to enable API access."
        )


def _ensure_owns_key(profile: AuthReconProfile, api_key: APIKey) -> None:
    """
    Verify that the profile owns the specified API key.

    Args:
        profile: Current authenticated profile
        api_key: API key to check ownership of

    Raises:
        HTTPException: 403 if profile doesn't own the key
    """
    if api_key.profile_id != profile.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this API key"
        )


@router.post("", response_model=APIKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: APIKeyCreate,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> APIKeyCreated:
    """
    Generate a new API key for CLI/programmatic authentication.

    **Security Requirements**:
    - User must have `api_access_enabled=True` (set by admin)
    - Key is shown ONCE at creation time - store it securely
    - Key is hashed with bcrypt before storage (like passwords)

    **Usage**:
    ```bash
    curl -H "X-API-Key: ak_live_xxxxx" http://api.example.com/api/v1/runs
    ```

    **Expiration**:
    - Default: Never expires (expires_days=null)
    - Custom: Set expires_days (1-365 days)

    Args:
        payload: API key creation parameters (name, optional expiration)
        db: Database session
        current_profile: Authenticated profile (from JWT or API key)

    Returns:
        APIKeyCreated: Contains plaintext key (ONLY shown once!)

    Raises:
        HTTPException: 403 if API access not enabled for this profile
    """
    # Check if user has API access enabled
    _ensure_api_access_enabled(current_profile, db)

    # Generate cryptographically secure API key
    plaintext_key = generate_api_key()

    # Hash the key (never store plaintext)
    key_hash = hash_api_key(plaintext_key)

    # Create display prefix for UI
    prefix = create_api_key_prefix(plaintext_key)

    # Calculate expiration if requested
    expires_at = None
    if payload.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_days)

    # Create API key record
    api_key = APIKey(
        id=str(uuid4()),
        profile_id=current_profile.id,
        name=payload.name,
        key_hash=key_hash,
        prefix=prefix,
        scope=payload.scope,
        is_revoked=False,
        expires_at=expires_at,
        created_at=datetime.now(timezone.utc),
    )

    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    # Return response with plaintext key (ONLY time it's shown)
    return APIKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key=plaintext_key,  # ONLY shown here!
        prefix=api_key.prefix,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        scope=api_key.scope,
    )


@router.get("", response_model=list[APIKeyRead])
async def list_api_keys(
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> list[APIKeyRead]:
    """
    List all API keys for the current user.

    Only returns keys owned by the authenticated profile.
    Plaintext keys are never returned (only shown once at creation).

    Args:
        db: Database session
        current_profile: Authenticated profile

    Returns:
        list[APIKeyRead]: List of API keys with metadata (no plaintext keys)

    Raises:
        HTTPException: 403 if API access not enabled for this profile
    """
    # Check if user has API access enabled
    _ensure_api_access_enabled(current_profile, db)

    # Get all keys for this profile
    api_keys = db.query(APIKey).filter(
        APIKey.profile_id == current_profile.id
    ).order_by(APIKey.created_at.desc()).all()

    return [APIKeyRead.model_validate(key) for key in api_keys]


@router.delete("/{key_id}", response_model=APIKeyRevoke)
async def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> APIKeyRevoke:
    """
    Revoke an API key (soft delete).

    Revoked keys can no longer be used for authentication.
    The key record remains in the database for audit purposes.

    Args:
        key_id: API key ID to revoke
        db: Database session
        current_profile: Authenticated profile

    Returns:
        APIKeyRevoke: Revoked key metadata

    Raises:
        HTTPException: 404 if key not found
        HTTPException: 403 if user doesn't own the key
        HTTPException: 403 if API access not enabled
    """
    # Check if user has API access enabled
    _ensure_api_access_enabled(current_profile, db)

    # Get the API key
    api_key = db.get(APIKey, key_id)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )

    # Verify ownership
    _ensure_owns_key(current_profile, api_key)

    # Revoke the key (soft delete)
    api_key.is_revoked = True
    api_key.revoked_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(api_key)

    return APIKeyRevoke.model_validate(api_key)
