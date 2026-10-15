"""AuthRecon profile service functions.

This module handles AuthRecon-specific user profiles that reference Portal users.
Profiles store ONLY service-specific data (artifact keys, LLM settings).
User identity remains in Portal database.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import decrypt_with_master, encrypt_with_master
from app.models.profile import AuthReconProfile


def get_profile_by_portal_user_id(db: Session, portal_user_id: str) -> Optional[AuthReconProfile]:
    """Get AuthRecon profile by Portal user ID."""
    return db.scalar(
        select(AuthReconProfile).where(AuthReconProfile.portal_user_id == portal_user_id)
    )


def sync_portal_profile(db: Session, portal_user_id: str, *, llm_enabled: bool = False) -> AuthReconProfile:
    """
    Ensure an AuthRecon profile exists for the given Portal user.

    This creates ONLY service-specific data. Identity fields remain in Portal.

    Args:
        db: Database session
        portal_user_id: Portal user ID (from Portal.PortalUser.id)
        llm_enabled: Whether to enable LLM features for this profile

    Returns:
        AuthReconProfile: The created or retrieved profile
    """
    profile = get_profile_by_portal_user_id(db, portal_user_id)

    if not profile:
        # Create new profile with encrypted artifact key
        artifact_key = Fernet.generate_key()
        encrypted_key = encrypt_with_master(artifact_key)

        profile = AuthReconProfile(
            portal_user_id=portal_user_id,
            artifact_key_encrypted=encrypted_key,
            llm_enabled=llm_enabled,
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile

    # Profile exists - just update last_login_at
    # Note: We don't sync identity fields anymore (they live in Portal)
    return profile


def update_last_login(db: Session, profile: AuthReconProfile) -> None:
    """Update profile's last login timestamp."""
    profile.last_login_at = datetime.now(timezone.utc)
    db.add(profile)
    db.commit()


def ensure_profile_artifact_key(db: Session, profile: AuthReconProfile) -> bytes:
    """
    Ensure the profile has an artifact encryption key provisioned and return the raw key bytes.

    Args:
        db: Database session
        profile: AuthReconProfile instance

    Returns:
        bytes: Raw artifact encryption key

    Raises:
        ValueError: If profile is None
    """
    if profile is None:
        raise ValueError("Profile is required to derive artifact key")

    if profile.artifact_key_encrypted:
        return decrypt_with_master(profile.artifact_key_encrypted)

    # Generate new key if missing
    key_bytes = Fernet.generate_key()
    profile.artifact_key_encrypted = encrypt_with_master(key_bytes)
    db.add(profile)
    db.flush()
    return key_bytes






def get_profile_artifact_cipher(db: Session, profile: AuthReconProfile) -> Fernet:
    """
    Convenience helper to retrieve a Fernet cipher bound to the profile's artifact key.

    Args:
        db: Database session
        profile: AuthReconProfile instance

    Returns:
        Fernet: Cipher for encrypting/decrypting artifacts

    Raises:
        ValueError: If profile is None
    """
    if profile is None:
        raise ValueError("Profile is required to obtain artifact cipher")

    key = ensure_profile_artifact_key(db, profile)
    return Fernet(key)
