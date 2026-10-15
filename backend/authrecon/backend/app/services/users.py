from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Sequence

from cryptography.fernet import Fernet
import secrets
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    decrypt_with_master,
    encrypt_with_master,
    hash_password,
    verify_password,
)
from app.models import AuthReconProfile
# Legacy User model removed - user identity now managed in Portal database
from app.schemas.user import UserCreate


# ============================================================================
# DEPRECATED FUNCTIONS - User management moved to Portal
# ============================================================================
# All functions below that reference "User" are deprecated.
# User identity is now managed exclusively in the Portal database.
# AuthRecon only stores lightweight profiles (AuthReconProfile).


def get_user_by_email(db: Session, email: str):
    """DEPRECATED: User management moved to Portal."""
    raise NotImplementedError("User management moved to Portal database")


def create_user(db: Session, payload: UserCreate):
    """DEPRECATED: User management moved to Portal."""
    raise NotImplementedError("User management moved to Portal database")


def authenticate_user(db: Session, email: str, password: str):
    """DEPRECATED: Authentication moved to Portal."""
    raise NotImplementedError("Authentication moved to Portal SSO")


def update_last_login(db: Session, user):
    """DEPRECATED: User management moved to Portal."""
    raise NotImplementedError("User management moved to Portal database")


def list_users(db: Session):
    """DEPRECATED: User management moved to Portal."""
    raise NotImplementedError("User management moved to Portal database")


def update_user(db: Session, user, **kwargs):
    """DEPRECATED: User management moved to Portal."""
    raise NotImplementedError("User management moved to Portal database")


def sync_portal_user(db: Session, username: str, *, is_admin: bool):
    """DEPRECATED: Replaced by sync_portal_profile in profiles.py."""
    raise NotImplementedError("Use sync_portal_profile from profiles.py instead")


# ============================================================================
# LEGACY ARTIFACT ENCRYPTION FUNCTIONS
# ============================================================================
# These functions are kept for backward compatibility with old encrypted artifacts.
# New code should use the equivalent functions in profiles.py


def ensure_user_artifact_key(db: Session, profile: AuthReconProfile) -> bytes:
    """
    Ensure the profile has an artifact encryption key provisioned and return the raw key bytes.

    NOTE: This is a legacy function kept for backward compatibility with encrypted artifacts.
    New code should use ensure_profile_artifact_key from profiles.py
    """
    if profile is None:
        raise ValueError("Profile is required to derive artifact key")

    if profile.artifact_key_encrypted:
        return decrypt_with_master(profile.artifact_key_encrypted)

    key_bytes = Fernet.generate_key()
    profile.artifact_key_encrypted = encrypt_with_master(key_bytes)
    db.add(profile)
    db.flush()
    return key_bytes


def get_user_artifact_cipher(db: Session, profile: AuthReconProfile) -> Fernet:
    """
    Convenience helper to retrieve a Fernet cipher bound to the profile's artifact key.

    NOTE: This is a legacy function kept for backward compatibility with encrypted artifacts.
    New code should use get_profile_artifact_cipher from profiles.py
    """
    if profile is None:
        raise ValueError("Profile is required to obtain artifact cipher")
    key = ensure_user_artifact_key(db, profile)
    return Fernet(key)
