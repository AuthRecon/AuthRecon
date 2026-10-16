from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_credential_cipher
from app.models import AuditLog, StoredCredential, AuthReconProfile
from app.schemas.credential import CredentialCreate, CredentialUpdate


def list_credentials_for_user(db: Session, profile: AuthReconProfile) -> list[StoredCredential]:
    """List credentials accessible to this profile.

    Admins see all credentials; non-admins see only the ones they own.
    (profile.is_admin is populated from the Portal JWT claims by the API deps.)
    """
    stmt = (
        select(StoredCredential)
        .where(StoredCredential.is_archived.is_(False))
        .order_by(StoredCredential.created_at.desc())
    )
    # Non-admins only see their own credentials; admins see all.
    if not profile.is_admin:
        stmt = stmt.where(StoredCredential.owner_profile_id == profile.id)
    return db.scalars(stmt).all()


def get_credential(db: Session, credential_id: str) -> Optional[StoredCredential]:
    return db.get(StoredCredential, credential_id)


def _encrypt_secret(secret: str) -> str:
    cipher = get_credential_cipher()
    return cipher.encrypt(secret.encode("utf-8")).decode("utf-8")


def _decrypt_secret(secret_encrypted: str) -> str:
    cipher = get_credential_cipher()
    return cipher.decrypt(secret_encrypted.encode("utf-8")).decode("utf-8")


def create_credential(db: Session, *, owner: AuthReconProfile | None, payload: CredentialCreate) -> StoredCredential:
    credential = StoredCredential(
        name=payload.name,
        description=payload.description,
        auth_type=payload.auth_type,
        username=payload.username,
        secret_encrypted=_encrypt_secret(payload.secret),
        additional_fields=payload.additional_fields,
        allowed_domains=payload.allowed_domains,
        owner_profile_id=owner.id if owner else None,
    )
    db.add(credential)
    db.flush()

    _record_audit(
        db,
        actor=owner,
        credential=credential,
        action="create_credential",
        details={"name": credential.name, "auth_type": credential.auth_type},
    )
    db.commit()
    db.refresh(credential)
    return credential


def update_credential(db: Session, *, credential: StoredCredential, actor: AuthReconProfile | None, payload: CredentialUpdate) -> StoredCredential:
    changes: dict[str, str] = {}
    if payload.name is not None:
        credential.name = payload.name
        changes["name"] = payload.name
    if payload.description is not None:
        credential.description = payload.description
    if payload.auth_type is not None:
        credential.auth_type = payload.auth_type
        changes["auth_type"] = payload.auth_type
    if payload.username is not None:
        credential.username = payload.username
        changes["username"] = payload.username
    if payload.secret is not None:
        credential.secret_encrypted = _encrypt_secret(payload.secret)
        changes["secret"] = "***"
    if payload.additional_fields is not None:
        credential.additional_fields = payload.additional_fields
    if payload.allowed_domains is not None:
        credential.allowed_domains = payload.allowed_domains
        changes["allowed_domains"] = ", ".join(payload.allowed_domains) or "(unbound)"
    if payload.is_archived is not None:
        credential.is_archived = payload.is_archived
        changes["is_archived"] = str(payload.is_archived)

    db.add(credential)
    _record_audit(
        db,
        actor=actor,
        credential=credential,
        action="update_credential",
        details=changes,
    )
    db.commit()
    db.refresh(credential)
    return credential


def delete_credential(db: Session, *, credential: StoredCredential, actor: AuthReconProfile | None) -> None:
    _record_audit(
        db,
        actor=actor,
        credential=credential,
        action="delete_credential",
        details={"name": credential.name},
    )
    db.delete(credential)
    db.commit()


def get_plain_secret(credential: StoredCredential) -> str:
    return _decrypt_secret(credential.secret_encrypted)


def touch_usage(db: Session, credential: StoredCredential) -> None:
    credential.last_used_at = datetime.now(timezone.utc)
    db.add(credential)
    db.commit()


def _record_audit(db: Session, *, actor: AuthReconProfile | None, credential: StoredCredential | None, action: str, details: dict) -> None:
    entry = AuditLog(
        actor_profile_id=actor.id if actor else None,
        credential_id=credential.id if credential else None,
        entity_type="credential" if credential else "system",
        entity_id=credential.id if credential else None,
        action=action,
        details=details,
    )
    db.add(entry)
