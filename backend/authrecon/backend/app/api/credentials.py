from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_profile
from app.db import get_db
from app.models import StoredCredential
from app.models.profile import AuthReconProfile
from app.schemas.credential import CredentialCreate, CredentialRead, CredentialUpdate
from app.services.credentials import (
    create_credential,
    delete_credential,
    get_credential,
    get_plain_secret,
    list_credentials_for_user,
    update_credential,
)

router = APIRouter(prefix="/credentials", tags=["credentials"])


def _ensure_can_access(profile: AuthReconProfile, credential: StoredCredential) -> None:
    if profile.is_admin:
        return
    if credential.owner_profile_id and credential.owner_profile_id == profile.id:
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")


@router.get("", response_model=list[CredentialRead])
async def list_credentials(
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> list[CredentialRead]:
    credentials = list_credentials_for_user(db, current_profile)
    return [CredentialRead.from_orm(item) for item in credentials]


@router.post("", response_model=CredentialRead, status_code=status.HTTP_201_CREATED)
async def create_stored_credential(
    payload: CredentialCreate,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> CredentialRead:
    credential = create_credential(db, owner=current_profile, payload=payload)
    return CredentialRead.from_orm(credential)


@router.patch("/{credential_id}", response_model=CredentialRead)
async def update_stored_credential(
    credential_id: str,
    payload: CredentialUpdate,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> CredentialRead:
    credential = get_credential(db, credential_id)
    if not credential:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    _ensure_can_access(current_profile, credential)

    updated = update_credential(db, credential=credential, actor=current_profile, payload=payload)
    return CredentialRead.from_orm(updated)


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_stored_credential(
    credential_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> Response:
    credential = get_credential(db, credential_id)
    if not credential:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    _ensure_can_access(current_profile, credential)
    delete_credential(db, credential=credential, actor=current_profile)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{credential_id}/reveal", response_model=dict)
async def reveal_secret(
    credential_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> dict[str, str]:
    credential = get_credential(db, credential_id)
    if not credential:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    _ensure_can_access(current_profile, credential)
    secret = get_plain_secret(credential)
    return {"secret": secret}
