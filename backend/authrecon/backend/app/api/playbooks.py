"""
Playbook (TenantPlaybook) management — view and clear learned auth patterns.

Addresses a real gap: there was previously no way to view, edit, or reset
playbooks short of a direct database query. This matters in practice — a
playbook learned from one page on a domain can get reused against a
completely different, unrelated page on that same domain (playbooks are
keyed by domain + auth_type, not full path), producing a confusing stuck
failure with no way to clear it except manual DB access. These endpoints
are that escape hatch.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_profile
from app.db import get_db
from app.models.playbook import TenantPlaybook
from app.models.profile import AuthReconProfile

router = APIRouter()


class PlaybookRead(BaseModel):
    id: str
    domain: str
    auth_type: str
    confidence_score: int
    success_count: int
    failure_count: int
    created_at: str | None = None
    last_successful_at: str | None = None
    last_validated_at: str | None = None


class PlaybookDeleteResult(BaseModel):
    deleted_count: int


def _playbook_query(db: Session, current_profile: AuthReconProfile):
    stmt = select(TenantPlaybook)
    if not current_profile.is_admin:
        stmt = stmt.where(TenantPlaybook.profile_id == current_profile.id)
    return stmt


@router.get("", response_model=list[PlaybookRead])
async def list_playbooks(
    domain: str | None = Query(default=None, description="Filter to a specific domain"),
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> list[PlaybookRead]:
    stmt = _playbook_query(db, current_profile)
    if domain:
        stmt = stmt.where(TenantPlaybook.domain == domain)
    stmt = stmt.order_by(TenantPlaybook.created_at.desc())
    rows = db.scalars(stmt).all()
    return [
        PlaybookRead(
            id=row.id,
            domain=row.domain,
            auth_type=row.auth_type,
            confidence_score=row.confidence_score,
            success_count=row.success_count,
            failure_count=row.failure_count,
            created_at=row.created_at.isoformat() if row.created_at else None,
            last_successful_at=row.last_successful_at.isoformat() if row.last_successful_at else None,
            last_validated_at=row.last_validated_at.isoformat() if row.last_validated_at else None,
        )
        for row in rows
    ]


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> Response:
    playbook = db.get(TenantPlaybook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    if not current_profile.is_admin and playbook.profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")
    db.delete(playbook)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("", response_model=PlaybookDeleteResult)
async def delete_playbooks_by_domain(
    domain: str = Query(..., description="Clear all playbooks for this domain (required — no bulk-delete-everything footgun)"),
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> PlaybookDeleteResult:
    stmt = _playbook_query(db, current_profile).where(TenantPlaybook.domain == domain)
    rows = db.scalars(stmt).all()
    count = len(rows)
    for row in rows:
        db.delete(row)
    db.commit()
    return PlaybookDeleteResult(deleted_count=count)
