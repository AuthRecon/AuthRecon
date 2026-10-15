"""Security notice shown to every user after login, again every
``REMIND_AFTER_DAYS``, and immediately when ``NOTICE_VERSION`` is bumped
(change the version whenever the notice text changes materially).

The text itself lives in the frontend (src/components/SecurityNotice.jsx);
this module only tracks who acknowledged which version, and when.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

import audit
from auth import SessionUser, get_current_user_from_token
from database import get_session
from models.security_notice import SecurityNoticeAck

NOTICE_VERSION = 1
REMIND_AFTER_DAYS = 7

router = APIRouter()


def notice_status(user_id: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    with get_session() as session:
        ack = session.get(SecurityNoticeAck, user_id)
        acked_at = ack.acknowledged_at if ack else None
        version = ack.notice_version if ack else None
    if acked_at is not None and acked_at.tzinfo is None:
        acked_at = acked_at.replace(tzinfo=timezone.utc)  # SQLite drops tzinfo
    due = (
        acked_at is None
        or version != NOTICE_VERSION
        or now - acked_at >= timedelta(days=REMIND_AFTER_DAYS)
    )
    return {
        "version": NOTICE_VERSION,
        "remind_after_days": REMIND_AFTER_DAYS,
        "acknowledged_at": acked_at.isoformat() if acked_at else None,
        "required": due,
    }


@router.get("/security-notice")
async def get_security_notice(user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    if not user.user_id:
        raise HTTPException(status_code=401, detail="Invalid session")
    return notice_status(user.user_id)


@router.post("/security-notice/ack")
async def acknowledge_security_notice(
    request: Request, user: SessionUser = Depends(get_current_user_from_token)
) -> dict:
    if not user.user_id:
        raise HTTPException(status_code=401, detail="Invalid session")
    now = datetime.now(timezone.utc)
    with get_session() as session:
        ack = session.get(SecurityNoticeAck, user.user_id)
        if ack is None:
            ack = SecurityNoticeAck(user_id=user.user_id, notice_version=NOTICE_VERSION, acknowledged_at=now)
            session.add(ack)
        else:
            ack.notice_version, ack.acknowledged_at = NOTICE_VERSION, now
        session.commit()
    audit.emit(audit.SECURITY_NOTICE_ACKNOWLEDGED, actor_username=user.username,
               actor_ip=request.client.host if request.client else None, detail=f"version {NOTICE_VERSION}")
    return notice_status(user.user_id, now)
