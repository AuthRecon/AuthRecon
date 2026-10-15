"""Internal VNC session lookup endpoint — called by the portal WebSocket proxy only.

Validates the shared PORTAL_API_SECRET so this endpoint is never reachable by
regular clients (the portal calls it over the internal Docker network).
Returns the noVNC port for an active manual-recording run after verifying that
the requesting portal user owns the run (or is an admin).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db
from app.models.profile import AuthReconProfile
from app.models.run import Run

router = APIRouter()


@router.get("/internal/vnc/{run_id}")
def get_vnc_info(
    run_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    settings = get_settings()

    x_portal_secret = request.headers.get("X-Portal-Secret", "")
    x_portal_user_id = request.headers.get("X-Portal-User-Id", "")
    x_portal_is_admin = request.headers.get("X-Portal-Is-Admin", "false")

    # Check secret first — always 403, never leak header names via validation errors
    if not x_portal_secret or x_portal_secret != settings.portal_api_secret:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not x_portal_user_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    is_admin = x_portal_is_admin.lower() == "true"
    if not is_admin:
        profile = db.query(AuthReconProfile).filter(
            AuthReconProfile.portal_user_id == x_portal_user_id
        ).first()
        if not profile or run.submitted_by_profile_id != profile.id:
            raise HTTPException(status_code=403, detail="Access denied")

    if not run.vnc_port:
        raise HTTPException(status_code=404, detail="No active VNC session for this run")

    return {"vnc_port": run.vnc_port, "run_id": run_id}
