"""
Read/write surface for AI-assisted auth-flow analysis — see SECURITY.md.

This is the only place in the API that hands page content to a caller in a
form meant for a model to read. Everything returned here has already passed
through sanitize_html_for_llm(). Nothing here ever returns a credential
value, a username, or session cookies — see the field allow-lists below.

Two endpoints:
- GET  /runs/{run_id}/ai-context     — sanitized pre/post-auth HTML for a
  run the rule-based pattern library struggled with, plus what's already
  known about the detected auth flow.
- POST /runs/{run_id}/ai-suggestion  — records a suggestion (selectors,
  auth type, confidence, reasoning) against the run for audit/review. This
  does NOT automatically retry the run with those selectors — the
  deterministic worker doesn't yet consume this data. Recording it here is
  the first step; wiring it into the worker's retry path is a separate,
  deliberately-not-rushed piece of work.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.artifacts import _read_artifact_bytes
from app.api.deps import get_current_active_profile
from app.db import get_db
from app.models import Artifact as ArtifactModel, Run
from app.models.profile import AuthReconProfile
from app.services.automation.ai_fallback.sanitize import sanitize_html_for_llm
from app.services.storage import get_artifact_storage

router = APIRouter()


class RoleHtmlContext(BaseModel):
    role_slug: str | None = None
    role_label: str | None = None
    pre_auth_html: str | None = None
    post_auth_html: str | None = None


class AIRunContext(BaseModel):
    run_id: str
    status: str
    target_url: str
    detected_auth_type: str | None = None
    pattern: str | None = None
    error_message: str | None = None
    prior_suggestions: list[dict] = Field(default_factory=list)
    roles: list[RoleHtmlContext] = Field(default_factory=list)


class AuthSuggestionIn(BaseModel):
    auth_type: str
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class AuthSuggestionOut(BaseModel):
    recorded: bool
    total_suggestions_for_run: int
    note: str = (
        "Recorded against this run. It will NOT retry automatically — "
        "trigger POST /runs/{run_id}/rerun (or submit a fresh run against "
        "the same target) and the worker will try these selectors as a "
        "last resort if heuristic detection and any existing playbook "
        "both fail again, for form-based auth only."
    )


def _get_owned_run(run_id: str, db: Session, current_profile: AuthReconProfile) -> Run:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")
    return run


@router.get(
    "/{run_id}/ai-context",
    response_model=AIRunContext,
    summary="Get sanitized auth-flow context for AI-assisted analysis",
)
async def get_ai_context(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> AIRunContext:
    run = _get_owned_run(run_id, db, current_profile)

    html_artifacts = db.scalars(
        select(ArtifactModel).where(
            ArtifactModel.run_id == run_id,
            ArtifactModel.type == "html",
        )
    ).all()

    storage = get_artifact_storage()
    roles: dict[str, RoleHtmlContext] = {}
    for artifact in html_artifacts:
        name = artifact.name or ""
        if "pre_auth" not in name and "post_auth" not in name:
            continue
        try:
            payload, _ = _read_artifact_bytes(db, run, artifact, storage)
        except (FileNotFoundError, HTTPException):
            continue

        sanitized = sanitize_html_for_llm(payload.decode("utf-8", errors="replace"))
        role_key = artifact.role_slug or "default"
        ctx = roles.setdefault(
            role_key,
            RoleHtmlContext(role_slug=artifact.role_slug, role_label=artifact.role_slug),
        )
        if "pre_auth" in name:
            ctx.pre_auth_html = sanitized
        else:
            ctx.post_auth_html = sanitized

    options = run.options or {}
    return AIRunContext(
        run_id=run.id,
        status=run.status.value if hasattr(run.status, "value") else str(run.status),
        target_url=run.target_url,
        detected_auth_type=run.auth_type,
        pattern=run.pattern,
        error_message=run.error_message,
        prior_suggestions=options.get("ai_suggestions", []),
        roles=list(roles.values()),
    )


@router.post(
    "/{run_id}/ai-suggestion",
    response_model=AuthSuggestionOut,
    summary="Record an AI-suggested auth pattern for a run",
)
async def submit_ai_suggestion(
    run_id: str,
    suggestion: AuthSuggestionIn,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> AuthSuggestionOut:
    run = _get_owned_run(run_id, db, current_profile)

    options = dict(run.options or {})
    suggestions = list(options.get("ai_suggestions", []))
    suggestions.append(
        {
            **suggestion.model_dump(),
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "submitted_by_profile_id": current_profile.id,
        }
    )
    options["ai_suggestions"] = suggestions
    run.options = options
    db.add(run)
    db.commit()

    return AuthSuggestionOut(recorded=True, total_suggestions_for_run=len(suggestions))
