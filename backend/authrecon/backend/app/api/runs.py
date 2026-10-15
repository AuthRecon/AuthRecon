import logging
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4
from collections import defaultdict
import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_profile
from app.core.security import get_credential_cipher
from app.db import get_db
from app.models import Run, TimelineEvent, StoredCredential
from app.models.profile import AuthReconProfile
from app.services.profiles import get_profile_artifact_cipher
from app.services.artifact_crypto import decrypt_run_cookies
from app.services.was_setup import build_failure_guidance, build_was_setup, run_warnings
from app.schemas.run import (
    AuthDetectionInfo,
    RunSubmission,
    RunDetail,
    RunSummary,
    RunStatus,
    TimelineEntry,
    TechFingerprint,
    RunRoleSummary,
)
from app.schemas.credential import CredentialCreate
from app.schemas.types import HttpUrlStr
from app.services.auth_detection import detect_auth_type
from app.services.credentials import create_credential, get_credential, touch_usage
from app.services.queue import get_queue
from app.services.storage import get_artifact_storage

router = APIRouter()
logger = logging.getLogger(__name__)


def _run_session_cookies(db: Session, run: Run) -> list:
    """Captured cookies for the run-detail response (caller already checked
    owner-or-admin). Falls back to the legacy plaintext column for old runs."""
    if run.session_cookies_enc:
        try:
            return decrypt_run_cookies(db, run)
        except Exception:
            logger.warning("Could not decrypt session cookies for run %s", run.id)
            return []
    return run.session_cookies or []


def _normalize_session_cookies(raw: Any) -> list[dict]:
    if not raw:
        return []
    normalized: list[dict] = []
    for cookie in raw:
        if isinstance(cookie, dict):
            normalized.append(cookie)
        elif isinstance(cookie, str):
            normalized.append({"name": cookie})
    return normalized


def _cookie_cipher(db: Session, run: Run):
    """Owner's profile key, or the master key for runs with no owner (see worker)."""
    if run.submitted_by is not None:
        return get_profile_artifact_cipher(db, run.submitted_by)
    return get_credential_cipher()


def _decrypt_security_context_cookies(security_context_dict: dict, db: Session, run: Run) -> None:
    """
    Decrypt all cookie values in-place within security_context dict using the run's cookie cipher.
    Cookies are stored encrypted in the database, this decrypts them for API responses.
    """
    if not security_context_dict:
        return

    cookies_analysis = security_context_dict.get("cookies")
    if not cookies_analysis or not isinstance(cookies_analysis, dict):
        return

    cookies_list = cookies_analysis.get("cookies")
    if not cookies_list or not isinstance(cookies_list, list):
        return

    try:
        cipher = _cookie_cipher(db, run)
        for cookie in cookies_list:
            if not isinstance(cookie, dict):
                continue

            # Get encrypted value from value_encrypted field
            encrypted_value = cookie.get("value_encrypted")
            if encrypted_value and isinstance(encrypted_value, str):
                # Decrypt the value using Fernet cipher
                try:
                    decrypted_bytes = cipher.decrypt(encrypted_value.encode("utf-8"))
                    # Store as plaintext string for API response
                    cookie["value_encrypted"] = decrypted_bytes.decode("utf-8")
                except Exception:
                    # If decryption fails, leave as-is (might be legacy plaintext)
                    logger.debug("Failed to decrypt cookie value, leaving as-is")
    except Exception as e:
        logger.warning(f"Failed to get cipher for cookie decryption: {e}")


def _submission_channel(profile: AuthReconProfile, client: str | None) -> str | None:
    """How a run was submitted, when not from the web UI. The client header is
    informational only (set by the AuthRecon MCP server); identity comes from
    the authenticated key."""
    if getattr(profile, "auth_method", None) != "api_key":
        return None
    return "MCP" if (client or "").strip().lower() == "mcp" else "API key"


def _submitted_by(profile: AuthReconProfile, channel: str | None) -> str:
    return f"{profile.username} (via {channel})" if channel else profile.username


def _ensure_credential_access(profile: AuthReconProfile, credential: StoredCredential) -> None:
    """Check if profile can access credential (admin bypass or owner check)."""
    if profile.is_admin:
        return
    if credential.owner_profile_id and credential.owner_profile_id == profile.id:
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted to use credential")


def _run_to_summary(run: Run) -> RunSummary:
    options = run.options if isinstance(run.options, dict) else {}
    return RunSummary(
        id=run.id,
        status=run.status,
        target_url=run.target_url,
        submitted_at=run.submitted_at,
        auth_type=run.auth_type,
        operator=run.operator,
        ai_assisted=bool(options.get("ai_suggestions")),
        warnings=run_warnings(run),
    )


def _run_to_detail(run: Run, db: Session) -> RunDetail:
    duration = None
    if run.started_at and run.finished_at:
        duration = int((run.finished_at - run.started_at).total_seconds())

    timeline = [
        TimelineEntry(occurred_at=event.occurred_at, message=event.message)
        for event in run.timeline_events
    ]

    detected_info = None
    if isinstance(run.options, dict):
        raw_detected = run.options.get("detected_auth")
        if isinstance(raw_detected, dict):
            detected_info = AuthDetectionInfo(
                auth_type=str(raw_detected.get("auth_type") or ""),
                evidence=raw_detected.get("evidence"),
                pre_login_url=raw_detected.get("final_url"),
                error=raw_detected.get("error"),
                signals=raw_detected.get("signals") or [],
                redirect_chain=raw_detected.get("redirect_chain") or [],
                probed_urls=raw_detected.get("probed_urls") or [],
            )
            if not detected_info.auth_type:
                detected_info.auth_type = run.auth_type

    fingerprint = None
    js_frameworks: list[str] = []
    if isinstance(run.tech_fingerprint, dict) and run.tech_fingerprint:
        try:
            fingerprint = TechFingerprint.model_validate(run.tech_fingerprint)
            js_frameworks = list(fingerprint.js_frameworks)
        except Exception:  # pragma: no cover - defensive parsing
            logger.debug("Failed to parse tech fingerprint for run %s", run.id, exc_info=True)
            fingerprint = None
            js_frameworks = []

    role_scope = None
    if isinstance(run.options, dict):
        raw_scope = run.options.get("scope")
        if isinstance(raw_scope, dict) and raw_scope.get("roles"):
            role_scope = {
                "roles": raw_scope.get("roles")
            }

    role_stats = _artifact_stats_by_role(run)
    roles = _build_role_summaries(run, role_stats)

    # Parse security_context from JSONB
    security_context = None
    if run.security_context and isinstance(run.security_context, dict):
        try:
            from app.schemas.security_context import SecurityContext
            # Decrypt cookie values for the owner's response only. Work on a copy:
            # decrypting in place would leave plaintext on the ORM object, where
            # any later commit could write it back to the database.
            context_copy = deepcopy(run.security_context)
            _decrypt_security_context_cookies(context_copy, db, run)
            security_context = SecurityContext.model_validate(context_copy)
        except Exception:
            logger.debug("Failed to parse security_context for run %s", run.id, exc_info=True)
            security_context = None

    return RunDetail(
        **_run_to_summary(run).model_dump(),
        started_at=run.started_at,
        finished_at=run.finished_at,
        duration_seconds=duration,
        final_url=run.final_url,
        pattern=run.pattern,
        llm_pattern=run.llm_pattern,
        session_cookies=_normalize_session_cookies(_run_session_cookies(db, run)),
        js_frameworks=js_frameworks,
        tech_fingerprint=fingerprint,
        security_context=security_context,
        timeline=timeline,
        detected_auth=detected_info,
        role_scope=role_scope,
        ai_suggestions=(run.options or {}).get("ai_suggestions", []) if isinstance(run.options, dict) else [],
        roles=roles,
        error_message=run.error_message,
        flow_summary=run.flow_summary,
        streaming_enabled=run.streaming_enabled,
        vnc_port=run.vnc_port,
        was_setup=build_was_setup(run),
        failure=build_failure_guidance(run),
    )


def _artifact_stats_by_role(run: Run) -> dict[str | None, dict]:
    stats: dict[str | None, dict] = {}
    artifacts = list(getattr(run, "artifacts", []) or [])
    for artifact in artifacts:
        slug = artifact.role_slug
        bucket = stats.setdefault(
            slug,
            {
                "total": 0,
                "screenshots": 0,
                "by_type": defaultdict(int),
            },
        )
        artifact_type = (artifact.type or "artifact").lower()
        bucket["total"] += 1
        bucket["by_type"][artifact_type] += 1
        if artifact_type == "screenshot":
            bucket["screenshots"] += 1

    normalized: dict[str | None, dict] = {}
    for slug, data in stats.items():
        normalized[slug] = {
            "total": data["total"],
            "screenshots": data["screenshots"],
            "by_type": dict(data["by_type"]),
        }
    return normalized


def _build_role_summaries(run: Run, stats: dict[str | None, dict]) -> list[RunRoleSummary]:
    options = run.options if isinstance(run.options, dict) else {}
    raw_scope = options.get("scope") if isinstance(options, dict) else {}
    raw_roles = raw_scope.get("roles") if isinstance(raw_scope, dict) else None
    if not isinstance(raw_roles, list) or not raw_roles:
        return []

    summaries: list[RunRoleSummary] = []
    for index, entry in enumerate(raw_roles):
        if not isinstance(entry, dict):
            continue
        slug = str(entry.get("slug") or "").strip()
        if not slug:
            slug = _slugify_role(entry.get("label") or entry.get("username") or f"role-{index + 1}", index + 1)
        tag_values = entry.get("tags") if isinstance(entry.get("tags"), list) else []
        tag_strings = [str(tag) for tag in tag_values if isinstance(tag, (str, int))]
        role_stats = stats.get(slug) or {"total": 0, "screenshots": 0, "by_type": {}}
        summaries.append(
            RunRoleSummary(
                slug=slug,
                label=entry.get("label") or entry.get("username") or f"Role {index + 1}",
                username=entry.get("username"),
                status=entry.get("status"),
                final_url=entry.get("final_url"),
                auth_type=entry.get("auth_type") or run.auth_type,
                tags=tag_strings,
                artifact_count=role_stats.get("total", 0),
                screenshot_count=role_stats.get("screenshots", 0),
                artifact_types=role_stats.get("by_type", {}),
                error=entry.get("error"),
            )
        )
    return summaries


def _slugify_role(value: str | None, index: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", (value or "").strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or f"role-{index:02d}"

def _get_run_for_user(run_id: str, db: Session, current_profile: AuthReconProfile) -> Run:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")
    return run


class DetectRequest(BaseModel):
    target_url: HttpUrlStr
    login_hint: str | None = None


@router.post("/detect", summary="Detect a target's login type without logging in")
async def detect_login(
    payload: DetectRequest,
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> dict:
    """Load the page (no credentials are sent) and report what kind of login it
    uses and how the scanner would authenticate. Same probing a run does first."""
    from app.services.was_setup import _HTTP_CHALLENGE

    detection = await run_in_threadpool(
        detect_auth_type, str(payload.target_url), login_hint=payload.login_hint, use_browser=True
    )
    info = detection.to_dict()
    auth_type = info.get("auth_type") or "generic"
    return {
        "target_url": str(payload.target_url),
        "auth_type": auth_type,
        "confidence": info.get("confidence"),
        "evidence": info.get("evidence"),
        "final_url": info.get("final_url"),
        "scanner_method": "http_auth" if auth_type in _HTTP_CHALLENGE else "selenium",
        "error": info.get("error"),
    }


@router.post(
    "",
    response_model=RunSummary,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a new reconnaissance run"
)
async def submit_run(
    payload: RunSubmission,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
    client: str | None = Header(None, alias="X-AuthRecon-Client"),
) -> RunSummary:
    run_id = f"RUN-{uuid4().hex[:8].upper()}"
    submitted_at = datetime.now(timezone.utc)
    channel = _submission_channel(current_profile, client)

    options = dict(payload.options)
    if channel:
        options["submitted_via"] = channel
    credential: StoredCredential | None = None
    target_url = str(payload.target_url)

    # Check if this is a manual recording session
    is_manual_mode = payload.recording_mode == "manual"

    # Skip auth detection for manual mode (operator will log in manually)
    if is_manual_mode:
        auth_type = "manual_recording"
        options["recording_mode"] = "manual"
    else:
        # Enable browser-based detection for SPAs (JavaScript-rendered forms)
        # Detection can launch a browser and take tens of seconds: run it in a
        # worker thread so the API keeps serving other requests meanwhile.
        detection = await run_in_threadpool(
            detect_auth_type, target_url, login_hint=payload.login_hint, use_browser=True
        )
        auth_type = detection.auth_type or "generic"
        options["detected_auth"] = detection.to_dict()

    # Skip credential processing for manual mode
    if not is_manual_mode:
        forced_auth_type = (payload.auth_type or "").strip().lower()
        if forced_auth_type:
            options["forced_auth_type"] = forced_auth_type
            options["detected_auth"]["forced"] = forced_auth_type
            auth_type = forced_auth_type

        # Store login_hint if provided
        if payload.login_hint:
            options["login_hint"] = payload.login_hint.strip()

        # Store domain_prefix if provided
        if payload.domain_prefix:
            options["domain_prefix"] = payload.domain_prefix.strip()

        # Store selected engines (default: selenium only)
        if payload.engines:
            options["engines"] = payload.engines
        else:
            options["engines"] = ["selenium"]

    scope = options.setdefault("scope", {})
    roles_payload: list[dict[str, str]] = []

    # Process credentials only for automated mode
    if not is_manual_mode and payload.credential_id:
        credential = get_credential(db, payload.credential_id)
        if not credential or credential.is_archived:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not available")
        _ensure_credential_access(current_profile, credential)
        options["credential_id"] = credential.id
        options["username"] = credential.username
        if auth_type in ("unknown", "generic") and credential.auth_type:
            auth_type = credential.auth_type
        touch_usage(db, credential)
    elif not is_manual_mode and payload.roles:
        cipher = get_credential_cipher()
        for index, role in enumerate(payload.roles, start=1):
            role_username = (role.get("username") or "").strip()
            role_password = (role.get("password") or "").strip()
            if not role_username or not role_password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role entry {index} requires both username and password.",
                )
            roles_payload.append(
                {
                    "label": role.get("label") or f"Role {index}",
                    "username": role_username,
                    "secret": cipher.encrypt(role_password.encode("utf-8")).decode("utf-8"),
                    "auth_type": role.get("auth_type") or auth_type,
                    "tags": role.get("tags") or [],
                }
            )
        scope["roles"] = roles_payload
    elif not is_manual_mode:
        username = payload.username or ""
        options["username"] = username
        if payload.save_credential_name:
            cred_payload = CredentialCreate(
                name=payload.save_credential_name,
                description=f"Saved during run {run_id}",
                auth_type=auth_type if auth_type not in ("unknown", None) else "generic",
                username=username,
                secret=payload.password or "",
                additional_fields={},
            )
            credential = create_credential(db, owner=current_profile, payload=cred_payload)
            options["credential_id"] = credential.id
            if auth_type in ("unknown", "generic"):
                auth_type = credential.auth_type
        else:
            cipher = get_credential_cipher()
            options["one_time_secret"] = cipher.encrypt((payload.password or "").encode("utf-8")).decode("utf-8")

    # Create run with appropriate status
    run = Run(
        id=run_id,
        status=RunStatus.manual_recording if is_manual_mode else RunStatus.queued,
        target_url=target_url,
        submitted_at=submitted_at,
        operator=current_profile.username,  # Username from Portal (via JWT)
        auth_type=auth_type,
        submitted_by_profile_id=current_profile.id,
        streaming_enabled=payload.streaming_enabled,
        options=options,
    )
    db.add(run)

    # Add timeline event
    if is_manual_mode:
        db.add(
            TimelineEvent(
                run=run,
                occurred_at=submitted_at,
                message=f"Manual recording session started by {_submitted_by(current_profile, channel)}",
            )
        )
    else:
        db.add(
            TimelineEvent(
                run=run,
                occurred_at=submitted_at,
                message=f"Run submitted by {_submitted_by(current_profile, channel)}",
            )
        )

    db.commit()
    db.refresh(run)

    # Queue to worker only for automated mode
    if not is_manual_mode:
        queue = get_queue()
        queue.enqueue("app.worker.process_run", run.id, job_timeout=1800)

    return _run_to_summary(run)


@router.get(
    "",
    response_model=list[RunSummary],
    summary="List recent runs"
)
async def list_runs(
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> list[RunSummary]:
    stmt = select(Run).order_by(Run.submitted_at.desc())
    if not current_profile.is_admin:
        stmt = stmt.where(Run.submitted_by_profile_id == current_profile.id)
    runs = db.scalars(stmt).all()
    return [_run_to_summary(run) for run in runs]


@router.get(
    "/{run_id}",
    response_model=RunDetail,
    summary="Get run details"
)
async def get_run(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> RunDetail:
    run = _get_run_for_user(run_id, db, current_profile)
    return _run_to_detail(run, db)


@router.get(
    "/{run_id}/events",
    summary="Stream timeline events (SSE placeholder)",
)
async def stream_run_events(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> StreamingResponse:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if not current_profile.is_admin and run.submitted_by_profile_id != current_profile.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not permitted")

    async def event_generator():
        for event in run.timeline_events:
            data = f"data: {event.occurred_at.isoformat()} - {event.message}\n\n"
            yield data.encode("utf-8")

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post(
    "/{run_id}/cancel",
    response_model=RunSummary,
    summary="Cancel a running reconnaissance job",
)
async def cancel_run(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> RunSummary:
    run = _get_run_for_user(run_id, db, current_profile)
    if run.status in (RunStatus.succeeded, RunStatus.failed, RunStatus.passed):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Run already finished.")

    now = datetime.now(timezone.utc)
    run.status = RunStatus.failed
    run.finished_at = now
    if not run.pattern:
        run.pattern = "Run cancelled by operator"
    db.add(
        TimelineEvent(
            run=run,
            occurred_at=now,
            message=f"Run cancelled by {current_profile.username}",
        )
    )
    db.commit()
    db.refresh(run)
    return _run_to_summary(run)


@router.post(
    "/{run_id}/rerun",
    response_model=RunSummary,
    summary="Re-run a test with same configuration",
    description="Creates a new run using the same configuration (target URL, credentials, auth type, options) as the specified run.",
)
async def rerun_test(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
    client: str | None = Header(None, alias="X-AuthRecon-Client"),
) -> RunSummary:
    """Re-run an existing test with the same configuration."""
    # Get the original run
    original_run = _get_run_for_user(run_id, db, current_profile)

    # Extract configuration from original run
    target_url = original_run.target_url
    auth_type = original_run.auth_type
    options = dict(original_run.options or {})

    # Create new run ID
    new_run_id = f"RUN-{uuid4().hex[:8].upper()}"
    submitted_at = datetime.now(timezone.utc)

    # Get credential or role info from original run
    credential_id = options.get("credential_id")
    scope = options.get("scope", {})
    roles_payload = scope.get("roles", [])

    # Create new run
    new_run = Run(
        id=new_run_id,
        target_url=target_url,
        auth_type=auth_type,
        status=RunStatus.queued,
        submitted_at=submitted_at,
        submitted_by=current_profile,
        operator=current_profile.username,
        options=options,
    )
    channel = _submission_channel(current_profile, client)
    if channel:
        options["submitted_via"] = channel
    else:
        options.pop("submitted_via", None)

    db.add(new_run)
    db.add(
        TimelineEvent(
            run=new_run,
            occurred_at=submitted_at,
            message=f"Re-run of {run_id} submitted by {_submitted_by(current_profile, channel)}",
        )
    )
    db.commit()
    db.refresh(new_run)

    # Enqueue worker job (same as submit_run)
    from app.services.queue import get_queue
    queue = get_queue()
    queue.enqueue("app.worker.process_run", new_run.id, job_timeout=1800)

    return _run_to_summary(new_run)


@router.delete(
    "/{run_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a recon run and associated artifacts",
)
async def delete_run(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> None:
    run = _get_run_for_user(run_id, db, current_profile)
    storage = get_artifact_storage()
    try:
        storage.delete_run(run.id)
    except Exception:  # pragma: no cover - best effort cleanup
        logger.debug("Failed to remove artifact storage for run %s", run.id, exc_info=True)
    db.delete(run)
    db.commit()


@router.post(
    "/{run_id}/duplicate",
    response_model=RunSummary,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Duplicate a run submission",
)
async def duplicate_run(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> RunSummary:
    source = _get_run_for_user(run_id, db, current_profile)
    new_run_id = f"RUN-{uuid4().hex[:8].upper()}"
    submitted_at = datetime.now(timezone.utc)
    options = deepcopy(source.options) if isinstance(source.options, dict) else {}

    run = Run(
        id=new_run_id,
        status=RunStatus.queued,
        target_url=source.target_url,
        submitted_at=submitted_at,
        operator=current_profile.username,  # Username from Portal (via JWT)
        auth_type=source.auth_type,
        submitted_by_profile_id=current_profile.id,
        options=options,
    )
    db.add(run)
    db.add(
        TimelineEvent(
            run=run,
            occurred_at=submitted_at,
            message=f"Run duplicated from {source.id} by {current_profile.username}",
        )
    )
    db.commit()
    db.refresh(run)

    queue = get_queue()
    queue.enqueue("app.worker.process_run", run.id, job_timeout=1800)
    return _run_to_summary(run)


@router.post(
    "/{run_id}/start-manual-session",
    summary="Start manual recording browser session"
)
async def start_manual_session(
    run_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
):
    """
    Launch a browser session for manual recording.
    Operator controls the browser via VNC to log in manually.
    """
    run = _get_run_for_user(run_id, db, current_profile)
    
    # Verify run is in manual_recording status
    if run.status != RunStatus.manual_recording:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Run must be in manual_recording status (current: {run.status})"
        )
    
    # Queue browser launch job to worker (which has VNC running)
    queue = get_queue()
    queue.enqueue(
        "app.worker.process_manual_session",
        run_id,
        run.target_url,
        job_timeout=3600,  # 1 hour max
        job_id=f"manual-session-{run_id}",
    )

    # Add timeline event
    db.add(
        TimelineEvent(
            run=run,
            occurred_at=datetime.now(timezone.utc),
            message="Manual browser session started - operator can now log in via VNC",
        )
    )
    db.commit()
    
    return {
        "success": True,
        "message": "Manual browser session starting",
        "target_url": run.target_url,
    }


@router.post(
    "/{run_id}/end-manual-session",
    summary="End manual recording session and extract artifacts"
)
async def end_manual_session(
    run_id: str,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
):
    """
    End the manual recording session, close browser, and extract artifacts.
    """
    run = _get_run_for_user(run_id, db, current_profile)

    # Worker polls database for status change, no in-memory tracking needed

    # Add timeline event
    db.add(
        TimelineEvent(
            run=run,
            occurred_at=datetime.now(timezone.utc),
            message="Manual session ended by operator",
        )
    )
    
    # Update run status
    run.status = RunStatus.succeeded
    run.finished_at = datetime.now(timezone.utc)
    db.commit()
    
    return {
        "success": True,
        "message": "Manual session ended",
        "artifacts_extracted": False,  # Will be True once we implement extraction
    }
