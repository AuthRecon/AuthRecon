"""AI & MCP: how an external AI client connects to AuthRecon.

AuthRecon does not run or call an LLM itself. AI comes in one way only: an MCP
client (Claude Desktop, Claude Code, ...) connects to the AuthRecon MCP server
through the portal (/apps/authrecon/mcp) and calls its allow-listed tools. See
SECURITY.md.

Each MCP client authenticates with its user's own AuthRecon API key, so the AI
acts as that user and sees only that user's data. There is no shared MCP
secret. The MCP server holds no credentials: it asks ``/ai/mcp-gate`` whether
the caller's key is valid and MCP is enabled, then makes every tool call with
the caller's key.

This router holds:
- the admin on/off switch for MCP (instance-wide, stored in app_settings)
- which users may create API/MCP keys (AuthReconProfile.api_access_enabled)
- the per-user "use AI login suggestions" preference (AuthReconProfile.llm_enabled)
- status for the Settings > AI & MCP page
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_profile, get_current_admin, resolve_api_key
from app.db import get_db
from app.models.api_key import APIKey
from app.models.app_setting import MCP_ENABLED, get_setting, set_setting
from app.models.profile import AuthReconProfile
from app.services.profiles import sync_portal_profile

router = APIRouter(prefix="/ai", tags=["ai"])

# Path clients use, relative to the portal's public URL.
MCP_PORTAL_PATH = "/apps/authrecon/mcp"


class ApiKeySummary(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    last_mcp_used_at: datetime | None = None


class AiStatus(BaseModel):
    mcp_enabled: bool
    mcp_path: str
    is_admin: bool
    api_access: bool
    use_ai_suggestions: bool
    api_keys: list[ApiKeySummary]
    last_client_activity: datetime | None = None


class AiPreferences(BaseModel):
    use_ai_suggestions: bool


class McpToggle(BaseModel):
    enabled: bool


class ApiAccessEntry(BaseModel):
    portal_user_id: str
    api_access_enabled: bool


class ApiAccessUpdate(BaseModel):
    enabled: bool


class McpGateResult(BaseModel):
    ok: bool


def mcp_enabled(db: Session) -> bool:
    return bool(get_setting(db, MCP_ENABLED, False))


@router.get("/status", response_model=AiStatus, summary="AI client connection status")
def get_ai_status(
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> AiStatus:
    keys = db.scalars(
        select(APIKey)
        .where(APIKey.profile_id == current_profile.id, APIKey.is_revoked.is_(False))
        .order_by(APIKey.created_at.desc())
    ).all()
    summaries = [
        ApiKeySummary(
            id=k.id,
            name=k.name,
            prefix=k.prefix,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            last_mcp_used_at=k.last_mcp_used_at,
        )
        for k in keys
    ]
    connected = [k.last_mcp_used_at for k in keys if k.last_mcp_used_at]
    is_admin = bool(getattr(current_profile, "is_admin", False))
    return AiStatus(
        mcp_enabled=mcp_enabled(db),
        mcp_path=MCP_PORTAL_PATH,
        is_admin=is_admin,
        api_access=bool(current_profile.api_access_enabled) or is_admin,
        use_ai_suggestions=bool(current_profile.llm_enabled),
        api_keys=summaries,
        last_client_activity=max(connected) if connected else None,
    )


@router.put("/preferences", response_model=AiPreferences, summary="Update AI preferences")
def update_ai_preferences(
    payload: AiPreferences,
    db: Session = Depends(get_db),
    current_profile: AuthReconProfile = Depends(get_current_active_profile),
) -> AiPreferences:
    current_profile.llm_enabled = bool(payload.use_ai_suggestions)
    db.add(current_profile)
    db.commit()
    return AiPreferences(use_ai_suggestions=current_profile.llm_enabled)


def _audit_setting(db: Session, actor: AuthReconProfile, action: str, details: dict) -> None:
    """Admin changes to AI/MCP access go in the audit log (who, what, when)."""
    from app.models import AuditLog

    db.add(AuditLog(actor_profile_id=actor.id, entity_type="setting", action=action, details=details))
    db.commit()


@router.put("/mcp", response_model=McpToggle, summary="Enable or disable MCP (admin)")
def set_mcp_enabled(
    payload: McpToggle,
    db: Session = Depends(get_db),
    _admin: AuthReconProfile = Depends(get_current_admin),
) -> McpToggle:
    set_setting(db, MCP_ENABLED, bool(payload.enabled))
    _audit_setting(db, _admin, "mcp_enabled" if payload.enabled else "mcp_disabled", {})
    return McpToggle(enabled=mcp_enabled(db))


@router.get("/api-access", response_model=list[ApiAccessEntry], summary="Who may create API/MCP keys (admin)")
def list_api_access(
    db: Session = Depends(get_db),
    _admin: AuthReconProfile = Depends(get_current_admin),
) -> list[ApiAccessEntry]:
    profiles = db.scalars(select(AuthReconProfile)).all()
    return [
        ApiAccessEntry(portal_user_id=p.portal_user_id, api_access_enabled=bool(p.api_access_enabled))
        for p in profiles
    ]


@router.put(
    "/api-access/{portal_user_id}",
    response_model=ApiAccessEntry,
    summary="Allow or block a user's API/MCP keys (admin)",
)
def set_api_access(
    portal_user_id: str,
    payload: ApiAccessUpdate,
    db: Session = Depends(get_db),
    _admin: AuthReconProfile = Depends(get_current_admin),
) -> ApiAccessEntry:
    # Users who never opened AuthRecon have no profile yet; create it so the
    # grant is in place on their first visit. Turning access off also stops
    # existing keys working, because key auth re-checks this flag per request.
    profile = sync_portal_profile(db, portal_user_id)
    profile.api_access_enabled = bool(payload.enabled)
    db.add(profile)
    db.commit()
    _audit_setting(db, _admin, "api_access_granted" if payload.enabled else "api_access_revoked",
                   {"portal_user_id": portal_user_id})
    return ApiAccessEntry(portal_user_id=profile.portal_user_id, api_access_enabled=profile.api_access_enabled)


@router.get("/mcp-gate", response_model=McpGateResult, summary="MCP server: check a client's key")
def mcp_gate(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> McpGateResult:
    """Called by the MCP server for every client request.

    401 when the key is missing, invalid, revoked, expired or its user lost API
    access; 403 when an admin has MCP turned off. Records the key's
    last-connected time on success.
    """
    if not mcp_enabled(db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MCP is disabled by an administrator")
    resolved = resolve_api_key(x_api_key, db)
    if not resolved:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API key")
    key, _profile = resolved
    key.last_mcp_used_at = datetime.now(timezone.utc)
    db.add(key)
    db.commit()
    return McpGateResult(ok=True)
