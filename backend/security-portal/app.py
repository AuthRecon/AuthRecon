"""Security Portal FastAPI application."""
from __future__ import annotations

import logging
import os
import secrets
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

import asyncio
import json as _json

import httpx
import redis.asyncio as _aioredis
import websockets
import websockets.exceptions
from fastapi import Body, Depends, FastAPI, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.websockets import WebSocketState
from pydantic import BaseModel, ConfigDict, Field
from slowapi.util import get_remote_address

from auth import SessionUser, configure_user_lookup, get_current_user_from_token, create_jwt_token, revoke_jti

import secrets as _secrets

# --- Lightweight in-memory per-IP throttle (brute-force slowdown) -----------
# slowapi's @limiter.limit decorator is incompatible with this FastAPI/Pydantic
# v2 stack for endpoints with a Pydantic body (it turns the body annotation into
# an unresolvable ForwardRef -> 500). Use a simple sliding-window throttle.
# Note: in-memory/per-process (resets on restart); move to Redis for multi-instance.
import time as _time
from collections import defaultdict as _defaultdict

_login_attempts: "dict[str, list[float]]" = _defaultdict(list)


def _throttle(ip: str, max_attempts: int, window_seconds: int) -> None:
    now = _time.monotonic()
    recent = [t for t in _login_attempts.get(ip, []) if now - t < window_seconds]
    if len(recent) >= max_attempts:
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait and try again.")
    recent.append(now)
    _login_attempts[ip] = recent
from config import APP_VERSION, PortalConfig, load_config
from database import Base, get_session, init_engine
from models import PortalUser  # noqa: F401
from models.license import ClientLicense, LicenseActivation  # noqa: F401
from models.audit_log import AuditLog  # noqa: F401 — registers table with Base.metadata
from models.security_notice import SecurityNoticeAck  # noqa: F401 — registers table
from security_notice import router as security_notice_router
import audit
from tools_registry import ToolRegistry
from user_store import UserStore
from config_store import ConfigStore
from users import router as users_router
from security.encryption import EncryptionManager, ensure_key_exists
from validation import validate_password
from asset_store import AssetStore
from artifact_store import ArtifactStore
from diagnostics import DiagnosticsManager
from service_tokens import create_service_token
from licensing import LicenseManager

PROXY_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
# Trust headers the portal sets itself; a client-supplied copy is never forwarded.
CLIENT_STRIPPED_HEADERS = {
    "x-admin-token",
    "x-portal-secret",
    "x-portal-user-id",
    "x-portal-is-admin",
}


APP_NAME = "Security Portal"
LOGGER = logging.getLogger(APP_NAME)
SECURITY_LOGGER = logging.getLogger(f"{APP_NAME}.security")
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")


class ServiceLoginRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    username: Optional[str] = None
    email: Optional[str] = Field(default=None, alias="email")
    password: str


# API Models for JWT authentication
class APILoginRequest(BaseModel):
    """API login request model."""
    username: str
    password: str


class APILoginResponse(BaseModel):
    """API login response model."""
    token: str
    user: dict

    def resolve_username(self) -> str:
        return (self.username or self.email or "").strip().lower()


class LicenseStatusResponse(BaseModel):
    valid: bool
    tier: str
    expiration: Optional[str]
    installation_id: str
    features: list[str]
    last_checked: str
    message: Optional[str] = None


class LicenseRefreshRequest(BaseModel):
    license_key: Optional[str] = None


class GenerateLicenseRequest(BaseModel):
    """Request to generate a new license."""
    license_type: str  # 'professional', 'enterprise', 'perpetual'
    credential_id: Optional[str] = None  # Link to client credential
    expires_at: Optional[str] = None  # ISO datetime or None for perpetual
    max_installations: int = 1
    notes: Optional[str] = None


class GenerateLicenseResponse(BaseModel):
    """Response with generated license key."""
    license_key: str
    license_type: str
    expires_at: Optional[str]
    message: str


class LicenseListResponse(BaseModel):
    """Response with list of licenses."""
    licenses: list[dict]


class RevokeLicenseRequest(BaseModel):
    """Request to revoke a license."""
    reason: str


def create_app(config_path: Optional[Path] = None) -> FastAPI:
    """Application factory."""
    config: PortalConfig = load_config(config_path)
    _configure_logging(config.log_path)
    _enc_key_env = os.getenv("PORTAL_ENCRYPTION_KEY")
    if _enc_key_env:
        encryption_manager = EncryptionManager.from_key_bytes(_enc_key_env.encode())
        logging.getLogger("portal").info("Encryption key loaded from PORTAL_ENCRYPTION_KEY environment variable.")
    else:
        ensure_key_exists(config.encryption_key_path)
        encryption_manager = EncryptionManager(config.encryption_key_path)
        logging.getLogger("portal").info(
            "Encryption key loaded from file %s. "
            "Consider migrating to the PORTAL_ENCRYPTION_KEY environment variable for improved security.",
            config.encryption_key_path,
        )
    engine = init_engine(config.database_url)
    Base.metadata.create_all(bind=engine)
    user_store = UserStore(get_session, config.user_store_path)
    config_store = ConfigStore(get_session, encryptor=encryption_manager)
    asset_store = AssetStore(get_session)
    artifact_store = ArtifactStore(get_session, encryptor=encryption_manager)
    diagnostics_manager = DiagnosticsManager(asset_store, artifact_store)

    tool_registry = ToolRegistry(config.tools_config_path)
    tool_registry.load_tools()
    config_store.migrate_plaintext()

    app = FastAPI(title=APP_NAME, version=APP_VERSION)

    # Add CORS middleware for React frontend
    # Read allowed origins from environment variable (comma-separated)
    allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
    allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",")]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],  # Explicit methods only
        allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Portal-Token"],  # Add X-Portal-Token for dual auth
        expose_headers=["Content-Length", "Content-Type"],
    )

    app.state.config = config
    app.state.tool_registry = tool_registry
    app.state.user_store = user_store
    configure_user_lookup(user_store.get_user)
    app.state.config_store = config_store
    app.state.asset_store = asset_store
    app.state.artifact_store = artifact_store
    app.state.diagnostics = diagnostics_manager
    app.state.license_manager = LicenseManager(config)

    # Redis client for VNC tickets (DB 1 — separate from authrecon's DB 0)
    _redis = _aioredis.from_url(config.redis_url, decode_responses=True)

    # Include user management router
    app.include_router(users_router, prefix="/api")
    app.include_router(security_notice_router, prefix="/api")

    def _require_service_secret(request: Request) -> None:
        provided = request.headers.get("x-portal-service-secret")
        if not provided or provided != config.portal_api_secret:
            raise HTTPException(status_code=403, detail="Invalid service secret")

    def get_license_manager(request: Request) -> LicenseManager:
        manager: LicenseManager = getattr(request.app.state, "license_manager", None)
        if manager is None:
            raise HTTPException(status_code=500, detail="License manager unavailable")
        return manager

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        """Add security headers to all responses."""
        response = await call_next(request)

        # noVNC static assets are intentionally embedded in the portal iframe.
        # Use SAMEORIGIN / frame-ancestors 'self' for that path so the browser
        # allows the iframe while still blocking embedding by external origins.
        is_novnc = request.url.path.startswith("/apps/authrecon/novnc/")

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "SAMEORIGIN" if is_novnc else "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # HSTS only means something over HTTPS (browsers ignore it on plain
        # HTTP). Honour X-Forwarded-Proto for TLS-terminating reverse proxies.
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        if request.url.scheme == "https" or forwarded_proto == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy
        # For noVNC pages: also allow ws://127.0.0.1:9000. In WSL2 dev environments
        # Chrome resolves 'localhost' to ::1 (IPv6) but Docker only binds IPv4, so the
        # noVNC host is set to 127.0.0.1 to force IPv4. That makes it a different origin
        # from the page (served from localhost:9000), which 'self' doesn't cover.
        # In production (accessed via server IP/hostname) 'self' covers it naturally.
        if is_novnc:
            connect_src = "connect-src 'self' ws://127.0.0.1:9000 wss://127.0.0.1:9000"
        else:
            connect_src = "connect-src 'self'"
        # unsafe-eval is required by noVNC but not by React (bundled).
        # Only include it on the noVNC path so the main app runs without it.
        script_src = (
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
            if is_novnc
            else "script-src 'self' 'unsafe-inline'"
        )
        csp_directives = [
            "default-src 'self'",
            script_src,
            "style-src 'self' 'unsafe-inline'",  # Tailwind uses inline styles
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            connect_src,
            # noVNC is embedded in the portal's own iframe — allow framing by same origin only.
            # All other portal pages may not be framed by anyone.
            "frame-ancestors 'self'" if is_novnc else "frame-ancestors 'none'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        return response

    @app.middleware("http")
    async def add_portal_context(request: Request, call_next):
        request.state.portal_config = config
        return await call_next(request)

    @app.get("/healthz", response_class=Response)
    async def health_check() -> str:
        return "ok"

    @app.get("/", response_model=dict)
    async def root() -> dict:
        """Legacy server-rendered UI has been retired in favor of the SPA."""
        return {
            "status": "ok",
            "frontend_url": FRONTEND_URL,
            "message": "Portal UI is served by the React frontend.",
        }

    def _legacy_ui_disabled() -> dict:
        return {
            "detail": "Legacy portal UI has been removed. Use the React frontend.",
            "frontend_url": FRONTEND_URL,
        }

    @app.api_route("/login", methods=["GET", "POST"], include_in_schema=False)
    async def login_disabled():
        return JSONResponse(content=_legacy_ui_disabled(), status_code=410)

    @app.api_route("/setup", methods=["GET", "POST"], include_in_schema=False)
    async def setup_disabled():
        return JSONResponse(content=_legacy_ui_disabled(), status_code=410)

    @app.get("/network-tools", include_in_schema=False)
    async def network_tools_disabled():
        return JSONResponse(content=_legacy_ui_disabled(), status_code=410)

    @app.get("/api/license/status", response_model=LicenseStatusResponse)
    async def get_license_status(
        license_manager: LicenseManager = Depends(get_license_manager),
        _user: SessionUser = Depends(get_current_user_from_token),
    ):
        return license_manager.get_status().to_dict()

    @app.post("/api/license/check", response_model=LicenseStatusResponse)
    async def refresh_license(
        payload: LicenseRefreshRequest,
        license_manager: LicenseManager = Depends(get_license_manager),
        _user: SessionUser = Depends(get_current_user_from_token),
    ):
        return license_manager.refresh(license_key=payload.license_key).to_dict()

    # License Management (Admin Only)

    def _generate_license_key(license_type: str) -> str:
        """Generate a license key in format: AUTHRECON-TYPE-XXXX-XXXX-XXXX"""
        type_prefix = license_type.upper()[:4]  # PROF, ENTE, PERP

        def random_segment():
            return ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

        # Generate 3 random segments
        seg1 = random_segment()
        seg2 = random_segment()
        seg3 = random_segment()

        return f"AUTHRECON-{type_prefix}-{seg1}-{seg2}-{seg3}"

    @app.post("/api/admin/licenses", response_model=GenerateLicenseResponse)
    async def generate_license(
        payload: GenerateLicenseRequest,
        user: SessionUser = Depends(get_current_user_from_token)
    ):
        """Generate a new license (admin only)."""
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")

        # Generate license key
        license_key = _generate_license_key(payload.license_type)

        # Parse expiration
        expires_at_dt = None
        if payload.expires_at:
            try:
                expires_at_dt = datetime.fromisoformat(payload.expires_at.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid expiration date format")

        # Create license record
        with get_session() as db:
            new_license = ClientLicense(
                license_key=license_key,
                license_type=payload.license_type,
                credential_id=payload.credential_id,
                issued_by=user.user_id,
                expires_at=expires_at_dt,
                max_installations=payload.max_installations,
                notes=payload.notes
            )
            db.add(new_license)
            db.commit()
            db.refresh(new_license)
            audit.emit(audit.LICENSE_GENERATED, actor_username=user.username,
                       detail=f"license_id={new_license.id} type={payload.license_type}")

            return GenerateLicenseResponse(
                license_key=license_key,
                license_type=payload.license_type,
                expires_at=expires_at_dt.isoformat() if expires_at_dt else None,
                message="License generated successfully"
            )

    @app.get("/api/admin/licenses", response_model=LicenseListResponse)
    async def list_licenses(user: SessionUser = Depends(get_current_user_from_token)):
        """List all Portal-issued licenses (admin only)."""
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")

        with get_session() as db:
            from sqlalchemy import select
            from models.license import ClientLicense
            from models.asset import PortalAsset
            from models import PortalUser

            stmt = (
                select(ClientLicense, PortalAsset, PortalUser)
                .outerjoin(PortalAsset, ClientLicense.credential_id == PortalAsset.id)
                .outerjoin(PortalUser, ClientLicense.issued_by == PortalUser.id)
            )
            results = db.execute(stmt).all()

            licenses = []
            for license_obj, asset, issuer in results:
                # Count activations
                activation_count = len(license_obj.activations) if license_obj.activations else 0

                licenses.append({
                    "id": license_obj.id,
                    "license_key": license_obj.license_key,
                    "license_type": license_obj.license_type,
                    "credential_id": license_obj.credential_id,
                    "credential_name": asset.company_name if asset else None,
                    "issued_by": issuer.username if issuer else "Unknown",
                    "issued_at": license_obj.issued_at.isoformat() if license_obj.issued_at else None,
                    "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else None,
                    "max_installations": license_obj.max_installations,
                    "activation_count": activation_count,
                    "revoked": license_obj.revoked,
                    "revoked_reason": license_obj.revoked_reason,
                    "notes": license_obj.notes
                })

            return LicenseListResponse(licenses=licenses)

    @app.post("/api/admin/licenses/{license_id}/revoke")
    async def revoke_license(
        license_id: str,
        payload: RevokeLicenseRequest,
        user: SessionUser = Depends(get_current_user_from_token)
    ):
        """Revoke a license (admin only)."""
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")

        with get_session() as db:
            from sqlalchemy import select
            from models.license import ClientLicense

            stmt = select(ClientLicense).where(ClientLicense.id == license_id)
            license_obj = db.execute(stmt).scalar_one_or_none()

            if not license_obj:
                raise HTTPException(status_code=404, detail="License not found")

            license_obj.revoked = True
            license_obj.revoked_reason = payload.reason
            license_obj.revoked_at = datetime.utcnow()

            db.commit()
            audit.emit(audit.LICENSE_REVOKED, actor_username=user.username, detail=f"license_id={license_id}")

            return {"success": True, "message": "License revoked successfully"}

    @app.get("/api/admin/audit-log")
    async def get_audit_log(
        limit: int = 100,
        offset: int = 0,
        event_type: str | None = None,
        user: SessionUser = Depends(get_current_user_from_token),
    ):
        """Return paginated audit log entries (admin only)."""
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")

        from sqlalchemy import select, func
        from models.audit_log import AuditLog

        limit = min(max(1, limit), 500)
        session = get_session()
        try:
            stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
            count_stmt = select(func.count()).select_from(AuditLog)
            if event_type:
                stmt = stmt.where(AuditLog.event_type == event_type)
                count_stmt = count_stmt.where(AuditLog.event_type == event_type)
            total = session.execute(count_stmt).scalar()
            rows = session.execute(stmt.offset(offset).limit(limit)).scalars().all()
            return {
                "total": total,
                "offset": offset,
                "limit": limit,
                "entries": [
                    {
                        "id": r.id,
                        "event_type": r.event_type,
                        "actor_username": r.actor_username,
                        "actor_ip": r.actor_ip,
                        "target_username": r.target_username,
                        "detail": r.detail,
                        "created_at": r.created_at.isoformat(),
                    }
                    for r in rows
                ],
            }
        finally:
            session.close()

    # JWT API Authentication Endpoints (for React frontend)

    @app.post("/api/auth/login", response_model=APILoginResponse)
    async def api_login(request: Request, payload: APILoginRequest):
        """JWT-based login endpoint for React frontend."""
        client_ip = get_remote_address(request)
        _throttle(client_ip, max_attempts=5, window_seconds=60)
        username = payload.username.strip()

        if not user_store.is_initialized:
            raise HTTPException(status_code=503, detail="Portal not initialized")

        password = payload.password.strip()

        if not username or not password:
            SECURITY_LOGGER.warning(f"Login attempt with missing credentials from {client_ip}")
            raise HTTPException(status_code=400, detail="Username and password required")

        record = user_store.verify_credentials(username, password)
        if not record:
            SECURITY_LOGGER.warning(f"Failed login attempt for user '{username}' from {client_ip}")
            audit.emit(audit.LOGIN_FAILURE, actor_username=username, actor_ip=client_ip)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Create JWT token
        token = create_jwt_token(
            username=record["username"],
            is_admin=record["is_admin"],
            user_id=record["id"]
        )

        SECURITY_LOGGER.info(f"Successful login for user '{username}' from {client_ip}")
        audit.emit(audit.LOGIN_SUCCESS, actor_username=record["username"], actor_ip=client_ip)

        return {
            "token": token,
            "user": {
                "username": record["username"],
                "is_admin": record["is_admin"],
                "id": record["id"]
            }
        }

    @app.post("/api/auth/setup", response_model=APILoginResponse)
    async def api_setup(payload: APILoginRequest):
        """JWT-based setup endpoint for React frontend - creates first admin user."""
        # Check if portal is already initialized
        if user_store.is_initialized:
            raise HTTPException(status_code=400, detail="Portal already initialized")

        username = payload.username.strip().lower()
        password = payload.password.strip()

        # Validation
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")

        _pw_error = validate_password(password)
        if _pw_error:
            raise HTTPException(status_code=400, detail=_pw_error)

        # Basic email validation
        if "@" not in username or "." not in username:
            raise HTTPException(status_code=400, detail="Username must be a valid email address")

        # Create admin user
        try:
            user_store.add_user(username, password, is_admin=True)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        # Verify credentials
        record = user_store.verify_credentials(username, password)
        if not record:
            raise HTTPException(status_code=500, detail="Failed to initialize admin user")

        # Create JWT token
        token = create_jwt_token(
            username=record["username"],
            is_admin=record["is_admin"],
            user_id=record["id"]
        )

        audit.emit(audit.SETUP_COMPLETED, actor_username=record["username"])

        return {
            "token": token,
            "user": {
                "username": record["username"],
                "is_admin": record["is_admin"],
                "id": record["id"]
            }
        }

    @app.post("/api/auth/logout")
    async def api_logout(request: Request):
        """Revoke the current JWT by adding its jti to the Redis blocklist.

        Validates the token signature before revoking (prevents revoking arbitrary tokens),
        but accepts expired tokens so logout works even after expiry.  Always returns 200
        so the client can safely clear its local state regardless of token status.
        """
        import time as _time
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]
            try:
                from auth import JWT_SECRET_KEY as _jwtkey, JWT_ALGORITHM as _jwtalg
                import jwt as _pyjwt
                payload = _pyjwt.decode(
                    raw_token, _jwtkey, algorithms=[_jwtalg],
                    options={"verify_exp": False},  # Accept expired tokens on logout
                )
                jti = payload.get("jti")
                exp = payload.get("exp")
                _logout_user = payload.get("username") or payload.get("sub")
                if jti and exp:
                    ttl = max(1, int(exp - _time.time()))
                    revoke_jti(jti, ttl)
                audit.emit(audit.LOGOUT, actor_username=_logout_user, actor_ip=get_remote_address(request))
            except Exception:
                pass  # Invalid signature or missing fields — nothing to revoke
        return {"success": True}

    @app.get("/api/auth/me")
    async def api_auth_me(user: SessionUser = Depends(get_current_user_from_token)):
        """Who the bearer token belongs to. Also lets the frontend confirm a session is still valid."""
        return {"username": user.username, "is_admin": user.is_admin, "id": user.user_id}

    @app.get("/api/auth/status")
    async def api_auth_status():
        """Check if portal needs setup or is ready for login."""
        return {
            "initialized": user_store.is_initialized,
            "needs_setup": not user_store.is_initialized
        }
    @app.get("/api/tools")
    async def list_tools(user: SessionUser = Depends(get_current_user_from_token)):
        return {"tools": app.state.tool_registry.list_tools()}

    def _require_portal_auth(request: Request) -> SessionUser:
        """Allow a bearer token, or the X-Portal-Token header, for API proxy usage."""
        # Allow OPTIONS requests (CORS preflight) without authentication
        if request.method == "OPTIONS":
            # Return a dummy SessionUser for OPTIONS requests (won't be used in actual proxy logic)
            return SessionUser(username="", is_admin=False, user_id="")

        # Try X-Portal-Token header (used when Authorization header has service token)
        portal_token_header = request.headers.get("X-Portal-Token")
        if portal_token_header and portal_token_header.startswith("Bearer "):
            # Extract just the token part (remove "Bearer " prefix)
            token_value = portal_token_header[7:]  # Skip "Bearer "
            # Validate the portal token directly
            try:
                from auth import decode_jwt_token, session_user_from_payload
                return session_user_from_payload(decode_jwt_token(token_value))
            except HTTPException:
                raise  # a valid-looking token for a disabled user must not fall through
            except Exception:
                pass  # Fall through to regular token check

        return get_current_user_from_token(request)

    @app.get("/tools/{tool_id}/launch")
    async def launch_tool(tool_id: str, user: SessionUser = Depends(get_current_user_from_token)):
        try:
            tool = tool_registry.get_tool(tool_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        if tool.get("sso_enabled") and tool.get("sso_entry_url"):
            if not config.portal_api_secret:
                raise HTTPException(status_code=503, detail="Portal SSO not configured.")
            token = create_service_token(
                user,
                config.portal_api_secret,
                service=str(tool.get("service_id") or tool_id),
            )
            destination = _append_query(tool["sso_entry_url"], {"portal_token": token})
            return RedirectResponse(destination, status_code=302)

        url = tool.get("url")
        if not url:
            raise HTTPException(status_code=404, detail="Tool launch URL missing.")
        return RedirectResponse(url, status_code=302)

    @app.post("/api/tools/{tool_id}/service-token")
    async def issue_service_token(tool_id: str, user: SessionUser = Depends(_require_portal_auth)):
        """Mint a short-lived portal token for SSO-enabled tools (used by React frontend)."""
        try:
            tool = tool_registry.get_tool(tool_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        if not tool.get("sso_enabled") or not tool.get("sso_entry_url"):
            raise HTTPException(status_code=400, detail="SSO is not configured for this tool.")

        if not config.portal_api_secret:
            raise HTTPException(status_code=503, detail="Portal SSO not configured.")

        service_id = str(tool.get("service_id") or tool_id)
        token = create_service_token(
            user,
            config.portal_api_secret,
            service=service_id,
        )
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        return {
            "token": token,
            "service_id": service_id,
            "expires_at": expires_at.isoformat(),
        }

    @app.get("/api/diagnostics/recent")
    async def get_recent_diagnostics(user: SessionUser = Depends(get_current_user_from_token)):
        """Get recent diagnostics runs for current user."""
        recent_runs = diagnostics_manager.list_recent_runs(owner=user, limit=10)
        return [
            {
                "artifact_id": run.artifact_id,
                "asset_id": run.asset_id,
                "tool": run.tool,
                "target": run.target,
                "exit_code": run.exit_code,
                "summary": run.summary,
            }
            for run in recent_runs
        ]

    @app.post("/api/diagnostics/run")
    async def run_diagnostics(payload: Dict[str, Any] = Body(...), user: SessionUser = Depends(get_current_user_from_token)):
        tool = str(payload.get("tool", "")).strip().lower()
        target = str(payload.get("target", "")).strip()
        private = bool(payload.get("private", False))
        if not tool or not target:
            raise HTTPException(status_code=400, detail="Tool and target are required.")
        try:
            # ping/traceroute block for up to ~20s: keep them off the event loop
            # so the portal (and every proxied/VNC session) stays responsive.
            result = await asyncio.to_thread(
                diagnostics_manager.run_tool, tool=tool, target=target, private=private, user=user
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {
            "artifact_id": result.artifact_id,
            "asset_id": result.asset_id,
            "tool": result.tool,
            "target": result.target,
            "exit_code": result.exit_code,
            "summary": result.summary,
        }

    @app.get("/api/artifacts/{artifact_id}/download")
    async def download_artifact(artifact_id: str, user: SessionUser = Depends(get_current_user_from_token)):
        """Download and decrypt an artifact (for API requests)."""
        artifact_data = artifact_store.fetch(artifact_id)
        if not artifact_data:
            raise HTTPException(status_code=404, detail="Artifact not found")

        # Authorization check: verify ownership or admin access or global scope
        owner_id = artifact_data.get("owner_id")
        sharing_scope = artifact_data.get("sharing_scope", "private")

        # Allow access if:
        # 1. User is the owner
        # 2. User is admin
        # 3. Artifact is global scope (shared with everyone)
        is_owner = owner_id == user.user_id
        is_admin = user.is_admin
        is_global = sharing_scope == "global"

        if not (is_owner or is_admin or is_global):
            raise HTTPException(status_code=403, detail="Access denied")

        # Return the decrypted blob content as plain text
        blob = artifact_data["blob"]
        if isinstance(blob, bytes):
            content = blob.decode("utf-8", errors="replace")
        else:
            content = str(blob)

        return Response(content=content, media_type="text/plain")

    # ==================== LoginLab Control Endpoints ====================

    LOGINLAB_URL = os.getenv("LOGINLAB_URL", "http://loginlab:5500")
    # LoginLab has its own token: it is an intentionally vulnerable service, so
    # it must never hold PORTAL_API_SECRET (which authrecon-api trusts).
    LOGINLAB_SERVICE_TOKEN = os.getenv("LOGINLAB_SERVICE_TOKEN", "")

    async def _loginlab_request(method: str, path: str, user: SessionUser = None) -> dict:
        """Make a request to LoginLab service."""
        headers = {
            "X-Service-Token": LOGINLAB_SERVICE_TOKEN,
            "X-User": user.username if user else "system",
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if method == "GET":
                    resp = await client.get(f"{LOGINLAB_URL}{path}", headers=headers)
                else:
                    resp = await client.post(f"{LOGINLAB_URL}{path}", headers=headers)
                return resp.json()
        except httpx.ConnectError:
            return {"error": "LoginLab service not running", "active": False, "available": False}
        except Exception as e:
            return {"error": str(e), "active": False, "available": False}

    @app.get("/api/loginlab/status")
    async def loginlab_status():
        """Get LoginLab status (public - only returns active/inactive state)."""
        result = await _loginlab_request("GET", "/api/loginlab/status")
        result["available"] = "error" not in result or result.get("active", False)
        return result

    @app.post("/api/loginlab/enable")
    async def loginlab_enable(
        request: Request,
        user: SessionUser = Depends(get_current_user_from_token),
        duration_minutes: int = 30
    ):
        """Enable LoginLab training environment (admin only)."""
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only. LoginLab contains intentional vulnerabilities.")

        SECURITY_LOGGER.info(f"LoginLab ENABLED by {user.username} for {duration_minutes} minutes")
        audit.emit(audit.LOGINLAB_ENABLED, actor_username=user.username, detail=f"{duration_minutes} minutes")

        result = await _loginlab_request("POST", f"/api/loginlab/enable?duration_minutes={duration_minutes}", user)
        return result

    @app.post("/api/loginlab/disable")
    async def loginlab_disable(user: SessionUser = Depends(get_current_user_from_token)):
        """Disable LoginLab training environment (admin only)."""
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin only.")

        SECURITY_LOGGER.info(f"LoginLab DISABLED by {user.username}")
        audit.emit(audit.LOGINLAB_DISABLED, actor_username=user.username)

        result = await _loginlab_request("POST", "/api/loginlab/disable", user)
        return result

    @app.post("/api/service/auth/login")
    async def service_auth_login(payload: ServiceLoginRequest = Body(...), request: Request = None):
        _require_service_secret(request)
        username = payload.resolve_username()
        if not username or not payload.password:
            raise HTTPException(status_code=400, detail="Username and password required")
        record = user_store.verify_credentials(username, payload.password)
        if not record:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {
            "username": record["username"],
            "is_admin": record["is_admin"],
            "id": record["id"],
        }

    @app.api_route("/apps/authrecon/api/{path:path}", methods=PROXY_METHODS, include_in_schema=False)
    async def proxy_authrecon_api(
        path: str,
        request: Request,
        user: SessionUser = Depends(_require_portal_auth),
    ):
        path = _safe_proxy_path(path)
        target = f"/api/{path}" if path else "/api"
        return await _proxy_request(request, "http://authrecon-api:8000", target)

    @app.post("/api/authrecon/vnc-token/{run_id}", include_in_schema=False)
    async def issue_vnc_token(
        run_id: str,
        user: SessionUser = Depends(_require_portal_auth),
    ):
        """Issue a Redis-backed VNC access ticket.

        Ticket is cryptographically random, scoped to run_id + user_id, stored in
        Redis (DB 1) with a 120-second TTL, and consumed (deleted) by the WebSocket
        handler on first successful backend connection.  Survives portal restarts and
        is not subject to in-memory dict races.
        """
        # Verify run ownership + get the worker's noVNC port
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    f"http://authrecon-api:8000/internal/vnc/{run_id}",
                    headers={
                        "X-Portal-Secret": config.portal_api_secret,
                        "X-Portal-User-Id": str(user.user_id or ""),
                        "X-Portal-Is-Admin": "true" if user.is_admin else "false",
                    },
                )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=503, detail="VNC service unavailable") from exc

        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="VNC session not available")

        vnc_port = resp.json()["vnc_port"]

        ticket = _secrets.token_urlsafe(32)
        payload = _json.dumps({
            "run_id": run_id,
            "vnc_port": vnc_port,
            "user_id": str(user.user_id or ""),
        })
        await _redis.set(f"vnc:ticket:{ticket}", payload, ex=120)
        return {"token": ticket, "expires_in": 120}

    # noVNC static assets — registered BEFORE the catch-all authrecon frontend
    # route so the specific path wins. No auth: these are public JS/HTML files;
    # the WebSocket endpoint below enforces auth on the actual VNC data channel.
    #
    # Frame-blocking headers are stripped from the response: authrecon-api's
    # security middleware adds X-Frame-Options: DENY and CSP frame-ancestors 'none'
    # to all responses, which would prevent the noVNC page from loading inside our
    # portal iframe. These are intentionally removed for this specific static route
    # because the noVNC page is deliberately embedded in the portal UI.
    @app.api_route(
        "/apps/authrecon/novnc/{path:path}", methods=("GET", "HEAD"), include_in_schema=False
    )
    async def proxy_novnc_static(request: Request, path: str = ""):
        path = _safe_proxy_path(path)
        return await _proxy_request(request, "http://authrecon-api:8000", f"/novnc/{path}")

    # MCP endpoint for AI clients (Claude Code, Claude Desktop, ...). No portal
    # login here: MCP clients authenticate with the user's own AuthRecon API key
    # (Authorization: Bearer ak_live_...), which the MCP server checks against
    # authrecon-api on every request. Must be registered before the
    # /apps/authrecon/{path} catch-all below.
    @app.api_route("/apps/authrecon/mcp", methods=("GET", "POST", "DELETE"), include_in_schema=False)
    @app.api_route("/apps/authrecon/mcp/{path:path}", methods=("GET", "POST", "DELETE"), include_in_schema=False)
    async def proxy_mcp(request: Request, path: str = ""):
        path = _safe_proxy_path(path)
        target = f"/mcp/{path}" if path else "/mcp"
        return await _proxy_request(request, config.mcp_base_url, target)

    # -------------------------------------------------------------------------
    # VNC WebSocket proxy — authenticated, ownership-verified.
    #
    # Flow:
    #   Browser (noVNC JS inside iframe)
    #     → ws://portal:9000/apps/authrecon/vnc/{run_id}   (portal validates auth)
    #     → ws://authrecon-worker:{vnc_port}/websockify     (internal Docker network)
    #     → x11vnc on the worker's Xvfb display
    #
    # Auth: session cookie (secportal_session) sent automatically by the browser
    # because the iframe is served from the portal's own origin.
    # Ownership: portal calls authrecon-api /internal/vnc/{run_id} with the shared
    # PORTAL_API_SECRET — authrecon-api verifies the profile owns the run.
    # VNC ports are no longer published externally; they are internal-only.
    # -------------------------------------------------------------------------
    @app.websocket("/apps/authrecon/vnc/{run_id}")
    async def proxy_vnc_websocket(ws_client: WebSocket, run_id: str):
        # 1. Validate Redis-backed VNC ticket.
        #    Ticket is issued by POST /api/authrecon/vnc-token/{run_id} (JWT-authed),
        #    stored in Redis DB 1 with a 120s TTL, scoped to run_id + user_id.
        #    On successful backend connection the ticket is deleted (one-time use).
        ticket = ws_client.query_params.get("t", "")
        if not ticket:
            await ws_client.close(code=1008)
            return

        raw = await _redis.get(f"vnc:ticket:{ticket}")
        if not raw:
            await ws_client.close(code=1008)
            return

        try:
            entry = _json.loads(raw)
        except Exception:
            await ws_client.close(code=1008)
            return

        if entry.get("run_id") != run_id:
            await ws_client.close(code=1008)
            return

        vnc_port = entry["vnc_port"]

        # 3. Accept the client WebSocket immediately so the browser gets its HTTP 101
        #    without waiting for the backend connection. noVNC needs the 101 before it
        #    will start the RFB handshake; delaying it past ~5s causes "Connecting" to
        #    stall and eventually timeout in the browser. noVNC always requests "binary"
        # 4. Connect to the worker's websockify BEFORE accepting the client WebSocket.
        #    The worker confirms websockify is listening before writing vnc_port to the DB,
        #    so the first attempt nearly always succeeds in <10ms — well within browser
        #    timeout. Connecting first eliminates the window where the client is accepted
        #    but no data flows, which was causing an immediate disconnect in the receive queue.
        import logging as _logging
        _log = _logging.getLogger("vnc-proxy")
        _log.info(f"[VNC] {run_id} connecting to worker port {vnc_port}")
        ws_backend = None
        for _attempt in range(10):
            try:
                ws_backend = await websockets.connect(
                    f"ws://authrecon-worker:{vnc_port}/websockify",
                    subprotocols=["binary"],
                )
                break
            except Exception as _e:
                _log.warning(f"[VNC] {run_id} backend attempt {_attempt+1} failed: {_e}")
                if _attempt < 9:
                    await asyncio.sleep(0.5)
        if ws_backend is None:
            _log.error(f"[VNC] {run_id} all backend attempts failed")
            await ws_client.close(code=1011)
            return

        # Backend is ready — now accept the client and consume the ticket atomically.
        # wsproto (and the spec) require that we only accept with a subprotocol the
        # client actually offered.  If it didn't include 'binary' we accept with none;
        # binary frames still flow correctly regardless of the negotiated subprotocol.
        _proto_header = ws_client.headers.get("sec-websocket-protocol", "")
        _client_protos = [p.strip() for p in _proto_header.split(",") if p.strip()]
        _use_proto = ws_backend.subprotocol if ws_backend.subprotocol in _client_protos else None
        await ws_client.accept(subprotocol=_use_proto)
        await _redis.delete(f"vnc:ticket:{ticket}")
        _log.info(f"[VNC] {run_id} accepted client, proxying")

        # 5. Bidirectional pipe — cancel both directions when either side closes
        async def _forward_to_backend():
            try:
                while True:
                    msg = await ws_client.receive()
                    if msg["type"] == "websocket.disconnect":
                        _log.info(f"[VNC] {run_id} client disconnected code={msg.get('code', '?')}")
                        break
                    payload = msg.get("bytes") or (
                        msg["text"].encode() if msg.get("text") else None
                    )
                    if payload is not None:
                        await ws_backend.send(payload)
            except Exception as _e:
                _log.warning(f"[VNC] {run_id} c→b error: {type(_e).__name__}: {_e}")

        async def _forward_to_client():
            try:
                async for message in ws_backend:
                    if isinstance(message, bytes):
                        await ws_client.send_bytes(message)
                    else:
                        await ws_client.send_text(message)
                _log.info(f"[VNC] {run_id} backend closed normally")
            except Exception as _e:
                _log.warning(f"[VNC] {run_id} b→c error: {type(_e).__name__}: {_e}")

        task_c2b = asyncio.create_task(_forward_to_backend())
        task_b2c = asyncio.create_task(_forward_to_client())
        try:
            done, pending = await asyncio.wait(
                [task_c2b, task_b2c], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            try:
                await ws_backend.close()
            except Exception:
                pass
            try:
                if ws_client.client_state != WebSocketState.DISCONNECTED:
                    await ws_client.close()
            except Exception:
                pass

    return app


def _configure_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=[logging.FileHandler(log_path), logging.StreamHandler()],
    )


app = create_app()


def _append_query(url: str, extra_params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in extra_params.items():
        if value is not None:
            existing[key] = value
    new_query = urlencode(existing, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _build_proxy_headers(source_headers) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for name, value in source_headers.items():
        lower = name.lower()
        if lower in HOP_HEADERS or lower in CLIENT_STRIPPED_HEADERS or lower == "host":
            continue
        headers[name] = value
    return headers


def _fully_unquote(value: str, max_rounds: int = 5) -> str:
    for _ in range(max_rounds):
        decoded = unquote(value)
        if decoded == value:
            return decoded
        value = decoded
    raise HTTPException(status_code=400, detail="Invalid proxy path")


def _safe_proxy_path(path: str) -> str:
    """Reject proxy paths that could escape the intended upstream prefix.

    Starlette has already decoded the path once; we decode further so
    double-encoded forms (``%252e%252e``) are caught too.
    """
    decoded = _fully_unquote(path or "")
    if (
        decoded.startswith("/")
        or "\\" in decoded
        or "\x00" in decoded
        or any(segment in (".", "..") for segment in decoded.split("/"))
    ):
        raise HTTPException(status_code=400, detail="Invalid proxy path")
    return path


def _join_proxy_url(base: str, path: str) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{base.rstrip('/')}{path}"


async def _proxy_request(
    request: Request,
    target_base: str,
    path: str,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Response:
    url = _join_proxy_url(target_base, path)
    headers = _build_proxy_headers(request.headers)
    if extra_headers:
        headers.update(extra_headers)
    body = await request.body()
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as client:
        proxied = await client.request(
            request.method,
            url,
            headers=headers,
            content=body,
            params=request.query_params,
        )
    filtered_headers = {
        key: value for key, value in proxied.headers.items() if key.lower() not in HOP_HEADERS
    }
    return Response(content=proxied.content, status_code=proxied.status_code, headers=filtered_headers)
