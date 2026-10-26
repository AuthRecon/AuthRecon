"""
LoginLab - AuthRecon Training Ground
FastAPI application providing multiple authentication scenarios for testing.

SECURITY WARNING: This is a deliberately simple practice target (fake users,
weak demo passwords). It should NEVER be exposed externally and should only accept connections from
AuthRecon services via service token authentication.
"""
import hmac
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Request, Response, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi import Depends
from starlette.middleware.base import BaseHTTPMiddleware

from .scenarios import SCENARIOS, get_scenario
from .telemetry import TelemetryCollector, TelemetryEntry


# Security configuration
LOGINLAB_SERVICE_TOKEN = os.getenv("LOGINLAB_SERVICE_TOKEN", "")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "authrecon-worker,authrecon-api,portal,localhost,127.0.0.1").split(",")
LOGINLAB_AUTO_DISABLE_MINUTES = int(os.getenv("LOGINLAB_AUTO_DISABLE_MINUTES", "30"))

# Global state for auto-disable
_loginlab_state = {
    "enabled": False,
    "enabled_until": None,
    "enabled_by": None,
}


def is_loginlab_active() -> bool:
    """Check if LoginLab is currently active (enabled and not timed out)."""
    if not _loginlab_state["enabled"]:
        return False
    if _loginlab_state["enabled_until"]:
        if datetime.now(timezone.utc) > _loginlab_state["enabled_until"]:
            # Auto-disable has triggered
            _loginlab_state["enabled"] = False
            _loginlab_state["enabled_until"] = None
            return False
    return True


def enable_loginlab(enabled_by: str = "unknown", duration_minutes: int = None) -> dict:
    """Enable LoginLab with auto-disable timer."""
    if duration_minutes is None:
        duration_minutes = LOGINLAB_AUTO_DISABLE_MINUTES

    _loginlab_state["enabled"] = True
    _loginlab_state["enabled_until"] = datetime.now(timezone.utc).replace(microsecond=0) + \
        __import__("datetime").timedelta(minutes=duration_minutes)
    _loginlab_state["enabled_by"] = enabled_by

    return {
        "status": "enabled",
        "enabled_until": _loginlab_state["enabled_until"].isoformat(),
        "auto_disable_minutes": duration_minutes,
        "enabled_by": enabled_by,
    }


def disable_loginlab() -> dict:
    """Disable LoginLab immediately."""
    _loginlab_state["enabled"] = False
    _loginlab_state["enabled_until"] = None
    _loginlab_state["enabled_by"] = None
    return {"status": "disabled"}


def get_loginlab_status() -> dict:
    """Get current LoginLab status."""
    active = is_loginlab_active()
    remaining_seconds = 0
    if active and _loginlab_state["enabled_until"]:
        remaining = _loginlab_state["enabled_until"] - datetime.now(timezone.utc)
        remaining_seconds = max(0, int(remaining.total_seconds()))

    return {
        "active": active,
        "enabled": _loginlab_state["enabled"],
        "enabled_until": _loginlab_state["enabled_until"].isoformat() if _loginlab_state["enabled_until"] else None,
        "enabled_by": _loginlab_state["enabled_by"],
        "remaining_seconds": remaining_seconds,
        "auto_disable_minutes": LOGINLAB_AUTO_DISABLE_MINUTES,
    }


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware that:
    1. Validates service token for non-health endpoints
    2. Checks if LoginLab is enabled (with auto-disable)
    3. Restricts access to allowed hosts only
    """

    EXEMPT_PATHS = {"/health", "/api/loginlab/status", "/api/loginlab/enable", "/api/loginlab/disable"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Always allow health and control endpoints
        if path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Check if LoginLab is active
        if not is_loginlab_active():
            return JSONResponse(
                status_code=503,
                content={
                    "error": "LoginLab is disabled",
                    "message": "LoginLab training environment is currently disabled by administrator. "
                               "Enable it from the AuthRecon settings panel.",
                    "status": get_loginlab_status(),
                }
            )

        # Validate service token if configured
        if LOGINLAB_SERVICE_TOKEN:
            auth_header = request.headers.get("Authorization", "")
            token_header = request.headers.get("X-Service-Token", "")

            valid_token = False
            if auth_header.startswith("Bearer "):
                valid_token = hmac.compare_digest(auth_header[7:], LOGINLAB_SERVICE_TOKEN)
            elif token_header:
                valid_token = hmac.compare_digest(token_header, LOGINLAB_SERVICE_TOKEN)

            # Also allow if request is from allowed internal host (for browser access during VNC)
            # Docker networks use IPs like 172.x.x.x, not hostnames
            client_host = request.client.host if request.client else ""
            is_allowed_host = (
                any(host in client_host for host in ALLOWED_HOSTS) or
                client_host.startswith("172.") or  # Docker bridge networks
                client_host.startswith("10.") or   # Docker overlay networks
                client_host.startswith("192.168.")  # Docker custom networks
            )

            if not valid_token and not is_allowed_host:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access denied",
                        "message": "LoginLab requires service token authentication. "
                                   "Access is restricted to AuthRecon services only.",
                    }
                )

        return await call_next(request)


# Initialize FastAPI app
app = FastAPI(
    title="LoginLab",
    description="AuthRecon training ground with multiple authentication scenarios. "
                "Practice target only; never expose it outside the stack.",
    version="1.0.0",
)

# Security middleware (must be added first)
app.add_middleware(SecurityMiddleware)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Static files (if needed)
static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Telemetry collector
telemetry = TelemetryCollector()

# Test users database
TEST_USERS = {
    "testuser@loginlab.local": {
        "password": "TestPass123!",
        "display_name": "Test User",
        "role": "user",
        "active": True,
    },
    "admin@loginlab.local": {
        "password": "AdminPass123!",
        "display_name": "Admin User",
        "role": "admin",
        "active": True,
    },
    "invalid@loginlab.local": {
        "password": "WrongPass123!",
        "display_name": "Invalid User",
        "role": "user",
        "active": False,
    },
}

# Session storage (in-memory for simplicity)
SESSIONS: Dict[str, dict] = {}
MULTIROLE_ACCOUNTS = {
    "admin@lab.local": {
        "password": "Beacon!2024",
        "display": "Avery Stone",
        "role": "Security Operations",
        "slug": "security-admin",
        "tenant": "demo-lab",
        "announcements": [
            "Atlas ingestion completed for 42 new assets.",
            "Credential rotation required for API gateway."
        ],
    },
    "analyst@lab.local": {
        "password": "Analyst#2024",
        "display": "Riley Chen",
        "role": "Application Analyst",
        "slug": "app-analyst",
        "tenant": "demo-lab",
        "announcements": [
            "Two new medium-risk findings assigned to your queue.",
            "LLM enrichment is enabled for your workspace."
        ],
    },
    "billing@lab.local": {
        "password": "Billing$2024",
        "display": "Morgan Patel",
        "role": "Billing Reviewer",
        "slug": "billing-approver",
        "tenant": "demo-billing",
        "announcements": [
            "Next invoice draft available for review.",
            "Access limited to billing dashboards."
        ],
    },
}
MULTIROLE_SESSIONS: Dict[str, dict] = {}


# ==================== Models ====================

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class ScenarioInfo(BaseModel):
    id: str
    name: str
    description: str
    auth_type: str
    difficulty: str
    path: str
    enabled: bool


# ==================== Dependencies ====================

def verify_credentials(username: str, password: str) -> Optional[dict]:
    """Verify username and password against test database."""
    user = TEST_USERS.get(username)
    if not user:
        return None
    if user["password"] != password:
        return None
    if not user["active"]:
        return None
    return {
        "username": username,
        "display_name": user["display_name"],
        "role": user["role"],
    }


def create_session(username: str) -> str:
    """Create a new session and return session ID."""
    session_id = secrets.token_urlsafe(32)
    user = TEST_USERS[username]
    SESSIONS[session_id] = {
        "username": username,
        "display_name": user["display_name"],
        "role": user["role"],
        "created_at": datetime.utcnow().isoformat(),
    }
    return session_id


def get_session(request: Request) -> Optional[dict]:
    """Get session data from cookie."""
    session_id = request.cookies.get("loginlab_session")
    if not session_id:
        return None
    return SESSIONS.get(session_id)


def set_session_cookies(response: Response, session_id: str) -> None:
    """
    Set multiple cookies for testing:
    - loginlab_session: short-lived, HttpOnly
    - loginlab_persistent: longer-lived to test TTL handling
    """
    response.set_cookie(
        key="loginlab_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=3600,  # 1 hour
        path="/",
    )
    response.set_cookie(
        key="loginlab_persistent",
        value=session_id + "_long",
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600,  # 7 days
        path="/",
    )


def create_multirole_session(email: str) -> str:
    """Create a session for the multi-role lab demo."""
    session_id = secrets.token_urlsafe(32)
    account = MULTIROLE_ACCOUNTS[email]
    MULTIROLE_SESSIONS[session_id] = {
        "email": email,
        "display": account["display"],
        "role": account["role"],
        "slug": account["slug"],
        "tenant": account["tenant"],
        "announcements": account["announcements"],
        "created_at": datetime.utcnow().isoformat(),
    }
    return session_id


def get_multirole_session(request: Request) -> Optional[dict]:
    session_id = request.cookies.get("multirole_session")
    if not session_id:
        return None
    return MULTIROLE_SESSIONS.get(session_id)


def clear_multirole_session(session_id: Optional[str]) -> None:
    if session_id and session_id in MULTIROLE_SESSIONS:
        MULTIROLE_SESSIONS.pop(session_id, None)


# ==================== Root & Index Routes ====================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Landing page with scenario index."""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scenarios": [s.dict() for s in SCENARIOS.values()],
            "test_users": [
                {
                    "username": k,
                    "password": v["password"],
                    "role": v["role"],
                }
                for k, v in TEST_USERS.items()
                if v["active"]
            ],
        },
    )


@app.get("/scenarios", response_model=List[ScenarioInfo])
async def list_scenarios():
    """List all available test scenarios."""
    return [s.dict() for s in SCENARIOS.values()]


@app.get("/scenarios/{scenario_id}", response_model=ScenarioInfo)
async def get_scenario_info(scenario_id: str):
    """Get details about a specific scenario."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario.dict()


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "loginlab",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenarios_count": len(SCENARIOS),
        "active_sessions": len(SESSIONS),
        "loginlab_active": is_loginlab_active(),
    }


# ==================== LoginLab Control Endpoints ====================

@app.get("/api/loginlab/status")
async def loginlab_status():
    """Get LoginLab enabled/disabled status."""
    return get_loginlab_status()


@app.post("/api/loginlab/enable")
async def loginlab_enable(request: Request, duration_minutes: int = None):
    """
    Enable LoginLab with auto-disable timer.
    Requires service token authentication.
    """
    # Validate service token
    auth_header = request.headers.get("Authorization", "")
    token_header = request.headers.get("X-Service-Token", "")

    valid_token = False
    if LOGINLAB_SERVICE_TOKEN:
        if auth_header.startswith("Bearer "):
            valid_token = hmac.compare_digest(auth_header[7:], LOGINLAB_SERVICE_TOKEN)
        elif token_header:
            valid_token = hmac.compare_digest(token_header, LOGINLAB_SERVICE_TOKEN)
    else:
        # No token configured - allow (dev mode)
        valid_token = True

    if not valid_token:
        raise HTTPException(status_code=403, detail="Invalid service token")

    enabled_by = request.headers.get("X-User", "unknown")
    result = enable_loginlab(enabled_by=enabled_by, duration_minutes=duration_minutes)
    return result


@app.post("/api/loginlab/disable")
async def loginlab_disable(request: Request):
    """
    Disable LoginLab immediately.
    Requires service token authentication.
    """
    # Validate service token
    auth_header = request.headers.get("Authorization", "")
    token_header = request.headers.get("X-Service-Token", "")

    valid_token = False
    if LOGINLAB_SERVICE_TOKEN:
        if auth_header.startswith("Bearer "):
            valid_token = hmac.compare_digest(auth_header[7:], LOGINLAB_SERVICE_TOKEN)
        elif token_header:
            valid_token = hmac.compare_digest(token_header, LOGINLAB_SERVICE_TOKEN)
    else:
        valid_token = True

    if not valid_token:
        raise HTTPException(status_code=403, detail="Invalid service token")

    return disable_loginlab()


@app.get("/metrics")
async def get_metrics():
    """Get testing metrics."""
    total = telemetry.total_attempts()
    successful = telemetry.successful_attempts()
    return {
        "total_attempts": total,
        "successful_attempts": successful,
        "failed_attempts": total - successful,
        "success_rate": successful / total if total > 0 else 0,
        "scenarios": {
            scenario_id: telemetry.scenario_stats(scenario_id)
            for scenario_id in SCENARIOS.keys()
        },
    }


@app.post("/reset")
async def reset_state():
    """Reset all sessions and telemetry."""
    SESSIONS.clear()
    telemetry.reset()
    return {"status": "reset", "message": "All sessions and telemetry cleared"}


# ==================== Multi-Role Demo ====================

def _multirole_template(name: str, request: Request, context: dict, status_code: int = 200):
    """Helper to render multi-role demo templates."""
    payload = {
        "request": request,
        "accounts": MULTIROLE_ACCOUNTS,
        **context,
    }
    return templates.TemplateResponse(name, payload, status_code=status_code)


@app.get("/lab/multirole", response_class=HTMLResponse)
async def multirole_login_page(request: Request):
    """Login portal for the multi-role demo."""
    return _multirole_template("multirole_login.html", request, {"error": None})


@app.post("/lab/multirole", response_class=HTMLResponse)
async def multirole_login(request: Request):
    form = await request.form()
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", "")).strip()
    account = MULTIROLE_ACCOUNTS.get(email)

    if not account or account["password"] != password:
        return _multirole_template(
            "multirole_login.html",
            request,
            {"error": "Invalid username or password."},
            status_code=401,
        )

    session_id = create_multirole_session(email)
    response = RedirectResponse(url="/lab/multirole/dashboard", status_code=302)
    response.set_cookie(
        "multirole_session",
        session_id,
        httponly=True,
        samesite="lax",
        max_age=3600,
        path="/",
    )
    return response


@app.get("/lab/multirole/dashboard", response_class=HTMLResponse)
async def multirole_dashboard(request: Request):
    session = get_multirole_session(request)
    if not session:
        return RedirectResponse(url="/lab/multirole", status_code=303)
    return _multirole_template(
        "multirole_dashboard.html",
        request,
        {"user": session},
    )


@app.get("/lab/multirole/logout")
async def multirole_logout(request: Request):
    session_id = request.cookies.get("multirole_session")
    clear_multirole_session(session_id)
    response = RedirectResponse(url="/lab/multirole", status_code=303)
    response.delete_cookie("multirole_session", path="/")
    return response


# ==================== Protected/Echo Routes ====================

def require_session(request: Request) -> dict:
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return session


@app.get("/protected", response_class=HTMLResponse)
async def protected_page(request: Request, session: dict = Depends(require_session)):
    """Simple protected page to verify authenticated access works."""
    return templates.TemplateResponse(
        "protected.html",
        {
            "request": request,
            "user": session,
            "cookies": request.cookies,
        },
    )


@app.get("/api/protected")
async def protected_api(request: Request, session: dict = Depends(require_session)):
    """Protected JSON endpoint echoing cookies and user info for scanner verification."""
    return {
        "status": "ok",
        "user": session,
        "cookies": request.cookies,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/echo-cookies")
async def echo_cookies(request: Request):
    """Unauthenticated cookie echo for debugging scanner cookie forwarding."""
    return {
        "cookies": request.cookies,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/protected/action")
async def protected_action(request: Request, session: dict = Depends(require_session)):
    """Authenticated action endpoint to provide a form target for the scanner."""
    form_data = await request.form()
    return JSONResponse(
        {
            "status": "ok",
            "user": session,
            "received": dict(form_data),
            "cookies": request.cookies,
        }
    )


# ==================== Scenario Routes ====================

# Import scenario routers
from .api.scenarios import basic_auth, form_login, multi_step, sso_redirect, ldap_login, api_auth, domain_login, covert_auth

app.include_router(basic_auth.router, tags=["scenarios"])
app.include_router(form_login.router, tags=["scenarios"])
app.include_router(multi_step.router, tags=["scenarios"])
app.include_router(sso_redirect.router, tags=["scenarios"])
app.include_router(ldap_login.router, tags=["scenarios"])
app.include_router(api_auth.router, tags=["scenarios"])
app.include_router(domain_login.router, tags=["scenarios"])
app.include_router(covert_auth.router, tags=["scenarios"])


# ==================== Telemetry Routes ====================

@app.get("/telemetry/{run_id}")
async def get_telemetry(run_id: str):
    """Get captured telemetry for a specific run."""
    entries = telemetry.get_by_run_id(run_id)
    if not entries:
        raise HTTPException(status_code=404, detail="No telemetry found for run")
    return {"run_id": run_id, "entries": entries}


@app.get("/telemetry")
async def list_telemetry(
    scenario: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """List recent telemetry entries."""
    entries = telemetry.list_recent(
        scenario=scenario,
        limit=limit,
        offset=offset,
    )
    return {
        "total": len(entries),
        "limit": limit,
        "offset": offset,
        "entries": entries,
    }


# ==================== Startup/Shutdown Events ====================

@app.on_event("startup")
async def startup_event():
    """Initialize resources on startup."""
    print("LoginLab starting up...")
    print(f"Loaded {len(SCENARIOS)} test scenarios")
    print(f"Loaded {len(TEST_USERS)} test users")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on shutdown."""
    print("LoginLab shutting down...")
    SESSIONS.clear()
