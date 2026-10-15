"""
SSO-Style Redirect Scenario
OAuth-like flow with state parameter and redirects.
"""
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import secrets

from ...main import verify_credentials, create_session, telemetry, templates, set_session_cookies

router = APIRouter()

# State storage for OAuth-like flow
STATE_STORAGE = {}


@router.get("/sso-redirect", response_class=HTMLResponse)
async def sso_redirect_start(request: Request):
    """Initiate SSO-like flow with state parameter."""
    # Generate state parameter
    state = secrets.token_urlsafe(32)
    STATE_STORAGE[state] = {
        "created_at": "timestamp",
        "redirect_uri": request.query_params.get("redirect_uri", "/"),
    }

    # Redirect to authorization page
    return RedirectResponse(
        url=f"/sso-redirect/authorize?state={state}",
        status_code=302,
    )


@router.get("/sso-redirect/authorize", response_class=HTMLResponse)
async def sso_redirect_authorize(request: Request, state: str):
    """Show authorization/login page."""
    if state not in STATE_STORAGE:
        return HTMLResponse("Invalid state parameter", status_code=400)

    return templates.TemplateResponse(
        "sso_redirect_login.html",
        {
            "request": request,
            "state": state,
        },
    )


@router.post("/sso-redirect/authorize")
async def sso_redirect_authorize_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    state: str = Form(...),
):
    """Handle authorization submission."""
    if state not in STATE_STORAGE:
        return HTMLResponse("Invalid state parameter", status_code=400)

    user = verify_credentials(username, password)

    if not user:
        telemetry.record(
            scenario="sso-redirect",
            request_data={
                "username": username,
                "state": state,
            },
            response_data={"status": 401},
            detection_hints={
                "auth_type": "oauth_redirect",
                "auth_failed": True,
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        return templates.TemplateResponse(
            "sso_redirect_login.html",
            {
                "request": request,
                "state": state,
                "error": "Invalid credentials",
            },
            status_code=401,
        )

    # Generate authorization code
    code = secrets.token_urlsafe(32)
    session_id = create_session(username)

    telemetry.record(
        scenario="sso-redirect",
        request_data={
            "username": username,
            "state": state,
        },
        response_data={
            "status": 302,
            "code": code,
        },
        detection_hints={
            "auth_type": "oauth_redirect",
            "auth_successful": True,
            "user_role": user["role"],
        },
        success=True,
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    redirect = RedirectResponse(
        url=f"/sso-redirect/callback?code={code}&state={state}",
        status_code=302,
    )
    set_session_cookies(redirect, session_id)
    return redirect


@router.get("/sso-redirect/callback", response_class=HTMLResponse)
async def sso_redirect_callback(request: Request, code: str, state: str):
    """Handle OAuth-like callback, then send the user to a stable app page
    (like real apps do), so the one-time code never ends up in a bookmark or
    a scanner's "page to verify"."""
    from ...main import get_session
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/sso-redirect", status_code=302)
    STATE_STORAGE.pop(state, None)
    return RedirectResponse(url="/sso-redirect/home", status_code=302)


@router.get("/sso-redirect/home", response_class=HTMLResponse)
async def sso_redirect_home(request: Request):
    """The application's signed-in home page."""
    from ...main import get_session
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/sso-redirect", status_code=302)

    return templates.TemplateResponse(
        "sso_redirect_dashboard.html",
        {
            "request": request,
            "user": session,
        },
    )
