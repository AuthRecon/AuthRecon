"""
LDAP-Style Login Scenario
Domain\\Username format authentication.
"""
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from ...main import verify_credentials, create_session, telemetry, templates

router = APIRouter()


def parse_ldap_username(username: str) -> str:
    """Parse LDAP-style username (DOMAIN\\user or user@domain)."""
    if "\\" in username:
        # Extract username from DOMAIN\\username format
        parts = username.split("\\", 1)
        if len(parts) == 2:
            return parts[1]  # Return username part
    return username  # Already in email format


@router.get("/ldap-login", response_class=HTMLResponse)
async def ldap_login_page(request: Request):
    """Display LDAP-style login form."""
    from ...main import get_session
    session = get_session(request)
    if session:
        return RedirectResponse(url="/ldap-login/dashboard", status_code=302)

    return templates.TemplateResponse(
        "ldap_login.html",
        {"request": request},
    )


@router.post("/ldap-login")
async def ldap_login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    """Handle LDAP-style login submission."""
    # Parse LDAP username format
    parsed_username = parse_ldap_username(username)

    telemetry_data = {
        "method": request.method,
        "path": str(request.url.path),
        "username_raw": username,
        "username_parsed": parsed_username,
        "format": "ldap" if "\\" in username else "email",
    }

    # Verify credentials
    user = verify_credentials(parsed_username, password)

    if not user:
        telemetry.record(
            scenario="ldap-login",
            request_data=telemetry_data,
            response_data={
                "status": 401,
                "error": "Invalid credentials",
            },
            detection_hints={
                "auth_type": "ldap_form",
                "auth_failed": True,
                "username_format": "ldap" if "\\" in username else "email",
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        return templates.TemplateResponse(
            "ldap_login.html",
            {
                "request": request,
                "error": "Invalid credentials. Try DOMAIN\\username or email format.",
            },
            status_code=401,
        )

    # Create session
    session_id = create_session(parsed_username)

    telemetry.record(
        scenario="ldap-login",
        request_data=telemetry_data,
        response_data={
            "status": 302,
            "redirect": "/ldap-login/dashboard",
            "session_created": True,
        },
        detection_hints={
            "auth_type": "ldap_form",
            "auth_successful": True,
            "username_format": "ldap" if "\\" in username else "email",
            "user_role": user["role"],
        },
        success=True,
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    redirect = RedirectResponse(url="/ldap-login/dashboard", status_code=302)
    redirect.set_cookie(
        key="loginlab_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )
    return redirect


@router.get("/ldap-login/dashboard", response_class=HTMLResponse)
async def ldap_login_dashboard(request: Request):
    """Authenticated dashboard."""
    from ...main import get_session
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/ldap-login", status_code=302)

    return templates.TemplateResponse(
        "ldap_dashboard.html",
        {
            "request": request,
            "user": session,
        },
    )
