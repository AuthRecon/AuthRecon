"""
Single-Form Login Scenario
Standard HTML form with username/password POST.
"""
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from ...main import verify_credentials, create_session, get_session, telemetry, templates, set_session_cookies

router = APIRouter()


@router.get("/form-login", response_class=HTMLResponse)
async def form_login_page(request: Request):
    """Display login form."""
    # Check if already authenticated
    session = get_session(request)
    if session:
        return RedirectResponse(url="/form-login/dashboard", status_code=302)

    # Show login form
    return templates.TemplateResponse(
        "form_login.html",
        {"request": request},
    )


@router.post("/form-login")
async def form_login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    """Handle login form submission."""
    # Capture telemetry
    request_data = {
        "method": request.method,
        "path": str(request.url.path),
        "headers": dict(request.headers),
        "username": username,
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
    }

    # Verify credentials
    user = verify_credentials(username, password)

    if not user:
        # Authentication failed
        telemetry.record(
            scenario="form-login",
            request_data=request_data,
            response_data={
                "status": 401,
                "error": "Invalid credentials",
            },
            detection_hints={
                "auth_type": "form_post",
                "auth_failed": True,
                "form_fields": ["username", "password"],
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        return templates.TemplateResponse(
            "form_login.html",
            {
                "request": request,
                "error": "Invalid username or password. Please try again.",
            },
            status_code=401,
        )

    # Create session
    session_id = create_session(username)

    # Success telemetry
    telemetry.record(
        scenario="form-login",
        request_data=request_data,
        response_data={
            "status": 302,
            "redirect": "/form-login/dashboard",
            "session_created": True,
        },
        detection_hints={
            "auth_type": "form_post",
            "auth_successful": True,
            "session_cookie": "loginlab_session",
            "user_role": user["role"],
        },
        success=True,
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    # Set session cookie and redirect
    redirect = RedirectResponse(url="/form-login/dashboard", status_code=302)
    set_session_cookies(redirect, session_id)
    return redirect


@router.get("/form-login/dashboard", response_class=HTMLResponse)
async def form_login_dashboard(request: Request):
    """Authenticated dashboard page."""
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/form-login", status_code=302)

    return templates.TemplateResponse(
        "form_dashboard.html",
        {
            "request": request,
            "user": session,
        },
    )


@router.get("/form-login/logout")
async def form_login_logout(request: Request, response: Response):
    """Logout and clear session."""
    redirect = RedirectResponse(url="/form-login", status_code=302)
    redirect.delete_cookie("loginlab_session")
    return redirect
