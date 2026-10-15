"""
Multi-Step Login Scenario
Email entry → Password entry (separate pages).
"""
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import secrets

from ...main import verify_credentials, create_session, telemetry, templates, set_session_cookies

router = APIRouter()

EMAIL_TOKENS = {}


@router.get("/multi-step", response_class=HTMLResponse)
async def multi_step_start(request: Request):
    """Step 1: Email entry."""
    return templates.TemplateResponse(
        "multi_step_email.html",
        {"request": request},
    )


@router.post("/multi-step/email")
async def multi_step_email_submit(
    request: Request,
    email: str = Form(...),
):
    """Handle email submission and show password page."""
    # Generate state token
    state_token = secrets.token_urlsafe(32)
    EMAIL_TOKENS[state_token] = email

    telemetry.record(
        scenario="multi-step",
        request_data={
            "step": 1,
            "email": email,
            "path": "/multi-step/email",
        },
        response_data={
            "status": 200,
            "next_step": "/multi-step/password",
        },
        detection_hints={
            "auth_type": "multi_step_form",
            "step": "email_entered",
            "state_token": state_token,
        },
        success=False,  # Not complete yet
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    return templates.TemplateResponse(
        "multi_step_password.html",
        {
            "request": request,
            "email": email,
            "state": state_token,
        },
    )


@router.post("/multi-step/password")
async def multi_step_password_submit(
    request: Request,
    response: Response,
    password: str = Form(...),
    state: str = Form(...),
):
    """Handle password submission."""
    # Retrieve email from state
    email = EMAIL_TOKENS.get(state)
    if not email:
        return templates.TemplateResponse(
            "multi_step_email.html",
            {
                "request": request,
                "error": "Session expired. Please start again.",
            },
            status_code=400,
        )

    # Verify credentials
    user = verify_credentials(email, password)

    if not user:
        telemetry.record(
            scenario="multi-step",
            request_data={
                "step": 2,
                "email": email,
                "path": "/multi-step/password",
            },
            response_data={
                "status": 401,
                "error": "Invalid credentials",
            },
            detection_hints={
                "auth_type": "multi_step_form",
                "step": "password_failed",
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        return templates.TemplateResponse(
            "multi_step_password.html",
            {
                "request": request,
                "email": email,
                "state": state,
                "error": "Invalid password. Please try again.",
            },
            status_code=401,
        )

    # Clean up state
    del EMAIL_TOKENS[state]

    # Create session
    session_id = create_session(email)

    telemetry.record(
        scenario="multi-step",
        request_data={
            "step": 2,
            "email": email,
            "path": "/multi-step/password",
        },
        response_data={
            "status": 302,
            "redirect": "/multi-step/dashboard",
            "session_created": True,
        },
        detection_hints={
            "auth_type": "multi_step_form",
            "step": "complete",
            "auth_successful": True,
            "user_role": user["role"],
        },
        success=True,
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    redirect = RedirectResponse(url="/multi-step/dashboard", status_code=302)
    set_session_cookies(redirect, session_id)
    return redirect


@router.get("/multi-step/dashboard", response_class=HTMLResponse)
async def multi_step_dashboard(request: Request):
    """Authenticated dashboard."""
    from ...main import get_session
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/multi-step", status_code=302)

    return templates.TemplateResponse(
        "multi_step_dashboard.html",
        {
            "request": request,
            "user": session,
        },
    )
