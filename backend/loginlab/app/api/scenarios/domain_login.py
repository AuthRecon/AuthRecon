"""
Domain/tenant select + checkbox-gated form login behind a reveal button.
"""
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from ...main import verify_credentials, create_session, get_session, telemetry, templates, set_session_cookies

router = APIRouter()

DOMAINS = ["acme.local", "corp.local", "demo.lab"]


def _normalize_username(username: str, domain: str) -> list[str]:
    candidates = []
    raw = username.strip()
    domain = domain.strip()
    if raw:
        candidates.append(raw)
        if "\\" in raw:
            candidates.append(raw.split("\\")[-1])
        if "@" in raw:
            # Keep as-is; also try stripping domain portion
            left = raw.split("@")[0]
            candidates.append(left)
        if domain:
            candidates.append(f"{raw}@{domain}")
            candidates.append(f"{domain}\\{raw}")
    return list(dict.fromkeys([c for c in candidates if c]))


@router.get("/form-login-domain", response_class=HTMLResponse)
async def domain_form_page(request: Request):
    """Show a form with domain dropdown, checkbox, and reveal toggle."""
    session = get_session(request)
    if session:
        return RedirectResponse(url="/form-login-domain/dashboard", status_code=302)

    return templates.TemplateResponse(
        "domain_login.html",
        {
            "request": request,
            "domains": DOMAINS,
            "error": None,
        },
    )


@router.post("/form-login-domain")
async def domain_form_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    domain: str = Form(""),
    consent: str = Form(None),
):
    """Handle login form submission with domain select and required checkbox."""
    if consent is None:
        return templates.TemplateResponse(
            "domain_login.html",
            {
                "request": request,
                "domains": DOMAINS,
                "error": "Please accept the access terms to continue.",
                "username": username,
                "domain_selected": domain,
            },
            status_code=400,
        )

    request_data = {
        "method": request.method,
        "path": str(request.url.path),
        "headers": dict(request.headers),
        "username": username,
        "domain": domain,
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
    }

    user = None
    for candidate in _normalize_username(username, domain):
        user = verify_credentials(candidate, password)
        if user:
            username = candidate
            break

    if not user:
        telemetry.record(
            scenario="form-login-domain",
            request_data=request_data,
            response_data={
                "status": 401,
                "error": "Invalid credentials",
            },
            detection_hints={
                "auth_type": "form_post",
                "auth_failed": True,
                "form_fields": ["username", "password", "domain", "consent_checkbox"],
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )
        return templates.TemplateResponse(
            "domain_login.html",
            {
                "request": request,
                "domains": DOMAINS,
                "error": "Invalid username or password.",
                "username": username,
                "domain_selected": domain,
            },
            status_code=401,
        )

    session_id = create_session(username)
    telemetry.record(
        scenario="form-login-domain",
        request_data=request_data,
        response_data={
            "status": 302,
            "redirect": "/form-login-domain/dashboard",
            "session_created": True,
            "domain": domain,
        },
        detection_hints={
            "auth_type": "form_post",
            "auth_successful": True,
            "session_cookie": "loginlab_session",
            "user_role": user["role"],
            "domain": domain,
        },
        success=True,
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    redirect = RedirectResponse(url="/form-login-domain/dashboard", status_code=302)
    set_session_cookies(redirect, session_id)
    return redirect


@router.get("/form-login-domain/dashboard", response_class=HTMLResponse)
async def domain_form_dashboard(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/form-login-domain", status_code=302)
    return templates.TemplateResponse(
        "domain_dashboard.html",
        {
            "request": request,
            "user": session,
        },
    )
