"""
Demo Pages - Beautiful login pages for screenshots and demos.

These pages simulate various SSO providers for visual demos of AuthRecon.
They're intentionally designed to look professional for testing and screenshots.
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

router = APIRouter(tags=["demo"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Demo credentials (all pages use the same for simplicity)
DEMO_CREDENTIALS = {
    # Microsoft
    "user@contoso.com": "AzureDemo123!",
    # Okta
    "demo.user": "OktaDemo123!",
    # Google
    "demo@example.com": "GoogleDemo123!",
    # Corporate
    "enterprise.user": "SecureDemo123!",
    # Generic fallbacks
    "testuser@loginlab.local": "TestPass123!",
    "admin@loginlab.local": "AdminPass123!",
}


def _verify_demo_creds(username: str, password: str) -> bool:
    """Verify demo credentials."""
    username_lower = username.lower().strip()
    return DEMO_CREDENTIALS.get(username_lower) == password


# ==================== Microsoft Demo ====================

@router.get("/demo/microsoft", response_class=HTMLResponse)
async def microsoft_demo_page(request: Request):
    """Microsoft/Azure AD style login page."""
    return templates.TemplateResponse(
        "demo_microsoft.html",
        {"request": request, "error": None}
    )


@router.post("/demo/microsoft", response_class=HTMLResponse)
async def microsoft_demo_login(request: Request):
    """Handle Microsoft demo login."""
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", "")).strip()

    if not _verify_demo_creds(username, password):
        return templates.TemplateResponse(
            "demo_microsoft.html",
            {"request": request, "error": "Your account or password is incorrect. If you don't remember your password, reset it now."},
            status_code=401
        )

    return RedirectResponse(url="/demo/success?provider=microsoft", status_code=302)


# ==================== Okta Demo ====================

@router.get("/demo/okta", response_class=HTMLResponse)
async def okta_demo_page(request: Request):
    """Okta style login page."""
    return templates.TemplateResponse(
        "demo_okta.html",
        {"request": request, "error": None}
    )


@router.post("/demo/okta", response_class=HTMLResponse)
async def okta_demo_login(request: Request):
    """Handle Okta demo login."""
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", "")).strip()

    if not _verify_demo_creds(username, password):
        return templates.TemplateResponse(
            "demo_okta.html",
            {"request": request, "error": "Unable to sign in. Please check your username and password."},
            status_code=401
        )

    return RedirectResponse(url="/demo/success?provider=okta", status_code=302)


# ==================== Google Demo ====================

@router.get("/demo/google", response_class=HTMLResponse)
async def google_demo_page(request: Request):
    """Google OAuth style login page."""
    return templates.TemplateResponse(
        "demo_google.html",
        {"request": request, "error": None}
    )


@router.post("/demo/google", response_class=HTMLResponse)
async def google_demo_login(request: Request):
    """Handle Google demo login."""
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", "")).strip()

    if not _verify_demo_creds(username, password):
        return templates.TemplateResponse(
            "demo_google.html",
            {"request": request, "error": "Couldn't find your Google Account"},
            status_code=401
        )

    return RedirectResponse(url="/demo/success?provider=google", status_code=302)


# ==================== Corporate SSO Portal Demo ====================

@router.get("/demo/corporate-sso", response_class=HTMLResponse)
async def corporate_sso_demo_page(request: Request):
    """Corporate SSO portal with multiple options."""
    return templates.TemplateResponse(
        "demo_corporate_sso.html",
        {"request": request, "error": None}
    )


@router.post("/demo/corporate-sso", response_class=HTMLResponse)
async def corporate_sso_demo_login(request: Request):
    """Handle Corporate SSO demo login."""
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", "")).strip()

    if not _verify_demo_creds(username, password):
        return templates.TemplateResponse(
            "demo_corporate_sso.html",
            {"request": request, "error": "Authentication failed. Please check your credentials and try again."},
            status_code=401
        )

    return RedirectResponse(url="/demo/success?provider=corporate", status_code=302)


# ==================== Success Page ====================

@router.get("/demo/success", response_class=HTMLResponse)
async def demo_success_page(request: Request, provider: str = "unknown"):
    """Success page after demo login."""
    provider_names = {
        "microsoft": "Microsoft Azure AD",
        "okta": "Okta",
        "google": "Google",
        "corporate": "Enterprise SSO",
    }
    provider_display = provider_names.get(provider, provider.title())

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Successful</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: system-ui, sans-serif;
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .success-card {{
                background: white;
                border-radius: 24px;
                padding: 48px;
                text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                max-width: 400px;
                width: 100%;
            }}
            .success-icon {{
                width: 80px;
                height: 80px;
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 24px;
            }}
            .success-icon svg {{
                width: 40px;
                height: 40px;
                color: white;
            }}
            h1 {{
                font-size: 24px;
                color: #1f2937;
                margin-bottom: 8px;
            }}
            p {{
                color: #6b7280;
                margin-bottom: 24px;
            }}
            .provider-badge {{
                display: inline-block;
                background: #ecfdf5;
                color: #059669;
                padding: 8px 16px;
                border-radius: 9999px;
                font-size: 14px;
                font-weight: 500;
                margin-bottom: 24px;
            }}
            .btn {{
                display: inline-block;
                padding: 12px 24px;
                background: #10b981;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 500;
                transition: background 0.2s;
            }}
            .btn:hover {{
                background: #059669;
            }}
            .back-link {{
                display: block;
                margin-top: 16px;
                color: #6b7280;
                text-decoration: none;
                font-size: 14px;
            }}
            .back-link:hover {{
                color: #10b981;
            }}
        </style>
    </head>
    <body>
        <div class="success-card">
            <div class="success-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <path d="M20 6L9 17l-5-5"/>
                </svg>
            </div>
            <h1>Authentication Successful!</h1>
            <p>You have been authenticated via</p>
            <div class="provider-badge">{provider_display}</div>
            <p style="font-size: 14px; color: #9ca3af;">
                This demo login was captured by AuthRecon for analysis.
            </p>
            <a href="/" class="btn">Back to Demo Pages</a>
            <a href="/" class="back-link">← Return to LoginLab</a>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
