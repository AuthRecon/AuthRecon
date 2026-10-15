"""
Covert Auth Scenario — hard difficulty.

Deliberately defeats AuthRecon's heuristic auth-element discovery
(app/services/automation/pre_run_discovery.py), which requires an actual
<form> element and an input[type='password'] to find anything:
- No <form> tag at all — fields sit in a plain <div>, submitted via a JS
  fetch() call to a JSON endpoint, not a form POST.
- The password-equivalent field is input[type='text'], visually masked
  with the -webkit-text-security CSS property instead of type='password'.
- Neither field's name/id/placeholder/aria-label contains any of the
  keywords the heuristic's CSS selectors look for (user/email/login/
  account) — labels are visible to a human (or a model reading the DOM)
  but the machine-readable attributes are generic (field_a/field_b).

This exists to give the ai_fallback / MCP-assisted retry path (see
SECURITY.md) something genuine to solve: a case the rule-based
library can't classify by design, not just one that looks hard to a
human. A model reading the sanitized page HTML can still work out which
field is which from the visible label text and the JS submit handler.
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from ...main import verify_credentials, create_session, get_session, telemetry, templates, set_session_cookies

router = APIRouter()


@router.get("/covert-auth", response_class=HTMLResponse)
async def covert_auth_page(request: Request):
    session = get_session(request)
    if session:
        return RedirectResponse(url="/covert-auth/dashboard", status_code=302)

    return templates.TemplateResponse(
        "covert_login.html",
        {"request": request, "error": None},
    )


@router.post("/covert-auth/submit")
async def covert_auth_submit(request: Request):
    """
    JSON endpoint the page's JS fetch() call POSTs to — deliberately not a
    form POST, so there's nothing here for form-discovery heuristics to
    find even if they went looking at the network layer instead of the DOM.
    """
    body = await request.json()
    field_a = str(body.get("field_a", ""))
    field_b = str(body.get("field_b", ""))

    request_data = {
        "method": "POST",
        "path": "/covert-auth/submit",
        "headers": dict(request.headers),
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
    }

    user = verify_credentials(field_a, field_b)

    if not user:
        telemetry.record(
            scenario="covert-auth",
            request_data=request_data,
            response_data={"status": 401, "error": "Invalid credentials"},
            detection_hints={
                "auth_type": "js_widget_auth",
                "auth_failed": True,
                "note": "No <form> element; fields submitted via fetch() to this JSON endpoint",
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    session_id = create_session(field_a)

    telemetry.record(
        scenario="covert-auth",
        request_data=request_data,
        response_data={"status": 200, "redirect": "/covert-auth/dashboard", "session_created": True},
        detection_hints={
            "auth_type": "js_widget_auth",
            "auth_successful": True,
            "session_cookie": "loginlab_session",
            "user_role": user["role"],
        },
        success=True,
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    response = JSONResponse({"redirect": "/covert-auth/dashboard"})
    set_session_cookies(response, session_id)
    return response


@router.get("/covert-auth/dashboard", response_class=HTMLResponse)
async def covert_auth_dashboard(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse(url="/covert-auth", status_code=302)

    return templates.TemplateResponse(
        "covert_dashboard.html",
        {"request": request, "user": session},
    )


@router.get("/covert-auth/logout")
async def covert_auth_logout(request: Request):
    redirect = RedirectResponse(url="/covert-auth", status_code=302)
    redirect.delete_cookie("loginlab_session")
    return redirect
