"""
HTTPX-based HTTP Basic Authentication.

WHY HTTPX FOR BASIC AUTH:
- No browser needed (Basic Auth is HTTP-level, not form-based)
- 100x faster than Selenium/Playwright (~100ms vs ~10s)
- Captures complete HTTP exchange (request headers, response headers, cookies)
- Lightweight - no ChromeDriver/browser binary overhead
- Perfect for API authentication testing

WHEN TO USE:
- HTTP Basic Auth (401 WWW-Authenticate challenge)
- API endpoints requiring Authorization header
- Services using .htaccess password protection
- Legacy systems with Basic Auth

WHEN NOT TO USE:
- Form-based authentication (use Playwright/Selenium instead)
- JavaScript-heavy SPAs (HTTPX doesn't execute JavaScript)
- OAuth flows (requires browser for redirects)

OUTPUT ARTIFACTS:
- Cookies: Session cookies if server sets any
- Headers: Complete request/response headers
- Timeline: HTTP request/response sequence (lightweight JSON)
- Security context: Authentication headers, cookie security

NO ARTIFACTS:
- Screenshots (headless HTTP client, no visual output)
- HAR files (can generate simplified timeline instead)
- .side files (no browser automation)

SPEED COMPARISON:
- Selenium form auth: ~10-15 seconds
- Playwright form auth: ~8-12 seconds
- HTTPX Basic Auth: ~0.1-0.5 seconds (100x faster!)
"""

from app.services.live_timeline import live_events
import httpx
import json
import base64
from datetime import datetime, timezone
from typing import List, Dict, Any

from app.services.automation.types import FormAuthResult, RecordedAction


async def attempt_basic_auth_httpx(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 30,
) -> FormAuthResult:
    """
    Attempt HTTP Basic Authentication using HTTPX (fast, headless).

    BASIC AUTH FLOW:
    1. Send GET request to target
    2. Receive 401 Unauthorized with WWW-Authenticate header
    3. Retry with Authorization: Basic <base64(username:password)>
    4. Receive 200 OK with session cookies (if successful)
    5. Extract headers, cookies, response body
    6. Return lightweight timeline (no HAR, no screenshots)

    Args:
        run_id: Unique identifier for this auth run
        target_url: Protected URL requiring Basic Auth
        username: Username for authentication
        password: Password for authentication
        timeout_seconds: Max time to wait for response (default 30s)

    Returns:
        FormAuthResult with:
            - success: True if 200 OK received (or 30x redirect to protected resource)
            - final_url: URL after authentication
            - cookies: Session cookies from server
            - timeline_json: HTTP request/response sequence (lightweight)
            - events: Authentication flow steps
            - recorded_actions: Authorization header for replay
            - NO screenshots, NO HAR (HTTPX is headless)

    Raises:
        ValueError: If username or password not provided
    """

    if not username:
        raise ValueError("Username required for Basic Auth")
    if not password:
        raise ValueError("Password required for Basic Auth")

    events: List[str] = live_events()
    recorded_actions: List[RecordedAction] = []
    timeline: List[Dict[str, Any]] = []

    # Encode credentials for Basic Auth
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    auth_header = f"Basic {encoded_credentials}"

    events.append(f"Attempting HTTP Basic Auth to: {target_url}")
    events.append(f"Username: {username}")

    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=True,  # Follow 30x redirects automatically
        verify=True,  # Verify SSL certificates (can be disabled for testing)
    ) as client:
        try:
            # Step 1: Initial request without auth (expect 401)
            start_time = datetime.now(timezone.utc)
            events.append("Sending initial request without authentication...")

            try:
                response_initial = await client.get(target_url)
                events.append(f"Initial response: {response_initial.status_code}")

                timeline.append({
                    "timestamp": start_time.isoformat(),
                    "method": "GET",
                    "url": target_url,
                    "status_code": response_initial.status_code,
                    "headers_sent": dict(response_initial.request.headers),
                    "headers_received": dict(response_initial.headers),
                    "note": "Initial request without auth"
                })

                # Check if Basic Auth is required
                if response_initial.status_code == 401:
                    www_auth = response_initial.headers.get("WWW-Authenticate", "")
                    events.append(f"401 Unauthorized received - WWW-Authenticate: {www_auth}")

                    if "basic" not in www_auth.lower():
                        events.append(f"Warning: Expected Basic auth, got: {www_auth}")
                elif response_initial.status_code == 200:
                    # No auth required! Resource is publicly accessible
                    events.append("No authentication required (200 OK without credentials)")
                    return FormAuthResult(
                        success=True,
                        final_url=str(response_initial.url),
                        events=events,
                        cookies=[{"name": k, "value": v} for k, v in response_initial.cookies.items()],
                        recorded_actions=[],
                        timeline_json=json.dumps(timeline, indent=2).encode(),
                        username_selector="[HTTP Basic Auth]",
                        password_selector="[HTTP Basic Auth]",
                        submit_selector="[HTTP Basic Auth]",
                        submit_method="http_basic_auth",
                    )
            except httpx.HTTPStatusError:
                pass  # Expected for 401

            # Step 2: Retry with Basic Auth header
            auth_start = datetime.now(timezone.utc)
            events.append("Sending authenticated request with Authorization header...")

            headers = {
                "Authorization": auth_header,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }

            response_auth = await client.get(target_url, headers=headers)
            events.append(f"Authenticated response: {response_auth.status_code}")

            timeline.append({
                "timestamp": auth_start.isoformat(),
                "method": "GET",
                "url": target_url,
                "status_code": response_auth.status_code,
                "headers_sent": dict(response_auth.request.headers),
                "headers_received": dict(response_auth.headers),
                "note": "Authenticated request with Basic Auth"
            })

            recorded_actions.append(RecordedAction(
                action="set_header",
                selector="Authorization",
                value=f"Basic <base64({username}:{password})>",
                note="HTTP Basic Auth header"
            ))

            # Check if authentication succeeded
            if response_auth.status_code in [200, 201, 202, 203, 204]:
                events.append(f"Authentication succeeded! Status: {response_auth.status_code}")

                # Extract cookies
                cookies = [
                    {
                        "name": name,
                        "value": value,
                        "domain": target_url.split('/')[2] if '//' in target_url else "",
                        "path": "/",
                        "httpOnly": True,  # Assume HttpOnly for Basic Auth cookies
                    }
                    for name, value in response_auth.cookies.items()
                ]

                events.append(f"Extracted {len(cookies)} cookies from response")

                return FormAuthResult(
                    success=True,
                    final_url=str(response_auth.url),
                    events=events,
                    cookies=cookies,
                    recorded_actions=recorded_actions,
                    timeline_json=json.dumps(timeline, indent=2).encode(),
                    username_selector="[HTTP Basic Auth]",
                    password_selector="[HTTP Basic Auth]",
                    submit_selector="[HTTP Basic Auth]",
                    submit_method="http_basic_auth",
                )

            elif response_auth.status_code == 401:
                events.append("Authentication failed: Credentials rejected (401 Unauthorized)")

                return FormAuthResult(
                    success=False,
                    final_url=str(response_auth.url),
                    events=events,
                    cookies=[],
                    recorded_actions=recorded_actions,
                    timeline_json=json.dumps(timeline, indent=2).encode(),
                )

            elif response_auth.status_code in [403]:
                events.append("Authentication failed: Access forbidden (403 Forbidden)")

                return FormAuthResult(
                    success=False,
                    final_url=str(response_auth.url),
                    events=events,
                    cookies=[],
                    recorded_actions=recorded_actions,
                    timeline_json=json.dumps(timeline, indent=2).encode(),
                )

            else:
                events.append(f"Unexpected status code: {response_auth.status_code}")

                return FormAuthResult(
                    success=False,
                    final_url=str(response_auth.url),
                    events=events,
                    cookies=[],
                    recorded_actions=recorded_actions,
                    timeline_json=json.dumps(timeline, indent=2).encode(),
                )

        except httpx.TimeoutException as e:
            events.append(f"Request timeout: {str(e)}")
            return FormAuthResult(
                success=False,
                final_url=target_url,
                events=events,
                cookies=[],
                recorded_actions=recorded_actions,
                timeline_json=json.dumps(timeline, indent=2).encode(),
            )

        except httpx.HTTPError as e:
            events.append(f"HTTP error: {str(e)}")
            return FormAuthResult(
                success=False,
                final_url=target_url,
                events=events,
                cookies=[],
                recorded_actions=recorded_actions,
                timeline_json=json.dumps(timeline, indent=2).encode(),
            )

        except Exception as e:
            events.append(f"Unexpected error: {str(e)}")
            return FormAuthResult(
                success=False,
                final_url=target_url,
                events=events,
                cookies=[],
                recorded_actions=recorded_actions,
                timeline_json=json.dumps(timeline, indent=2).encode(),
            )
