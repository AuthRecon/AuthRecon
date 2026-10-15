"""
HTTPX-based form authentication (headless, fast).

WHY HTTPX:
- FAST: ~100x faster than browser automation (no rendering, just HTTP)
- Lightweight: No browser overhead, minimal memory
- API-first: Perfect for JSON/REST authentication endpoints
- HTTP/2 support: Modern protocol handling
- Session management: Automatic cookie handling

WHEN TO USE:
- API-based authentication (POST /api/auth with JSON)
- Simple form auth where JavaScript isn't required
- High-volume testing (can run hundreds of parallel sessions)
- Headless CI/CD environments
- When you just need cookies, not screenshots/HAR

WHEN NOT TO USE:
- JavaScript-heavy login flows (use Playwright/Selenium)
- CAPTCHA/2FA challenges (need browser rendering)
- OAuth/SAML redirects (complex state management)
- When you need .side files for Tenable (use Selenium)
- When you need HAR files (use Playwright)

OUTPUT ARTIFACTS:
- Cookies: Session tokens (same format as Selenium/Playwright)
- Response data: Status codes, headers, body
- Security context: Headers (CSP, CORS, HSTS) from responses
- Timeline events: Request/response log

COMPARISON:
- Selenium: ~5 req/s, .side files, screenshots, heavy
- Playwright: ~15 req/s, HAR files, screenshots, modern
- HTTPX: ~500 req/s, cookies only, minimal overhead ⚡

USE CASE EXAMPLE:
  Modern SPA with JWT auth:
    POST /api/auth/login {"username": "admin", "password": "secret"}
    Response: {"token": "eyJhbG...", "expires": 3600}

  HTTPX can handle this in ~50ms vs Playwright's ~2000ms
"""

from app.services.live_timeline import live_events
import httpx
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from ..types import FormAuthResult, RecordedAction, ScreenshotCapture


async def attempt_form_login_httpx(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 30,
) -> FormAuthResult:
    """
    Attempt form-based authentication using HTTPX (headless HTTP client).

    AUTHENTICATION STRATEGIES:
    1. Detect auth endpoint:
       - Look for <form action="/login"> in HTML
       - Common API patterns: /api/auth, /api/login, /auth/login
       - Try form submission with credentials

    2. Submit credentials:
       - Form-encoded: username=admin&password=secret
       - JSON API: {"username": "admin", "password": "secret"}

    3. Follow redirects:
       - Track cookies across redirect chain
       - Detect success via status codes (200, 302)

    Args:
        run_id: Unique identifier for this auth run
        target_url: Login page URL or API endpoint
        username: Username/email for authentication
        password: Password for authentication
        timeout_seconds: Max time for HTTP requests

    Returns:
        FormAuthResult with:
            - success: True if HTTP auth succeeded (200 OK + cookies)
            - final_url: URL after auth flow
            - cookies: Session cookies from Set-Cookie headers
            - security_context: Headers (CSP, HSTS, CORS)
            - events: HTTP request/response timeline
            - har_bytes: None (HTTPX doesn't generate HAR)
            - screenshots: [] (no browser rendering)

    Raises:
        AutomationFailure: If no auth endpoint found or HTTP errors
    """

    events: List[str] = live_events()
    recorded_actions: List[RecordedAction] = []

    # Create HTTPX client with cookie jar
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout_seconds,
        headers={
            'User-Agent': 'AuthRecon/1.0 (HTTPX Engine)',
        }
    ) as client:

        events.append("Initializing HTTPX client")

        # STEP 1: Fetch login page to detect form/API endpoint
        events.append(f"Fetching login page: {target_url}")

        try:
            response = await client.get(target_url)
            pre_auth_html = response.text
            events.append(f"GET {target_url} → {response.status_code}")
        except httpx.RequestError as e:
            events.append(f"❌ Request failed: {e}")
            raise Exception(f"Failed to fetch login page: {e}")

        # STEP 2: Detect authentication endpoint
        auth_endpoint = None
        is_json_api = False

        # Try to find <form> in HTML
        soup = BeautifulSoup(pre_auth_html, 'html.parser')
        form = soup.find('form')

        if form and form.get('action'):
            # Traditional HTML form
            auth_endpoint = urljoin(target_url, form['action'])
            events.append(f"Detected HTML form → {auth_endpoint}")
        else:
            # Try common API endpoints
            api_paths = ['/api/auth/login', '/api/login', '/auth/login', '/login']
            base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

            for path in api_paths:
                test_endpoint = urljoin(base_url, path)
                events.append(f"Probing API endpoint: {test_endpoint}")

                try:
                    # OPTIONS request to check if endpoint exists
                    options_resp = await client.options(test_endpoint)
                    if options_resp.status_code < 400:
                        auth_endpoint = test_endpoint
                        is_json_api = True
                        events.append(f"✅ Found API endpoint: {auth_endpoint}")
                        break
                except:
                    continue

        if not auth_endpoint:
            auth_endpoint = target_url  # Fallback to target URL
            events.append("⚠️ No form/API detected, using target URL")

        # STEP 3: Submit credentials
        events.append(f"Submitting credentials to {auth_endpoint}")

        payload_data = {
            'username': username,
            'password': password,
        }

        # Try different field names (common variations)
        payload_variants = [
            {'username': username, 'password': password},
            {'email': username, 'password': password},
            {'user': username, 'pass': password},
            {'login': username, 'password': password},
        ]

        success = False
        final_url = None
        post_auth_html = None
        response = None

        for payload in payload_variants:
            try:
                if is_json_api:
                    # JSON API request
                    events.append(f"Trying JSON payload: {list(payload.keys())}")
                    response = await client.post(
                        auth_endpoint,
                        json=payload,
                        headers={'Content-Type': 'application/json'}
                    )
                else:
                    # Form-encoded request
                    events.append(f"Trying form payload: {list(payload.keys())}")
                    response = await client.post(
                        auth_endpoint,
                        data=payload,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'}
                    )

                events.append(f"POST {auth_endpoint} → {response.status_code}")

                # Check for success indicators
                if response.status_code in [200, 201, 302, 303]:
                    # Check if we got cookies
                    cookies = client.cookies
                    if len(cookies) > 0:
                        success = True
                        events.append(f"✅ Authentication successful ({len(cookies)} cookies received)")
                        break

                    # Check JSON response for token
                    try:
                        json_body = response.json()
                        if 'token' in json_body or 'access_token' in json_body or 'session' in json_body:
                            success = True
                            events.append("✅ Authentication successful (token received in JSON)")
                            break
                    except:
                        pass

                # Try next variant
                events.append("⚠️ No cookies/token received, trying next variant")

            except httpx.RequestError as e:
                events.append(f"❌ Request error: {e}")
                continue

        if not response:
            raise Exception("All authentication attempts failed")

        # STEP 4: Get final URL and content
        final_url = str(response.url)
        post_auth_html = response.text

        # STEP 5: Extract cookies
        cookies = [
            {
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain or '',
                'path': cookie.path or '/',
                'secure': cookie.secure or False,
                'httpOnly': True,  # HTTPX doesn't expose httpOnly flag
                'sameSite': 'Lax',  # Default assumption
                'expires': None,  # HTTPX doesn't parse expires
            }
            for cookie in client.cookies.jar
        ]

        events.append(f"Captured {len(cookies)} session cookies")

        # STEP 6: Extract security context from headers
        security_context = {
            'url': final_url,
            'captured_at': datetime.now(timezone.utc).isoformat(),
            'engine': 'httpx',
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'csp': response.headers.get('content-security-policy'),
            'hsts': response.headers.get('strict-transport-security'),
            'x_frame_options': response.headers.get('x-frame-options'),
            'cors_origin': response.headers.get('access-control-allow-origin'),
        }

        # Record actions for replay
        recorded_actions.append(RecordedAction(
            command="http_post",
            target=auth_endpoint,
            value=json.dumps(payload_data)
        ))

        # Extract page title from HTML
        soup = BeautifulSoup(post_auth_html, 'html.parser')
        page_title = soup.title.string if soup.title else None

        return FormAuthResult(
            final_url=final_url,
            page_title=page_title,
            heading=None,
            success_message=None,
            cookies=cookies,
            security_context=security_context,
            screenshots=[],  # No browser rendering
            events=events,
            pre_auth_html=pre_auth_html[:5000],  # Truncate (HTTPX doesn't need full HTML)
            post_auth_html=post_auth_html[:5000],
            username_selector=None,  # HTTPX doesn't use selectors
            password_selector=None,
            submit_selector=None,
            submit_method='http_post',
            recorded_actions=recorded_actions,
            har_bytes=None,  # HTTPX doesn't generate HAR files
            success=success,
        )
