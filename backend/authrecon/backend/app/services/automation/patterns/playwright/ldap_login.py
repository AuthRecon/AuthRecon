r"""
Playwright-based LDAP/ADFS authentication with HAR capture.

WHY PLAYWRIGHT FOR LDAP/ADFS:
- Captures complete STS redirect chains in HAR (3-5+ hops)
- Network trace shows SAML/federation token exchanges
- Auto-waiting handles ADFS/STS page transitions seamlessly
- Better detection of domain-specific auth flows

WHEN TO USE:
- Active Directory Federation Services (ADFS) login
- LDAP-backed enterprise authentication
- Domain\Username format authentication
- Government/corporate intranets
- Windows Integrated Auth pages

OUTPUT ARTIFACTS:
- network.har: Complete HTTP archive with STS redirect chain
- Cookies: Session tokens and federation cookies
- Screenshots: Pre-auth, credentials-entered, post-auth
- Security context: Federation headers, domain info
- Recorded actions: Replay instructions

FLOW:
1. Navigate to target (may redirect to ADFS/STS)
2. Wait for LDAP login page to load
3. Enter domain-prefixed username (DOMAIN\user)
4. Enter password
5. Submit credentials
6. Wait for STS redirect chain to complete
7. Verify landing on authenticated page
8. Extract artifacts
"""

from app.services.live_timeline import live_events
import tempfile
from datetime import datetime, timezone
from typing import List
from pathlib import Path

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

from app.services.automation.navigation import (
    playwright_goto_with_http2_fallback,
    with_http2_disabled,
)

from app.services.automation.types import FormAuthResult, RecordedAction, ScreenshotCapture


# LDAP/ADFS detection patterns
ADFS_HOSTS = ("adfs", "sts", "federation", "sso")


async def attempt_ldap_login_playwright(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 45,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    r"""
    Attempt LDAP/ADFS authentication using Playwright with HAR capture.

    LDAP/ADFS AUTHENTICATION FLOW:
    1. Launch Chromium with HAR recording enabled
    2. Navigate to target (may redirect to ADFS/STS domain)
    3. Wait for LDAP login page (network idle)
    4. Fill username field (with domain prefix if provided)
    5. Fill password field
    6. Submit credentials
    7. Wait for STS redirect chain (networkidle - critical for federation)
    8. Verify success (redirected away from ADFS/STS)
    9. Extract security context, cookies, screenshots
    10. Close browser → HAR file saved with complete redirect chain

    Args:
        run_id: Unique identifier for this auth run
        target_url: Login page URL (may redirect to ADFS/STS)
        username: Username for authentication
        password: Password for authentication
        timeout_seconds: Max time to wait for auth flow (default 45s)
        login_hint: Optional keyword to select correct login button
        domain_prefix: Optional domain prefix (e.g., CORP for CORP\username)

    Returns:
        FormAuthResult with:
            - success: True if authentication succeeded
            - final_url: URL after STS redirects (dashboard/home page)
            - har_bytes: Complete HAR file with federation flow
            - cookies: Session cookies + federation tokens
            - screenshots: Pre/credentials/post auth (3 screenshots)
            - security_context: Federation headers, domain info
            - events: Timeline of auth flow actions
            - recorded_actions: Replay instructions (Playwright format)

    Raises:
        Exception: If login forms not found or auth flow fails
    """

    # Setup HAR capture path
    har_path = Path(tempfile.gettempdir()) / f"{run_id}-playwright.har"

    events: List[str] = live_events()
    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []

    async with async_playwright() as p:
        # Launch browser with HAR recording
        async def _open_page(disable_http2: bool = False):
            launch_args = ['--disable-blink-features=AutomationControlled']
            browser = await p.chromium.launch(
                headless=True,
                args=with_http2_disabled(launch_args) if disable_http2 else launch_args,
            )
            context = await browser.new_context(
                record_har_path=str(har_path),
                record_har_omit_content=False,  # Include request/response bodies
                record_har_mode='minimal',  # Exclude large static assets
                ignore_https_errors=True,  # Testing environments
                user_agent='AuthRecon/1.0 (Playwright Engine - LDAP/ADFS)',
                viewport={'width': 1920, 'height': 1080},
            )
            page = await context.new_page()
            page.set_default_timeout(timeout_seconds * 1000)
            return browser, context, page

        browser, context, page = await _open_page()

        try:
            events.append("Launching Playwright browser with HAR recording (LDAP/ADFS mode)")

            # STEP 1: Navigate to target (may redirect to ADFS/STS)
            events.append(f"Navigating to {target_url}")
            recorded_actions.append(RecordedAction(
                action="navigate",
                selector=target_url,
                value=""
            ))

            browser, context, page, nav_timeout = await playwright_goto_with_http2_fallback(
                _open_page, browser, context, page, target_url,
                wait_until='networkidle', timeout=timeout_seconds * 1000,
            )
            if nav_timeout:
                events.append("⚠️ Initial page load timeout, attempting to continue")

            # Check if redirected to ADFS/STS
            current_url = page.url
            if any(host in current_url.lower() for host in ADFS_HOSTS):
                events.append(f"Detected ADFS/STS redirect: {current_url}")

            pre_auth_html = await page.content()
            pre_auth_url = page.url

            # Screenshot 1: Before auth
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-01-ldap-pre-auth.png",
                data=screenshot_bytes,
                description="LDAP/ADFS login page before authentication"
            ))
            events.append("Captured pre-authentication screenshot")

            # STEP 2: Detect username field
            events.append("Detecting LDAP/ADFS username field")

            # LDAP username field detection (comprehensive)
            username_selectors = [
                'input[name="UserName"]',
                'input[name="username"]',
                'input[name="UserId"]',
                'input[id*="Username" i]',
                'input[id*="UserName" i]',
                'input[id*="userId" i]',
                'input[placeholder*="domain" i]',
                'input[placeholder*="Username" i]',
                'input[type="text"]:visible:first',
            ]

            username_field = None
            for selector in username_selectors:
                username_field = page.locator(selector).first
                if await username_field.count() > 0:
                    try:
                        if await username_field.is_visible():
                            events.append(f"Found LDAP username field: {selector}")
                            break
                    except:
                        continue

            if not username_field or await username_field.count() == 0:
                raise Exception("No username field detected on LDAP/ADFS login page")

            # STEP 3: Fill username (with domain prefix)
            username_to_use = username
            if domain_prefix and username:
                # Support DOMAIN\username format
                username_to_use = f"{domain_prefix}\\{username}"
                events.append(f"Using LDAP username format: {username_to_use}")

            if username_to_use:
                events.append(f"Filling LDAP username: {username_to_use}")
                await username_field.fill(username_to_use)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[name="UserName"], input[type="text"]',
                    value=username_to_use
                ))

            # STEP 4: Detect password field
            events.append("Detecting LDAP/ADFS password field")
            password_selectors = [
                'input[name="Password"]',
                'input[name="password"]',
                'input[name="Passwd"]',
                'input[id*="Password" i]',
                'input[type="password"]',
            ]

            password_field = None
            for selector in password_selectors:
                password_field = page.locator(selector).first
                if await password_field.count() > 0:
                    try:
                        if await password_field.is_visible():
                            events.append(f"Found LDAP password field: {selector}")
                            break
                    except:
                        continue

            if not password_field or await password_field.count() == 0:
                raise Exception("No password field detected on LDAP/ADFS login page")

            # STEP 5: Fill password
            if password:
                events.append("Filling LDAP password: ********")
                await password_field.fill(password)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[type="password"]',
                    value="********"  # Redacted
                ))

            # Screenshot 2: Credentials entered
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-02-ldap-credentials-entered.png",
                data=screenshot_bytes,
                description="LDAP/ADFS credentials entered (password masked)"
            ))
            events.append("Captured screenshot after credentials entry")

            # STEP 6: Submit credentials
            events.append("Submitting LDAP/ADFS credentials")
            submit_selectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'input[value*="Sign" i]',
                'input[value*="Login" i]',
                'button[name="submit"]',
                'span[id*="submitButton"]',
                '.submit-button',
            ]

            submit_button = None
            for selector in submit_selectors:
                submit_button = page.locator(selector).first
                if await submit_button.count() > 0:
                    try:
                        if await submit_button.is_visible():
                            events.append(f"Found LDAP submit button: {selector}")
                            break
                    except:
                        continue

            if not submit_button or await submit_button.count() == 0:
                # Fallback: press Enter in password field
                events.append("No submit button found, pressing Enter in password field")
                await password_field.press('Enter')
            else:
                recorded_actions.append(RecordedAction(
                    action="click",
                    selector='input[type="submit"], button[type="submit"]',
                    value=""
                ))
                await submit_button.click()

            # STEP 7: Wait for STS redirect chain
            events.append("Waiting for LDAP/ADFS redirect chain (STS processing)...")
            try:
                # Network idle is critical for ADFS/STS multi-hop redirects
                await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                events.append("LDAP/ADFS redirect chain completed")
            except PlaywrightTimeout:
                events.append("⚠️ LDAP/ADFS redirect timeout, checking current state")

            # STEP 8: Verify success
            final_url = page.url
            post_auth_html = await page.content()
            page_title = await page.title()

            # Success heuristics for LDAP/ADFS:
            # 1. Redirected away from ADFS/STS domain
            current_host = final_url.lower()
            is_still_on_adfs = any(host in current_host for host in ADFS_HOSTS)

            # 2. No longer on login page (no password field visible)
            password_field_visible = await page.locator('input[type="password"]').count() > 0

            # 3. URL changed from pre-auth
            url_changed = final_url != pre_auth_url

            success = url_changed and not is_still_on_adfs and not password_field_visible

            if success:
                events.append(f"✅ LDAP/ADFS authentication successful (redirected to {final_url})")
            else:
                events.append(f"❌ LDAP/ADFS authentication may have failed (still on ADFS: {is_still_on_adfs}, login page: {password_field_visible})")

            # Screenshot 3: Post-auth
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-03-ldap-authenticated.png",
                data=screenshot_bytes,
                description="Final page after LDAP/ADFS authentication"
            ))
            events.append("Captured post-authentication screenshot")

            # STEP 9: Extract cookies
            cookies_raw = await context.cookies()
            cookies = [
                {
                    'name': c['name'],
                    'value': c['value'],
                    'domain': c.get('domain', ''),
                    'path': c.get('path', '/'),
                    'secure': c.get('secure', False),
                    'httpOnly': c.get('httpOnly', False),
                    'sameSite': c.get('sameSite', 'Lax'),
                    'expires': c.get('expires'),
                }
                for c in cookies_raw
            ]

            events.append(f"Captured {len(cookies)} session/federation cookies")

            # STEP 10: Close context to flush HAR file
            await context.close()
            events.append("Closed browser context, HAR file saved with STS redirect chain")

            # STEP 11: Read HAR file
            har_bytes = None
            if har_path.exists():
                har_bytes = har_path.read_bytes()
                har_size_kb = len(har_bytes) / 1024
                events.append(f"HAR file captured: {har_size_kb:.1f} KB (includes ADFS/STS redirects)")

                har_path.unlink()
            else:
                events.append("⚠️ HAR file not found (may indicate browser crash)")

            return FormAuthResult(
                final_url=final_url,
                page_title=page_title,
                heading=None,
                success_message=None,
                cookies=cookies,
                security_context=None,
                screenshots=screenshots,
                events=events,
                pre_auth_html=pre_auth_html,
                post_auth_html=post_auth_html,
                username_selector='input[name="UserName"], input[type="text"]',
                password_selector='input[type="password"]',
                submit_selector='input[type="submit"], button[type="submit"]',
                submit_method='click',
                recorded_actions=recorded_actions,
                har_bytes=har_bytes,  # 🎯 REAL HAR FILE with LDAP/ADFS flow
                success=success,
            )

        finally:
            await browser.close()
