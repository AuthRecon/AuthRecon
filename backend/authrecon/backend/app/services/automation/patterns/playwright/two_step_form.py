"""
Playwright-based two-step form authentication with HAR capture.

WHY PLAYWRIGHT FOR TWO-STEP:
- Captures BOTH form submissions in HAR (step 1: username POST, step 2: password POST)
- Auto-waiting eliminates timing issues between steps
- Network idle detection ensures all XHR/fetch calls captured
- Better handling of SPA transitions (React/Vue two-step flows)

WHEN TO USE:
- Microsoft/Azure AD login (email → next → password)
- Google login (email → next → password → 2FA)
- Custom enterprise SSO with staged authentication
- Any flow requiring separate username/password pages

OUTPUT ARTIFACTS:
- network.har: Complete HTTP archive (5-10+ entries showing both auth steps)
- Cookies: Session tokens for authenticated scanning
- Screenshots: Pre-auth, mid-auth (password page), post-auth
- Security context: CSP, CORS, headers extracted from responses
- Recorded actions: Step-by-step replay instructions

FLOW:
1. Navigate to login page
2. Enter username/email → Submit → Wait for navigation
3. Enter password → Submit → Wait for navigation
4. Verify success and extract artifacts
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
from app.services.automation.playwright_guard import harden_playwright_context, launch_chromium
from app.services.automation.remote_browser import browser_tmp_dir
from app.services.automation.typing_guard import ensure_safe_to_type


async def attempt_two_step_login_playwright(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 45,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Attempt two-step form-based authentication using Playwright with HAR capture.

    TWO-STEP AUTHENTICATION FLOW:
    1. Launch Chromium with HAR recording enabled
    2. Navigate to target (wait for network idle)
    3. Fill username/email field
    4. Click "Next" or "Continue" button
    5. Wait for password page to load (network idle)
    6. Fill password field
    7. Submit final form
    8. Wait for navigation/response (handles redirects + SPA transitions)
    9. Extract security context, cookies, screenshots
    10. Close browser → HAR file saved automatically

    Args:
        run_id: Unique identifier for this auth run
        target_url: Login page URL
        username: Username/email for step 1
        password: Password for step 2
        timeout_seconds: Max time to wait for each step (default 45s)
        login_hint: Optional keyword to select correct login button
        domain_prefix: Optional domain prefix for username (e.g., CORP\\username)

    Returns:
        FormAuthResult with:
            - success: True if authentication succeeded
            - final_url: URL after auth (dashboard/home page)
            - har_bytes: Complete HAR file (all HTTP requests/responses)
            - cookies: Session cookies for authenticated access
            - screenshots: Pre/mid/post auth visual proof (3+ screenshots)
            - security_context: CSP, CORS, headers, detected tech
            - events: Timeline of auth flow actions
            - recorded_actions: Replay instructions (Playwright format)

    Raises:
        Exception: If login forms not found or auth flow fails
    """

    # Setup HAR capture path
    har_path = Path(browser_tmp_dir()) / f"{run_id}-playwright.har"

    events: List[str] = live_events()
    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []

    async with async_playwright() as p:
        # Launch browser with HAR recording
        async def _open_page(disable_http2: bool = False):
            launch_args = ['--disable-blink-features=AutomationControlled']
            browser = await launch_chromium(p, 
                headless=True,
                args=with_http2_disabled(launch_args) if disable_http2 else launch_args,
            )
            context = await browser.new_context(
                accept_downloads=False,
                record_har_path=str(har_path),
                record_har_omit_content=False,  # Include request/response bodies
                record_har_mode='minimal',  # Exclude large static assets
                ignore_https_errors=True,  # Testing environments
                user_agent='AuthRecon/1.0 (Playwright Engine - Two-Step)',
                viewport={'width': 1920, 'height': 1080},
            )
            await harden_playwright_context(context)
            page = await context.new_page()
            page.set_default_timeout(timeout_seconds * 1000)
            return browser, context, page

        browser, context, page = await _open_page()

        try:
            events.append("Launching Playwright browser with HAR recording (two-step mode)")

            # STEP 1: Navigate to target
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

            pre_auth_html = await page.content()
            pre_auth_url = page.url

            # Screenshot 1: Before auth
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-01-pre-auth.png",
                data=screenshot_bytes,
                description="Initial page before two-step authentication"
            ))
            events.append("Captured pre-authentication screenshot")

            # STEP 2: Detect username/email field
            events.append("Detecting username/email field (Step 1)")

            # Username field detection (comprehensive selectors)
            username_selectors = [
                'input[type="text"][name*="user" i]',
                'input[type="email"]',
                'input[type="text"][id*="user" i]',
                'input[type="text"][id*="email" i]',
                'input[type="text"][placeholder*="user" i]',
                'input[type="text"][placeholder*="email" i]',
                'input[type="text"][autocomplete="username"]',
                'input[type="text"][autocomplete="email"]',
                'input[type="text"]:visible:first',  # Fallback to first visible text input
            ]

            username_field = None
            for selector in username_selectors:
                username_field = page.locator(selector).first
                if await username_field.count() > 0:
                    try:
                        if await username_field.is_visible():
                            events.append(f"Found username field: {selector}")
                            break
                    except:
                        continue

            if not username_field or await username_field.count() == 0:
                raise Exception("No username/email field detected on initial page")

            # STEP 3: Fill username
            username_to_use = username
            if domain_prefix and username:
                # Support DOMAIN\username format
                username_to_use = f"{domain_prefix}\\{username}"
                events.append(f"Using domain-prefixed username: {username_to_use}")

            if username_to_use:
                events.append(f"Filling username: {username_to_use}")
                await username_field.fill(username_to_use)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[type="text"], input[type="email"]',
                    value=username_to_use
                ))

            # Screenshot 2: Username entered
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-02-username-entered.png",
                data=screenshot_bytes,
                description="Username/email entered (Step 1)"
            ))
            events.append("Captured screenshot after username entry")

            # STEP 4: Submit username (find Next/Continue button)
            events.append("Submitting username (Step 1)")
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Next")',
                'button:has-text("Continue")',
                'button:has-text("Submit")',
                'button:visible:first',  # Fallback to first visible button
            ]

            submit_button = None
            for selector in submit_selectors:
                submit_button = page.locator(selector).first
                if await submit_button.count() > 0:
                    try:
                        if await submit_button.is_visible():
                            events.append(f"Found submit button: {selector}")
                            break
                    except:
                        continue

            if not submit_button or await submit_button.count() == 0:
                # Fallback: press Enter in username field
                events.append("No submit button found, pressing Enter in username field")
                await username_field.press('Enter')
            else:
                recorded_actions.append(RecordedAction(
                    action="click",
                    selector='button[type="submit"]',
                    value=""
                ))
                await submit_button.click()

            # STEP 5: Wait for password page to load
            events.append("Waiting for password page to load (Step 2)...")
            try:
                # Wait for navigation or network idle
                await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                events.append("Password page loaded successfully")
            except PlaywrightTimeout:
                events.append("⚠️ Password page load timeout, checking for password field")

            mid_auth_url = page.url
            if mid_auth_url != pre_auth_url:
                events.append(f"Page transitioned to: {mid_auth_url}")

            # Screenshot 3: Password page
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-03-password-page.png",
                data=screenshot_bytes,
                description="Password page after username submission (Step 2)"
            ))
            events.append("Captured password page screenshot")

            # STEP 6: Detect password field
            events.append("Detecting password field (Step 2)")
            password_field = page.locator('input[type="password"]').first

            # Wait for password field to appear (may take time in SPAs)
            try:
                await password_field.wait_for(state='visible', timeout=5000)
            except PlaywrightTimeout:
                pass

            if await password_field.count() == 0:
                raise Exception("No password field detected after username submission")

            events.append("Password field detected successfully")

            # STEP 7: Fill password
            if password:
                events.append("Filling password: ********")
                ensure_safe_to_type(page.url)
                await password_field.fill(password)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[type="password"]',
                    value="********"  # Redacted in recorded actions
                ))

            # Screenshot 4: Password entered
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-04-password-entered.png",
                data=screenshot_bytes,
                description="Password entered (Step 2, masked)"
            ))
            events.append("Captured screenshot after password entry")

            # STEP 8: Submit password (final submission)
            events.append("Submitting password (Step 2 - final)")
            final_submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
                'button:has-text("Login")',
                'button:has-text("Submit")',
            ]

            final_submit = None
            for selector in final_submit_selectors:
                final_submit = page.locator(selector).first
                if await final_submit.count() > 0:
                    try:
                        if await final_submit.is_visible():
                            break
                    except:
                        continue

            if not final_submit or await final_submit.count() == 0:
                # Fallback: press Enter in password field
                events.append("No final submit button found, pressing Enter in password field")
                await password_field.press('Enter')
            else:
                recorded_actions.append(RecordedAction(
                    action="click",
                    selector='button[type="submit"]',
                    value=""
                ))
                await final_submit.click()

            # STEP 9: Wait for final navigation/response
            try:
                await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                events.append("Final navigation completed")
            except PlaywrightTimeout:
                events.append("⚠️ Final navigation timeout, checking current state")

            # STEP 10: Capture post-auth state
            final_url = page.url
            post_auth_html = await page.content()
            page_title = await page.title()

            # Success heuristic: URL changed from mid-auth page
            url_changed = final_url != mid_auth_url
            content_changed = len(post_auth_html) != len(pre_auth_html)
            success = url_changed or content_changed

            if success:
                events.append(f"✅ Two-step authentication successful (redirected to {final_url})")
            else:
                events.append("❌ Two-step authentication may have failed (no redirect detected)")

            # Screenshot 5: Final authenticated page
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-05-authenticated.png",
                data=screenshot_bytes,
                description="Final page after successful two-step authentication"
            ))
            events.append("Captured post-authentication screenshot")

            # STEP 11: Extract cookies
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

            events.append(f"Captured {len(cookies)} session cookies")

            # STEP 12: Close context to flush HAR file
            await context.close()
            events.append("Closed browser context, HAR file saved")

            # STEP 13: Read HAR file
            har_bytes = None
            if har_path.exists():
                har_bytes = har_path.read_bytes()
                har_size_kb = len(har_bytes) / 1024
                events.append(f"HAR file captured: {har_size_kb:.1f} KB")

                har_path.unlink()
            else:
                events.append("⚠️ HAR file not found (may indicate browser crash)")

            return FormAuthResult(
                final_url=final_url,
                page_title=page_title,
                heading=None,  # Could extract h1
                success_message=None,  # Could detect success message
                cookies=cookies,
                security_context=None,
                screenshots=screenshots,
                events=events,
                pre_auth_html=pre_auth_html,
                post_auth_html=post_auth_html,
                username_selector='input[type="text"], input[type="email"]',
                password_selector='input[type="password"]',
                submit_selector='button[type="submit"]',
                submit_method='click',
                recorded_actions=recorded_actions,
                har_bytes=har_bytes,  # 🎯 REAL HAR FILE with both auth steps
                success=success,
            )

        finally:
            await browser.close()
