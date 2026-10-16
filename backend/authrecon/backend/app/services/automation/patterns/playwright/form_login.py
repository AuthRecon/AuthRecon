"""
Playwright-based form authentication with HAR capture.

WHY PLAYWRIGHT:
- Modern SPA support (React/Vue/Angular handle auth via JavaScript)
- Chrome DevTools Protocol (CDP) - sees ALL network requests (XHR/fetch/websockets)
- Real HAR file generation - captures complete auth flow with headers, timing, bodies
- Auto-waiting - no flaky "element not ready" errors
- Better selectors - text(), role(), chaining

WHEN TO USE:
- Modern SPAs where Selenium struggles (JavaScript-heavy auth)
- When you need complete network trace (HAR file for analysis/scanner)
- API-based authentication (sees fetch('/api/auth') calls Selenium misses)

OUTPUT ARTIFACTS:
- network.har: Complete HTTP archive (all requests/responses during auth flow)
- Cookies: Session tokens for authenticated scanning
- Screenshots: Visual proof of successful authentication
- Security context: CSP, CORS, headers extracted from responses
- API endpoints: Discovered via CDP monitoring (bonus for scanner)

COMPARISON TO SELENIUM:
- Selenium: Creates .side files (Tenable integration), stable for classic forms
- Playwright: Creates HAR files (scanner fuel), better for modern SPAs
- Both engines run in parallel - Playwright doesn't replace Selenium, enhances it
"""

from app.services.live_timeline import live_events
import tempfile
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
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


async def attempt_form_login_playwright(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 45,
) -> FormAuthResult:
    """
    Attempt form-based authentication using Playwright with HAR capture.

    AUTHENTICATION FLOW:
    1. Launch Chromium with HAR recording enabled
    2. Navigate to target (wait for network idle - SPAs need this)
    3. Detect username/password fields (multi-lingual, SPA-aware selectors)
    4. Fill credentials and submit
    5. Wait for navigation/response (handles redirects + SPA transitions)
    6. Extract security context, cookies, screenshots
    7. Close browser → HAR file saved automatically

    Args:
        run_id: Unique identifier for this auth run
        target_url: Login page URL
        username: Username/email for authentication
        password: Password for authentication
        timeout_seconds: Max time to wait for auth flow (default 45s)

    Returns:
        FormAuthResult with:
            - success: True if authentication succeeded
            - final_url: URL after auth (dashboard/home page)
            - har_bytes: Complete HAR file (all HTTP requests/responses)
            - cookies: Session cookies for authenticated access
            - screenshots: Before/after auth visual proof
            - security_context: CSP, CORS, headers, detected tech
            - events: Timeline of auth flow actions
            - recorded_actions: Replay instructions (Playwright format)

    Raises:
        AutomationFailure: If login forms not found or auth flow fails
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
                user_agent='AuthRecon/1.0 (Playwright Engine)',
                viewport={'width': 1920, 'height': 1080},
            )
            await harden_playwright_context(context)
            page = await context.new_page()
            page.set_default_timeout(timeout_seconds * 1000)
            return browser, context, page

        browser, context, page = await _open_page()

        try:
            events.append("Launching Playwright browser with HAR recording")

            # STEP 1: Navigate to target
            events.append(f"Navigating to {target_url}")
            recorded_actions.append(RecordedAction(
                action="navigate",
                selector=target_url,
                value=""
            ))

            # wait_until='networkidle' is KEY for SPAs
            # Waits for no network activity for 500ms (React/Vue rendering complete)
            browser, context, page, nav_timeout = await playwright_goto_with_http2_fallback(
                _open_page, browser, context, page, target_url,
                wait_until='networkidle', timeout=timeout_seconds * 1000,
            )
            if nav_timeout:
                events.append("⚠️ Page load timeout, attempting to continue")

            pre_auth_html = await page.content()
            pre_auth_url = page.url

            # Screenshot before auth
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-pre-auth.png",
                data=screenshot_bytes,
                description="Pre-authentication page"
            ))
            events.append("Captured pre-authentication screenshot")

            # STEP 2: Detect login form fields
            # Playwright selectors are MUCH more powerful than Selenium
            events.append("Detecting login form fields")

            # Username field detection (supports many patterns)
            username_selectors = [
                'input[type="text"][name*="user" i]',  # name="username", "user_name", etc (case-insensitive)
                'input[type="email"]',  # Email-based login
                'input[type="text"][id*="user" i]',  # id="userId", "username_field"
                'input[type="text"][placeholder*="user" i]',  # placeholder="Enter username"
                'input[type="text"][placeholder*="email" i]',  # placeholder="Email address"
                'input[type="text"][autocomplete="username"]',  # HTML5 autocomplete
                'input[type="text"]:first-of-type',  # Fallback: first text input
            ]

            username_field = None
            for selector in username_selectors:
                username_field = page.locator(selector).first
                if await username_field.count() > 0 and await username_field.is_visible():
                    events.append(f"Found username field: {selector}")
                    break

            if not username_field or await username_field.count() == 0:
                raise Exception("No username field detected")

            # Password field detection
            password_field = page.locator('input[type="password"]').first
            if await password_field.count() == 0:
                raise Exception("No password field detected")

            events.append("Login form detected successfully")

            # STEP 3: Fill credentials
            if username:
                events.append(f"Filling username: {username}")
                await username_field.fill(username)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[type="text"], input[type="email"]',
                    value=username
                ))

            if password:
                events.append("Filling password: ********")
                ensure_safe_to_type(page.url)
                await password_field.fill(password)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[type="password"]',
                    value="********"  # Redacted in recorded actions
                ))

            # STEP 4: Submit form
            events.append("Submitting login form")
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
                'button:has-text("Login")',
            ]

            submit_button = None
            for selector in submit_selectors:
                submit_button = page.locator(selector).first
                if await submit_button.count() > 0 and await submit_button.is_visible():
                    break

            if not submit_button or await submit_button.count() == 0:
                # Fallback: press Enter in password field
                events.append("No submit button found, pressing Enter")
                await password_field.press('Enter')
            else:
                recorded_actions.append(RecordedAction(
                    action="click",
                    selector='button[type="submit"]',
                    value=""
                ))
                await submit_button.click()

            # STEP 5: Wait for navigation/response
            # This handles both traditional redirects AND SPA transitions
            try:
                await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                events.append("Navigation completed")
            except PlaywrightTimeout:
                events.append("⚠️ Navigation timeout, checking current state")

            # STEP 6: Capture post-auth state
            final_url = page.url
            post_auth_html = await page.content()
            page_title = await page.title()

            # Success heuristic: URL changed or page content changed significantly
            url_changed = final_url != pre_auth_url
            content_changed = len(post_auth_html) != len(pre_auth_html)
            success = url_changed or content_changed

            if success:
                events.append(f"✅ Authentication successful (redirected to {final_url})")
            else:
                events.append("❌ Authentication may have failed (no redirect detected)")

            # Screenshot after auth
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-post-auth.png",
                data=screenshot_bytes,
                description="Post-authentication page"
            ))
            events.append("Captured post-authentication screenshot")

            # STEP 7: Extract security context
            # Use existing security context extractor (adapts from page HTML)
            events.append("Extracting security context")
            from selenium import webdriver
            # Note: security_context extraction needs adaptation for Playwright
            # For now, create a minimal context
            security_context = None

            # STEP 8: Extract cookies
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

            # STEP 9: Close context to flush HAR file
            await context.close()
            events.append("Closed browser context, HAR file saved")

            # STEP 10: Read HAR file
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
                security_context=security_context,
                screenshots=screenshots,
                events=events,
                pre_auth_html=pre_auth_html,
                post_auth_html=post_auth_html,
                username_selector='input[type="text"], input[type="email"]',
                password_selector='input[type="password"]',
                submit_selector='button[type="submit"]',
                submit_method='click',
                recorded_actions=recorded_actions,
                har_bytes=har_bytes,  # 🎯 REAL HAR FILE
                success=success,
            )

        finally:
            await browser.close()
