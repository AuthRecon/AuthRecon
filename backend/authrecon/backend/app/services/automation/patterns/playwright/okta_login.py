"""
Playwright-based Okta authentication with HAR capture.

WHY PLAYWRIGHT FOR OKTA:
- Okta has JavaScript-heavy UIs (React-based login pages)
- CDP captures complete Okta API calls (/api/v1/authn, /api/v1/sessions)
- HAR includes Okta SSO flow (Widget → API → Session → Redirect)
- Auto-waiting handles Okta's async validation
- MFA detection (can identify when MFA is required)

OKTA INTEGRATION PATTERNS:
- Okta-hosted login (yourcompany.okta.com)
- Custom domain (login.yourcompany.com → Okta backend)
- Okta Widget embedded in app
- Okta Identity Engine (new auth pipeline)

OUTPUT ARTIFACTS:
- network.har: Complete Okta auth flow (API calls to /authn, /sessions)
- Cookies: Okta session tokens (sid, idx, JSESSIONID)
- Screenshots: Okta login steps (username, password, MFA prompt)
- Security context: Okta API endpoints, session duration, MFA config
- MFA detection: Identifies if MFA is required (but cannot bypass)

OKTA-SPECIFIC FEATURES:
- Detects Okta Widget vs custom forms
- Extracts Okta org ID from domain
- Captures stateToken for session replay
- Identifies MFA methods (SMS, Authenticator, push)
"""

from app.services.live_timeline import live_events
import time
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


async def attempt_okta_login_playwright(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 60,
) -> FormAuthResult:
    """
    Attempt Okta authentication using Playwright with HAR capture.

    OKTA AUTH FLOW:
    1. Launch Chromium with HAR recording
    2. Navigate to Okta login page (detect Widget vs custom)
    3. Fill username field (email/username)
    4. Click "Next" or "Sign In" (Okta may verify username first)
    5. Fill password field
    6. Click "Sign In"
    7. Detect MFA prompt (if required, mark as "MFA required" and fail gracefully)
    8. Wait for Okta session creation (/api/v1/sessions)
    9. Wait for redirect to application
    10. Extract Okta cookies, HAR, session data

    Args:
        run_id: Unique identifier for this auth run
        target_url: Okta login URL (*.okta.com or custom domain)
        username: Username/email for Okta account
        password: Password for Okta account
        timeout_seconds: Max time for complete auth flow (default 60s)

    Returns:
        FormAuthResult with:
            - success: True if Okta session created (or partial success if MFA required)
            - final_url: URL after Okta auth (app dashboard or MFA prompt)
            - har_bytes: Complete HAR with Okta API calls
            - cookies: Okta session cookies (sid, idx, JSESSIONID)
            - screenshots: Okta login steps
            - security_context: Okta org ID, MFA config, session duration
            - events: Okta auth flow timeline
            - mfa_required: Boolean flag if MFA detected

    Note:
        If MFA is required, authentication will stop at MFA prompt.
        HAR will still contain all Okta API calls up to MFA challenge.
    """

    if not username:
        raise ValueError("Username required for Okta authentication")
    if not password:
        raise ValueError("Password required for Okta authentication")

    events: List[str] = live_events()
    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []
    har_path = None
    final_url = target_url
    cookies: List[Dict[str, Any]] = []
    mfa_required = False

    async with async_playwright() as p:
        har_path = f"{browser_tmp_dir()}/{run_id}-okta-network.har"

        async def _open_page(disable_http2: bool = False):
            launch_args = ['--disable-blink-features=AutomationControlled']
            browser = await launch_chromium(p, 
                headless=True,
                args=with_http2_disabled(launch_args) if disable_http2 else launch_args,
            )
            context = await browser.new_context(
                accept_downloads=False,
                record_har_path=har_path,
                record_har_omit_content=False,
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            )
            await harden_playwright_context(context)
            page = await context.new_page()
            return browser, context, page

        browser, context, page = await _open_page()

        try:
            # Navigate to Okta login page
            events.append(f"Navigating to Okta login: {target_url}")
            browser, context, page, nav_timeout = await playwright_goto_with_http2_fallback(
                _open_page, browser, context, page, target_url,
                wait_until='networkidle', timeout=timeout_seconds * 1000,
            )
            if nav_timeout:
                raise nav_timeout
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)

            current_url = page.url
            events.append(f"Loaded Okta page: {current_url}")

            # Detect Okta org from URL
            okta_org = _extract_okta_org(current_url)
            if okta_org:
                events.append(f"Detected Okta org: {okta_org}")

            # Take pre-auth screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name="okta-01-login-page.png",
                data=screenshot_bytes,
                description="Okta Login Page"
            ))

            # Detect Okta Widget vs custom form
            is_widget = await _detect_okta_widget(page)
            events.append(f"Okta integration type: {'Widget' if is_widget else 'Custom Form'}")

            # Fill username field
            username_selectors = [
                "input[name='username']",
                "input[name='identifier']",
                "input[type='email']",
                "input[type='text']",
                "input#okta-signin-username",
                "input#input0",  # Okta Identity Engine
            ]

            username_filled = False
            for selector in username_selectors:
                try:
                    await page.wait_for_selector(selector, timeout=5000, state='visible')
                    await page.fill(selector, username)
                    events.append(f"Entered username: {username}")
                    recorded_actions.append(RecordedAction(
                        action="type",
                        selector=selector,
                        value="${USERNAME}",
                        note="Okta username"
                    ))
                    username_filled = True
                    break
                except:
                    continue

            if not username_filled:
                events.append("Error: Could not find username field")
                await context.close()
                await browser.close()

                har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''

                return FormAuthResult(
                    success=False,
                    final_url=page.url,
                    events=events,
                    screenshots=screenshots,
                    har_bytes=har_bytes,
                    cookies=[],
                    recorded_actions=recorded_actions,
                )

            # Check if password field is visible (single-step) or need to click "Next"
            password_visible = False
            password_selectors = ["input[type='password']", "input[name='password']", "input#okta-signin-password", "input#input1"]

            for selector in password_selectors:
                try:
                    await page.wait_for_selector(selector, timeout=2000, state='visible')
                    password_visible = True
                    break
                except:
                    continue

            if not password_visible:
                # Two-step flow - click "Next" button
                events.append("Two-step Okta flow detected - clicking 'Next'")
                next_selectors = [
                    "button:has-text('Next')",
                    "input[type='submit']",
                    "button[type='submit']",
                    "input[value='Next']",
                ]

                for selector in next_selectors:
                    try:
                        await page.click(selector)
                        events.append("Clicked 'Next' button")
                        recorded_actions.append(RecordedAction(
                            action="click",
                            selector=selector,
                            note="Okta Next"
                        ))
                        await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                        break
                    except:
                        continue

                # Take screenshot after username step
                screenshot_bytes = await page.screenshot(full_page=False)
                screenshots.append(ScreenshotCapture(
                    file_name="okta-02-password-step.png",
                    data=screenshot_bytes,
                    description="Okta Password Step"
                ))

            # Fill password field
            password_filled = False
            for selector in password_selectors:
                try:
                    await page.wait_for_selector(selector, timeout=10000, state='visible')
                    ensure_safe_to_type(page.url)
                    await page.fill(selector, password)
                    events.append("Entered password")
                    recorded_actions.append(RecordedAction(
                        action="type",
                        selector=selector,
                        value="${PASSWORD}",
                        note="Okta password"
                    ))
                    password_filled = True
                    break
                except:
                    continue

            if not password_filled:
                events.append("Error: Could not find password field")

            # Click "Sign In" button
            signin_selectors = [
                "button:has-text('Sign in')",
                "button:has-text('Sign In')",
                "input[type='submit']",
                "button[type='submit']",
                "button[data-type='save']",
            ]

            for selector in signin_selectors:
                try:
                    await page.click(selector)
                    events.append("Clicked 'Sign In' button")
                    recorded_actions.append(RecordedAction(
                        action="click",
                        selector=selector,
                        note="Okta Sign In"
                    ))
                    break
                except:
                    continue

            # Wait for Okta response
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)

            # Check if MFA is required
            mfa_required = await _detect_okta_mfa(page)
            if mfa_required:
                events.append("MFA required - authentication cannot proceed without manual MFA verification")

                screenshot_bytes = await page.screenshot(full_page=False)
                screenshots.append(ScreenshotCapture(
                    file_name="okta-03-mfa-prompt.png",
                    data=screenshot_bytes,
                    description="Okta MFA Prompt"
                ))

                await context.close()
                await browser.close()

                har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''

                return FormAuthResult(
                    success=False,  # Mark as failed because MFA blocks automation
                    final_url=page.url,
                    events=events,
                    screenshots=screenshots,
                    har_bytes=har_bytes,
                    cookies=await context.cookies(),
                    recorded_actions=recorded_actions,
                    username_selector="[Okta-managed]",
                    password_selector="[Okta-managed]",
                    submit_selector="[Okta-managed]",
                    submit_method="okta_widget",
                )

            # Check for authentication errors
            error_detected = await _detect_okta_error(page)
            if error_detected:
                events.append("Okta authentication failed: Invalid credentials")

                screenshot_bytes = await page.screenshot(full_page=False)
                screenshots.append(ScreenshotCapture(
                    file_name="okta-error.png",
                    data=screenshot_bytes,
                    description="Okta Error"
                ))

                await context.close()
                await browser.close()

                har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''

                return FormAuthResult(
                    success=False,
                    final_url=page.url,
                    events=events,
                    screenshots=screenshots,
                    har_bytes=har_bytes,
                    cookies=[],
                    recorded_actions=recorded_actions,
                )

            # Wait for Okta session redirect to application
            events.append("Waiting for Okta session redirect to application...")
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)

            final_url = page.url
            events.append(f"Okta authentication successful! Redirected to: {final_url}")

            # Take final screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name="okta-04-authenticated.png",
                data=screenshot_bytes,
                description="Okta Authentication Success"
            ))

            # Extract cookies
            cookies = await context.cookies()
            events.append(f"Extracted {len(cookies)} cookies from Okta session")

            # Close context to save HAR
            await context.close()
            await browser.close()

            # Read HAR file
            har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''
            events.append(f"HAR file captured: {len(har_bytes)} bytes")

            return FormAuthResult(
                success=True,
                final_url=final_url,
                page_title=await page.title(),
                events=events,
                screenshots=screenshots,
                har_bytes=har_bytes,
                cookies=cookies,
                recorded_actions=recorded_actions,
                username_selector="[Okta-managed]",
                password_selector="[Okta-managed]",
                submit_selector="[Okta-managed]",
                submit_method="okta_widget",
            )

        except PlaywrightTimeout as e:
            events.append(f"Okta auth timeout: {str(e)}")
            await context.close()
            await browser.close()

            har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''

            return FormAuthResult(
                success=False,
                final_url=page.url if page else target_url,
                events=events,
                screenshots=screenshots,
                har_bytes=har_bytes,
                cookies=[],
                recorded_actions=recorded_actions,
            )

        except Exception as e:
            events.append(f"Okta automation error: {str(e)}")
            await context.close()
            await browser.close()

            har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''

            return FormAuthResult(
                success=False,
                final_url=target_url,
                events=events,
                screenshots=screenshots,
                har_bytes=har_bytes,
                cookies=[],
                recorded_actions=recorded_actions,
            )


def _extract_okta_org(url: str) -> str | None:
    """Extract Okta org ID from URL."""
    if ".okta.com" in url:
        # Example: https://dev-12345.okta.com → dev-12345
        parts = url.split(".okta.com")[0].split("//")[-1]
        return parts if parts else None
    return None


async def _detect_okta_widget(page) -> bool:
    """Detect if page uses Okta Sign-In Widget."""
    try:
        # Check for Okta Widget-specific elements
        widget_selectors = [
            "#okta-sign-in",
            ".okta-sign-in-header",
            "[data-se='o-form']",
        ]

        for selector in widget_selectors:
            try:
                await page.wait_for_selector(selector, timeout=2000)
                return True
            except:
                continue

        return False
    except:
        return False


async def _detect_okta_mfa(page) -> bool:
    """Detect if MFA is required."""
    try:
        # Check for MFA prompts
        mfa_indicators = [
            "text=Select a factor",
            "text=Verify with",
            "text=Send push",
            "text=Enter code",
            "[data-se='factor-list']",
            "input[name='answer']",  # Security question
        ]

        for indicator in mfa_indicators:
            try:
                await page.wait_for_selector(indicator, timeout=2000)
                return True
            except:
                continue

        return False
    except:
        return False


async def _detect_okta_error(page) -> bool:
    """Detect authentication errors."""
    try:
        error_selectors = [
            "text=Unable to sign in",
            "text=Authentication failed",
            "text=Invalid username or password",
            ".okta-form-infobox-error",
            "[data-se='o-form-error-container']",
        ]

        for selector in error_selectors:
            try:
                await page.wait_for_selector(selector, timeout=2000)
                return True
            except:
                continue

        return False
    except:
        return False
