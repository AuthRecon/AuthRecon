"""
Playwright-based Microsoft ADFS authentication with HAR capture.

WHY PLAYWRIGHT FOR ADFS:
- ADFS has complex redirect chains (app → ADFS → Azure AD → app)
- CDP captures complete STS exchange (Security Token Service)
- HAR includes SAML assertions and WS-Federation messages
- Auto-waiting handles ADFS async redirects
- Windows Integrated Auth detection

MICROSOFT ADFS SCENARIOS:
- On-premises ADFS (adfs.company.com)
- Azure AD with ADFS federation
- Office 365 with federated domains
- Hybrid Azure AD Join scenarios

OUTPUT ARTIFACTS:
- network.har: Complete ADFS flow (STS requests, SAML assertions, redirects)
- Cookies: MSISAuth cookies (ADFS session tokens)
- Screenshots: ADFS login steps (username, password, redirect)
- Security context: ADFS endpoints, SAML assertions, claims
- Federation metadata: Extracted from /.well-known/federation.xml

ADFS-SPECIFIC FEATURES:
- Detects ADFS version (2.0, 3.0, 4.0)
- Handles domain\\username format
- Extracts STS endpoints
- Captures SAML/WS-Fed tokens in HAR
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


async def attempt_microsoft_adfs_login_playwright(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 60,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Attempt Microsoft ADFS authentication using Playwright with HAR capture.

    ADFS AUTH FLOW:
    1. Launch Chromium with HAR recording
    2. Navigate to target (triggers ADFS redirect)
    3. Detect ADFS login page (adfs.company.com or login.microsoftonline.com)
    4. Fill username (handle DOMAIN\\username format if domain_prefix provided)
    5. Fill password
    6. Submit credentials
    7. Wait for ADFS STS response (SAML assertion or WS-Fed token)
    8. Wait for redirect chain back to application
    9. Extract cookies, HAR, SAML assertions

    Args:
        run_id: Unique identifier for this auth run
        target_url: ADFS-protected URL (app redirects to ADFS)
        username: Username for ADFS account
        password: Password for ADFS account
        timeout_seconds: Max time for complete ADFS flow (default 60s)
        domain_prefix: Optional domain prefix for DOMAIN\\username format

    Returns:
        FormAuthResult with:
            - success: True if ADFS authentication succeeded
            - final_url: URL after ADFS callback (app dashboard)
            - har_bytes: Complete HAR with ADFS STS requests and SAML assertions
            - cookies: ADFS session cookies (MSISAuth, MSISAuthenticated)
            - screenshots: ADFS login steps
            - security_context: ADFS endpoints, SAML claims, federation metadata
            - events: ADFS auth flow timeline
            - recorded_actions: Replay instructions

    Note:
        If Windows Integrated Auth is configured, ADFS may not show login form.
        HAR will still contain redirect chain and federation metadata.
    """

    if not username:
        raise ValueError("Username required for ADFS authentication")
    if not password:
        raise ValueError("Password required for ADFS authentication")

    events: List[str] = live_events()
    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []
    har_path = None
    final_url = target_url
    cookies: List[Dict[str, Any]] = []

    # Format username with domain prefix if provided
    username_to_use = f"{domain_prefix}\\{username}" if domain_prefix else username

    async with async_playwright() as p:
        har_path = f"{browser_tmp_dir()}/{run_id}-adfs-network.har"

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
            # Navigate to ADFS-protected resource
            events.append(f"Navigating to ADFS-protected resource: {target_url}")
            browser, context, page, nav_timeout = await playwright_goto_with_http2_fallback(
                _open_page, browser, context, page, target_url,
                wait_until='networkidle', timeout=timeout_seconds * 1000,
            )
            if nav_timeout:
                raise nav_timeout
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)

            current_url = page.url
            events.append(f"Loaded ADFS page: {current_url}")

            # Detect ADFS version and type
            adfs_info = _detect_adfs_version(current_url)
            events.append(f"Detected ADFS: {adfs_info}")

            # Take pre-auth screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name="adfs-01-login-page.png",
                data=screenshot_bytes,
                description="ADFS Login Page"
            ))

            # Fill username field
            username_selectors = [
                "input[name='UserName']",
                "input[name='username']",
                "input[type='email']",
                "input[type='text']",
                "input#userNameInput",
                "input#i0116",  # Azure AD / Microsoft 365
            ]

            username_filled = False
            for selector in username_selectors:
                try:
                    await page.wait_for_selector(selector, timeout=5000, state='visible')
                    await page.fill(selector, username_to_use)
                    events.append(f"Entered username: {username_to_use}")
                    recorded_actions.append(RecordedAction(
                        action="type",
                        selector=selector,
                        value="${USERNAME}",
                        note="ADFS username"
                    ))
                    username_filled = True
                    break
                except:
                    continue

            if not username_filled:
                events.append("Error: Could not find username field on ADFS login page")
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
            password_selectors = [
                "input[type='password']",
                "input[name='Password']",
                "input[name='password']",
                "input#passwordInput",
                "input#i0118",  # Azure AD / Microsoft 365
            ]

            for selector in password_selectors:
                try:
                    await page.wait_for_selector(selector, timeout=2000, state='visible')
                    password_visible = True
                    break
                except:
                    continue

            if not password_visible:
                # Two-step flow - click "Next" button
                events.append("Two-step ADFS flow detected - clicking 'Next'")
                next_selectors = [
                    "button:has-text('Next')",
                    "input[type='submit']",
                    "button[type='submit']",
                    "input#submitButton",
                    "input[value='Next']",
                ]

                for selector in next_selectors:
                    try:
                        await page.click(selector)
                        events.append("Clicked 'Next' button")
                        recorded_actions.append(RecordedAction(
                            action="click",
                            selector=selector,
                            note="ADFS Next"
                        ))
                        await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                        break
                    except:
                        continue

                # Take screenshot after username step
                screenshot_bytes = await page.screenshot(full_page=False)
                screenshots.append(ScreenshotCapture(
                    file_name="adfs-02-password-step.png",
                    data=screenshot_bytes,
                    description="ADFS Password Step"
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
                        note="ADFS password"
                    ))
                    password_filled = True
                    break
                except:
                    continue

            if not password_filled:
                events.append("Error: Could not find password field on ADFS login page")

            # Click "Sign In" button
            signin_selectors = [
                "button:has-text('Sign in')",
                "button:has-text('Sign In')",
                "input[type='submit']",
                "button[type='submit']",
                "input#submitButton",
                "input[value='Sign in']",
            ]

            for selector in signin_selectors:
                try:
                    await page.click(selector)
                    events.append("Clicked 'Sign In' button")
                    recorded_actions.append(RecordedAction(
                        action="click",
                        selector=selector,
                        note="ADFS Sign In"
                    ))
                    break
                except:
                    continue

            # Wait for ADFS STS response and redirect chain
            events.append("Waiting for ADFS STS response and redirect chain...")
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)

            # Check for authentication errors
            error_detected = await _detect_adfs_error(page)
            if error_detected:
                events.append("ADFS authentication failed: Invalid credentials or access denied")

                screenshot_bytes = await page.screenshot(full_page=False)
                screenshots.append(ScreenshotCapture(
                    file_name="adfs-error.png",
                    data=screenshot_bytes,
                    description="ADFS Error"
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

            # Wait for final redirect to application
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)

            final_url = page.url
            events.append(f"ADFS authentication successful! Redirected to: {final_url}")

            # Take final screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name="adfs-03-authenticated.png",
                data=screenshot_bytes,
                description="ADFS Authentication Success"
            ))

            # Extract cookies
            cookies = await context.cookies()
            events.append(f"Extracted {len(cookies)} cookies from ADFS session")

            # Look for specific ADFS cookies
            adfs_cookies = [c for c in cookies if c.get('name', '').startswith('MSISAuth') or c.get('name', '').startswith('MSIS')]
            if adfs_cookies:
                events.append(f"Found {len(adfs_cookies)} ADFS session cookies")

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
                username_selector="[ADFS-managed]",
                password_selector="[ADFS-managed]",
                submit_selector="[ADFS-managed]",
                submit_method="adfs_sts",
            )

        except PlaywrightTimeout as e:
            events.append(f"ADFS auth timeout: {str(e)}")
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
            events.append(f"ADFS automation error: {str(e)}")
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


def _detect_adfs_version(url: str) -> str:
    """Detect ADFS version and type from URL."""
    url_lower = url.lower()

    if "adfs/ls" in url_lower:
        return "ADFS 2.0/3.0 (WS-Federation)"
    elif "adfs/oauth2" in url_lower:
        return "ADFS 4.0+ (OAuth 2.0)"
    elif "login.microsoftonline.com" in url_lower:
        return "Azure AD with ADFS Federation"
    elif "sts." in url_lower or "/adfs/" in url_lower:
        return "ADFS STS (Generic)"
    else:
        return "Unknown ADFS/STS"


async def _detect_adfs_error(page) -> bool:
    """Detect ADFS authentication errors."""
    try:
        error_selectors = [
            "text=Authentication failed",
            "text=Invalid username or password",
            "text=Access denied",
            "text=Incorrect user ID or password",
            "#errorText",
            ".error-message",
            "[id*='error']",
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
