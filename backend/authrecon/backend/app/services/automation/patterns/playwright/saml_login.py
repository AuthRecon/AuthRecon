"""
Playwright-based SAML 2.0 SSO authentication with HAR capture.

WHY PLAYWRIGHT FOR SAML:
- Captures complete SAML redirect chain in HAR (SP → IdP → SP)
- Network trace shows SAML XML assertions (base64-encoded)
- Auto-waiting handles multi-hop SAML redirects
- Sees all POST requests with SAMLResponse payloads

WHEN TO USE:
- SAML 2.0 Single Sign-On (Okta, OneLogin, Ping Identity as IdP)
- Enterprise SSO portals
- Government/healthcare authentication
- University login systems (Shibboleth)

OUTPUT ARTIFACTS:
- network.har: Complete SAML flow with XML assertions
- Cookies: Session cookies from Service Provider
- Screenshots: Pre-auth (IdP login), credentials-entered, post-auth (SP)
- SAML assertions visible in HAR request bodies

FLOW:
1. Navigate to Service Provider (SP)
2. SP redirects to Identity Provider (IdP) with SAMLRequest
3. Fill credentials on IdP login page
4. IdP generates SAML assertion
5. Browser POSTs SAMLResponse back to SP
6. SP validates assertion and creates session
7. Redirected to authenticated SP page
"""

from app.services.live_timeline import live_events
import tempfile
from pathlib import Path
from typing import List

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

from app.services.automation.navigation import (
    playwright_goto_with_http2_fallback,
    with_http2_disabled,
)

from app.services.automation.types import FormAuthResult, RecordedAction, ScreenshotCapture


async def attempt_saml_login_playwright(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 45,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Attempt SAML 2.0 authentication using Playwright with HAR capture.

    Returns:
        FormAuthResult with complete SAML flow captured in HAR
    """
    har_path = Path(tempfile.gettempdir()) / f"{run_id}-playwright.har"
    events: List[str] = live_events()
    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []

    async with async_playwright() as p:
        async def _open_page(disable_http2: bool = False):
            launch_args = ['--disable-blink-features=AutomationControlled']
            browser = await p.chromium.launch(
                headless=True,
                args=with_http2_disabled(launch_args) if disable_http2 else launch_args,
            )
            context = await browser.new_context(
                record_har_path=str(har_path),
                record_har_omit_content=False,
                record_har_mode='minimal',
                ignore_https_errors=True,
                user_agent='AuthRecon/1.0 (Playwright Engine - SAML)',
                viewport={'width': 1920, 'height': 1080},
            )
            page = await context.new_page()
            page.set_default_timeout(timeout_seconds * 1000)
            return browser, context, page

        browser, context, page = await _open_page()

        try:
            events.append("Launching Playwright browser with HAR recording (SAML mode)")

            # Navigate to SP (will redirect to IdP)
            events.append(f"Navigating to Service Provider: {target_url}")
            recorded_actions.append(RecordedAction(action="navigate", selector=target_url, value=""))

            browser, context, page, nav_timeout = await playwright_goto_with_http2_fallback(
                _open_page, browser, context, page, target_url,
                wait_until='networkidle', timeout=timeout_seconds * 1000,
            )
            if nav_timeout:
                events.append("⚠️ Initial navigation timeout")

            current_url = page.url
            if 'saml' in current_url.lower() or 'sso' in current_url.lower():
                events.append(f"Redirected to SAML IdP: {current_url}")

            pre_auth_html = await page.content()
            pre_auth_url = page.url

            # Screenshot 1: IdP login page
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-01-saml-idp-login.png",
                data=screenshot_bytes,
                description="SAML Identity Provider login page"
            ))
            events.append("Captured IdP login page screenshot")

            # Find username field on IdP
            events.append("Detecting SAML IdP username field")
            username_selectors = [
                'input[name="username"]', 'input[name="email"]', 'input[name="j_username"]',
                'input#username', 'input[type="email"]', 'input[type="text"]:visible:first'
            ]

            username_field = None
            for selector in username_selectors:
                username_field = page.locator(selector).first
                if await username_field.count() > 0:
                    try:
                        if await username_field.is_visible():
                            events.append(f"Found IdP username field: {selector}")
                            break
                    except:
                        continue

            if not username_field or await username_field.count() == 0:
                raise Exception("No username field on SAML IdP login page")

            # Fill username
            username_to_use = username
            if domain_prefix and username:
                username_to_use = f"{domain_prefix}\\{username}"
                events.append(f"Using domain-prefixed username: {username_to_use}")

            if username_to_use:
                events.append(f"Filling IdP username: {username_to_use}")
                await username_field.fill(username_to_use)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[name="username"], input[type="text"]',
                    value=username_to_use
                ))

            # Find password field
            events.append("Detecting SAML IdP password field")
            password_field = page.locator('input[type="password"]').first
            if await password_field.count() == 0:
                raise Exception("No password field on SAML IdP login page")

            # Fill password
            if password:
                events.append("Filling IdP password: ********")
                await password_field.fill(password)
                recorded_actions.append(RecordedAction(
                    action="fill",
                    selector='input[type="password"]',
                    value="********"
                ))

            # Screenshot 2: Credentials entered
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-02-saml-credentials-entered.png",
                data=screenshot_bytes,
                description="SAML IdP credentials entered"
            ))
            events.append("Captured credentials entered screenshot")

            # Submit to IdP
            events.append("Submitting credentials to SAML IdP")
            submit_selectors = [
                'button[type="submit"]', 'input[type="submit"]',
                'button[name="_eventId_proceed"]', 'button#submit'
            ]

            submit_button = None
            for selector in submit_selectors:
                submit_button = page.locator(selector).first
                if await submit_button.count() > 0:
                    try:
                        if await submit_button.is_visible():
                            break
                    except:
                        continue

            if not submit_button or await submit_button.count() == 0:
                await password_field.press('Enter')
            else:
                recorded_actions.append(RecordedAction(action="click", selector='button[type="submit"]', value=""))
                await submit_button.click()

            # Wait for SAML redirect chain (IdP → SP)
            events.append("Waiting for SAML assertion POST to Service Provider...")
            try:
                await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                events.append("SAML flow completed")
            except PlaywrightTimeout:
                events.append("⚠️ SAML redirect timeout")

            # Verify success
            final_url = page.url
            post_auth_html = await page.content()
            page_title = await page.title()

            # Success: redirected back to SP, not on IdP anymore
            url_changed = final_url != pre_auth_url
            not_on_idp = 'saml' not in final_url.lower() and 'sso' not in final_url.lower()
            no_password_field = await page.locator('input[type="password"]').count() == 0

            success = url_changed and (not_on_idp or no_password_field)

            if success:
                events.append(f"✅ SAML authentication successful (returned to SP: {final_url})")
            else:
                events.append(f"❌ SAML authentication may have failed")

            # Screenshot 3: Post-SAML (back at SP)
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name=f"{run_id}-03-saml-authenticated.png",
                data=screenshot_bytes,
                description="Authenticated at Service Provider after SAML"
            ))
            events.append("Captured post-SAML screenshot")

            # Extract cookies
            cookies_raw = await context.cookies()
            cookies = [
                {
                    'name': c['name'], 'value': c['value'], 'domain': c.get('domain', ''),
                    'path': c.get('path', '/'), 'secure': c.get('secure', False),
                    'httpOnly': c.get('httpOnly', False), 'sameSite': c.get('sameSite', 'Lax'),
                    'expires': c.get('expires'),
                }
                for c in cookies_raw
            ]
            events.append(f"Captured {len(cookies)} session cookies")

            # Close and save HAR
            await context.close()
            events.append("Closed browser context, HAR saved with SAML flow")

            har_bytes = None
            if har_path.exists():
                har_bytes = har_path.read_bytes()
                events.append(f"HAR file captured: {len(har_bytes) / 1024:.1f} KB (includes SAML assertions)")
                har_path.unlink()
            else:
                events.append("⚠️ HAR file not found")

            return FormAuthResult(
                final_url=final_url, page_title=page_title, heading=None, success_message=None,
                cookies=cookies, security_context=None, screenshots=screenshots, events=events,
                pre_auth_html=pre_auth_html, post_auth_html=post_auth_html,
                username_selector='input[name="username"]', password_selector='input[type="password"]',
                submit_selector='button[type="submit"]', submit_method='click',
                recorded_actions=recorded_actions, har_bytes=har_bytes, success=success,
            )

        finally:
            await browser.close()
