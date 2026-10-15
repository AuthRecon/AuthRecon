"""
Playwright-based OAuth 2.0 / OpenID Connect authentication with HAR capture.

WHY PLAYWRIGHT FOR OAUTH:
- Popup window support (many OAuth flows open new windows)
- CDP network monitoring captures complete redirect chain
- HAR file includes all OAuth endpoints (authorize, token, callback)
- Auto-waiting handles dynamic OAuth screens
- Context isolation prevents session leakage

OAUTH PROVIDERS SUPPORTED:
- Google OAuth ("Sign in with Google")
- GitHub OAuth
- LinkedIn
- Auth0
- AWS Cognito
- Generic OAuth 2.0 authorization code flow

OUTPUT ARTIFACTS:
- network.har: Complete OAuth flow (redirect chain, authorize, token exchange, callback)
- Cookies: Session tokens after successful OAuth callback
- Screenshots: Each OAuth step (redirect, login, consent, callback)
- Security context: OAuth-specific headers, redirect_uri, state param
- API endpoints: Discovered OAuth provider endpoints

COMPARISON TO SELENIUM:
- Selenium: Basic OAuth support, limited popup handling
- Playwright: Full OAuth flow capture with HAR, better popup/redirect handling
"""

from app.services.live_timeline import live_events
import time
from datetime import datetime, timezone
from typing import List, Dict, Any
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

from app.services.automation.navigation import (
    playwright_goto_with_http2_fallback,
    with_http2_disabled,
)

from app.services.automation.types import FormAuthResult, RecordedAction, ScreenshotCapture


async def attempt_oauth_login_playwright(
    run_id: str,
    target_url: str,
    username: str | None,
    password: str | None,
    timeout_seconds: int = 60,  # OAuth flows can take longer
    login_hint: str | None = None,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Attempt OAuth 2.0 / OIDC authentication using Playwright with HAR capture.

    OAUTH AUTHENTICATION FLOW:
    1. Launch Chromium with HAR recording + popup handling
    2. Navigate to target (wait for OAuth redirect)
    3. Detect OAuth provider (Google/GitHub/Generic)
    4. Handle popup windows if needed (some OAuth flows use popups)
    5. Fill credentials on provider's login page
    6. Wait for OAuth callback redirect back to app
    7. Extract cookies, HAR, security context
    8. Close browser → HAR saved automatically

    Args:
        run_id: Unique identifier for this auth run
        target_url: OAuth initiation URL (app redirects to provider)
        username: Username/email for OAuth provider
        password: Password for OAuth provider
        timeout_seconds: Max time for complete OAuth flow (default 60s)
        login_hint: Optional hint for selecting OAuth provider button
        domain_prefix: Optional domain prefix for enterprise OAuth

    Returns:
        FormAuthResult with:
            - success: True if OAuth callback received
            - final_url: URL after callback (app dashboard)
            - har_bytes: Complete HAR with all OAuth requests
            - cookies: Session cookies from app (post-OAuth)
            - screenshots: OAuth flow steps (provider login, consent, callback)
            - security_context: OAuth endpoints, redirect_uri, state param
            - events: Timeline of OAuth flow
            - recorded_actions: Replay instructions

    Raises:
        AutomationFailure: If OAuth provider not detected or callback fails
    """

    if not username:
        raise ValueError("Username required for OAuth authentication")
    if not password:
        raise ValueError("Password required for OAuth authentication")

    events: List[str] = live_events()
    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []
    har_path = None
    final_url = target_url
    cookies: List[Dict[str, Any]] = []

    async with async_playwright() as p:
        # Launch browser with HAR recording
        har_path = f"/tmp/{run_id}-oauth-network.har"

        async def _open_page(disable_http2: bool = False):
            launch_args = ['--disable-blink-features=AutomationControlled']
            browser = await p.chromium.launch(
                headless=True,
                args=with_http2_disabled(launch_args) if disable_http2 else launch_args,
            )
            context = await browser.new_context(
                record_har_path=har_path,
                record_har_omit_content=False,
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            )
            page = await context.new_page()
            return browser, context, page

        browser, context, page = await _open_page()

        try:
            # Navigate to OAuth initiation URL
            events.append(f"Navigating to OAuth initiation URL: {target_url}")
            browser, context, page, nav_timeout = await playwright_goto_with_http2_fallback(
                _open_page, browser, context, page, target_url,
                wait_until='networkidle', timeout=timeout_seconds * 1000,
            )
            if nav_timeout:
                raise nav_timeout
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)

            current_url = page.url
            events.append(f"Loaded OAuth page: {current_url}")

            # Take pre-auth screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name="oauth-01-initiation.png",
                data=screenshot_bytes,
                description="OAuth Initiation Page"
            ))

            # Handle pre-OAuth prompts (language pickers, disclaimers, etc.)
            await _handle_pre_oauth_prompts(page, events, recorded_actions)

            # Handle login hint - click specific OAuth provider button
            if login_hint:
                events.append(f"Looking for OAuth provider button with hint: '{login_hint}'")

                # Try to find button with hint text
                hint_selectors = [
                    f"button:has-text('{login_hint}')",
                    f"a:has-text('{login_hint}')",
                    f"[role='button']:has-text('{login_hint}')",
                ]

                clicked = False
                for selector in hint_selectors:
                    try:
                        await page.wait_for_selector(selector, timeout=5000)
                        await page.click(selector)
                        events.append(f"Clicked OAuth provider button: '{login_hint}'")
                        recorded_actions.append(RecordedAction(
                            action="click",
                            selector=selector,
                            note=f"Selected OAuth provider: {login_hint}"
                        ))
                        clicked = True
                        await page.wait_for_load_state('networkidle', timeout=10000)
                        break
                    except:
                        continue

                if not clicked:
                    events.append(f"Warning: Could not find OAuth button with hint '{login_hint}', continuing anyway")

            # Wait for OAuth provider redirect
            await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
            current_url = page.url

            # Detect OAuth provider
            provider = _detect_oauth_provider(current_url)
            events.append(f"Detected OAuth provider: {provider}")

            # Take provider login page screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name="oauth-02-provider-login.png",
                data=screenshot_bytes,
                description=f"{provider.title()} Login Page"
            ))

            # Authenticate with provider-specific flow
            if provider == "google":
                await _authenticate_google_playwright(page, username, password, events, recorded_actions, screenshots, timeout_seconds)
            elif provider == "github":
                await _authenticate_github_playwright(page, username, password, events, recorded_actions, screenshots, timeout_seconds)
            elif provider == "linkedin":
                await _authenticate_linkedin_playwright(page, username, password, events, recorded_actions, screenshots, timeout_seconds)
            else:
                await _authenticate_generic_oauth_playwright(page, username, password, events, recorded_actions, screenshots, domain_prefix, timeout_seconds)

            # Wait for OAuth callback redirect back to original app
            events.append("Waiting for OAuth callback redirect...")
            success, error_message = await _wait_for_oauth_callback(page, timeout_seconds, target_url, events)

            if not success:
                screenshot_bytes = await page.screenshot(full_page=False)
                screenshots.append(ScreenshotCapture(
                    file_name="oauth-error.png",
                    data=screenshot_bytes,
                    description="OAuth Error"
                ))
                events.append(f"OAuth callback failed: {error_message}")

                # Still close context to save HAR
                await context.close()
                har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''

                return FormAuthResult(
                    success=False,
                    final_url=page.url,
                    page_title=await page.title(),
                    events=events,
                    screenshots=screenshots,
                    har_bytes=har_bytes,
                    cookies=[],
                    recorded_actions=recorded_actions,
                    username_selector="[OAuth-managed]",
                    password_selector="[OAuth-managed]",
                    submit_selector="[OAuth-managed]",
                    submit_method="oauth_flow",
                )

            # OAuth callback successful
            final_url = page.url
            events.append(f"OAuth callback successful! Redirected to: {final_url}")

            # Take final screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshots.append(ScreenshotCapture(
                file_name="oauth-03-callback-success.png",
                data=screenshot_bytes,
                description="OAuth Callback Success"
            ))

            # Extract cookies
            cookies = await context.cookies()
            events.append(f"Extracted {len(cookies)} cookies from authenticated session")

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
                username_selector="[OAuth-managed]",
                password_selector="[OAuth-managed]",
                submit_selector="[OAuth-managed]",
                submit_method="oauth_flow",
            )

        except PlaywrightTimeout as e:
            events.append(f"OAuth flow timeout: {str(e)}")
            await context.close()
            await browser.close()

            har_bytes = Path(har_path).read_bytes() if har_path and Path(har_path).exists() else b''

            return FormAuthResult(
                success=False,
                final_url=page.url if page else target_url,
                page_title=await page.title() if page else None,
                events=events,
                screenshots=screenshots,
                har_bytes=har_bytes,
                cookies=[],
                recorded_actions=recorded_actions,
            )

        except Exception as e:
            events.append(f"OAuth automation error: {str(e)}")
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


def _detect_oauth_provider(url: str) -> str:
    """Detect OAuth provider from URL."""
    url_lower = url.lower()
    if "accounts.google.com" in url_lower or "google.com/o/oauth2" in url_lower:
        return "google"
    if "github.com/login" in url_lower or "github.com/oauth" in url_lower:
        return "github"
    if "linkedin.com/oauth" in url_lower or "linkedin.com/uas" in url_lower:
        return "linkedin"
    if "auth0.com" in url_lower:
        return "auth0"
    if "cognito" in url_lower or "amazoncognito.com" in url_lower:
        return "cognito"
    if "okta.com" in url_lower:
        return "okta"
    return "generic"


async def _authenticate_google_playwright(
    page,
    username: str,
    password: str,
    events: List[str],
    actions: List[RecordedAction],
    screenshots: List[ScreenshotCapture],
    timeout_seconds: int
) -> None:
    """Google OAuth-specific authentication flow (Playwright)."""

    # Google uses two-step: email first, then password
    events.append("Starting Google OAuth flow (two-step)...")

    # Step 1: Enter email
    email_selectors = ["input[type='email']", "input[name='identifier']", "input#identifierId"]

    for selector in email_selectors:
        try:
            await page.wait_for_selector(selector, timeout=10000)
            await page.fill(selector, username)
            events.append(f"Entered email: {username}")
            actions.append(RecordedAction(
                action="type",
                selector=selector,
                value="${USERNAME}",
                note="Google email"
            ))
            break
        except:
            continue

    # Click Next
    next_button_selectors = ["button:has-text('Next')", "button#identifierNext", "[id*='next']"]
    for selector in next_button_selectors:
        try:
            await page.click(selector)
            events.append("Clicked 'Next' button")
            actions.append(RecordedAction(action="click", selector=selector, note="Google Next"))
            break
        except:
            continue

    # Wait for password page
    await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
    time.sleep(1)  # Google transition delay

    screenshot_bytes = await page.screenshot(full_page=False)
    screenshots.append(ScreenshotCapture(
        file_name="oauth-google-password-step.png",
        data=screenshot_bytes,
        description="Google Password Step"
    ))

    # Step 2: Enter password
    password_selectors = ["input[type='password']", "input[name='password']", "input[name='Passwd']"]

    for selector in password_selectors:
        try:
            await page.wait_for_selector(selector, timeout=10000)
            await page.fill(selector, password)
            events.append("Entered password")
            actions.append(RecordedAction(
                action="type",
                selector=selector,
                value="${PASSWORD}",
                note="Google password"
            ))
            break
        except:
            continue

    # Click Sign in
    signin_selectors = ["button:has-text('Sign in')", "button#passwordNext", "[id*='submit']"]
    for selector in signin_selectors:
        try:
            await page.click(selector)
            events.append("Clicked 'Sign in' button")
            actions.append(RecordedAction(action="click", selector=selector, note="Google Sign in"))
            break
        except:
            continue

    # Wait for OAuth consent or callback
    await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)


async def _authenticate_github_playwright(
    page,
    username: str,
    password: str,
    events: List[str],
    actions: List[RecordedAction],
    screenshots: List[ScreenshotCapture],
    timeout_seconds: int
) -> None:
    """GitHub OAuth-specific authentication flow (Playwright)."""

    events.append("Starting GitHub OAuth flow (single-step)...")

    # GitHub: username and password on same page
    username_selectors = ["input[name='login']", "input#login_field", "input[type='text']"]

    for selector in username_selectors:
        try:
            await page.wait_for_selector(selector, timeout=10000)
            await page.fill(selector, username)
            events.append(f"Entered username: {username}")
            actions.append(RecordedAction(
                action="type",
                selector=selector,
                value="${USERNAME}",
                note="GitHub username"
            ))
            break
        except:
            continue

    password_selectors = ["input[name='password']", "input#password", "input[type='password']"]

    for selector in password_selectors:
        try:
            await page.fill(selector, password)
            events.append("Entered password")
            actions.append(RecordedAction(
                action="type",
                selector=selector,
                value="${PASSWORD}",
                note="GitHub password"
            ))
            break
        except:
            continue

    # Click Sign in
    signin_selectors = ["button[type='submit']", "input[type='submit']", "button[name='commit']"]
    for selector in signin_selectors:
        try:
            await page.click(selector)
            events.append("Clicked 'Sign in' button")
            actions.append(RecordedAction(action="click", selector=selector, note="GitHub Sign in"))
            break
        except:
            continue

    await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)


async def _authenticate_linkedin_playwright(
    page,
    username: str,
    password: str,
    events: List[str],
    actions: List[RecordedAction],
    screenshots: List[ScreenshotCapture],
    timeout_seconds: int
) -> None:
    """LinkedIn OAuth-specific authentication flow (Playwright)."""

    events.append("Starting LinkedIn OAuth flow...")

    # LinkedIn: single-step login
    email_selector = "input[name='session_key']"
    password_selector = "input[name='session_password']"

    try:
        await page.wait_for_selector(email_selector, timeout=10000)
        await page.fill(email_selector, username)
        events.append(f"Entered email: {username}")

        await page.fill(password_selector, password)
        events.append("Entered password")

        await page.click("button[type='submit']")
        events.append("Clicked 'Sign in' button")

        await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
    except Exception as e:
        events.append(f"LinkedIn auth error: {str(e)}")


async def _authenticate_generic_oauth_playwright(
    page,
    username: str,
    password: str,
    events: List[str],
    actions: List[RecordedAction],
    screenshots: List[ScreenshotCapture],
    domain_prefix: str | None,
    timeout_seconds: int
) -> None:
    """Generic OAuth authentication (tries common patterns) (Playwright)."""

    events.append("Starting generic OAuth flow...")

    # Get username with domain prefix if provided
    username_to_use = f"{domain_prefix}\\{username}" if domain_prefix else username

    # Try to find username/email field
    username_selectors = [
        "input[type='email']",
        "input[type='text']",
        "input[name='username']",
        "input[name='email']",
        "input[id*='user']",
        "input[id*='email']",
    ]

    username_found = False
    for selector in username_selectors:
        try:
            await page.wait_for_selector(selector, timeout=5000)
            await page.fill(selector, username_to_use)
            events.append(f"Entered username: {username_to_use}")
            actions.append(RecordedAction(
                action="type",
                selector=selector,
                value="${USERNAME}",
                note="Generic OAuth username"
            ))
            username_found = True
            break
        except:
            continue

    if not username_found:
        events.append("Warning: Could not find username field")
        return

    # Check if password field is visible (single-step form)
    password_selectors = ["input[type='password']"]
    password_visible = False

    for selector in password_selectors:
        try:
            await page.wait_for_selector(selector, timeout=2000, state='visible')
            password_visible = True
            break
        except:
            continue

    if password_visible:
        # Single-step form
        events.append("Detected single-step OAuth form")
        await page.fill("input[type='password']", password)
        events.append("Entered password")

        # Find and click submit
        submit_selectors = ["button[type='submit']", "input[type='submit']", "button:has-text('Sign in')", "button:has-text('Login')"]
        for selector in submit_selectors:
            try:
                await page.click(selector)
                events.append("Clicked submit button")
                break
            except:
                continue
    else:
        # Two-step form - click next first
        events.append("Detected two-step OAuth form")
        next_selectors = ["button:has-text('Next')", "button:has-text('Continue')", "button[type='submit']"]
        for selector in next_selectors:
            try:
                await page.click(selector)
                events.append("Clicked 'Next' button")
                await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)
                break
            except:
                continue

        # Now enter password
        for selector in password_selectors:
            try:
                await page.wait_for_selector(selector, timeout=10000)
                await page.fill(selector, password)
                events.append("Entered password (step 2)")
                break
            except:
                continue

        # Click final submit
        submit_selectors = ["button[type='submit']", "button:has-text('Sign in')", "button:has-text('Login')"]
        for selector in submit_selectors:
            try:
                await page.click(selector)
                events.append("Clicked submit button")
                break
            except:
                continue

    await page.wait_for_load_state('networkidle', timeout=timeout_seconds * 1000)


async def _wait_for_oauth_callback(
    page,
    timeout_seconds: int,
    original_url: str,
    events: List[str]
) -> tuple[bool, str | None]:
    """
    Wait for OAuth callback redirect back to original application.

    OAuth flow: App → Provider → Callback with code → App exchanges code for token
    """
    deadline = time.time() + timeout_seconds
    original_domain = urlparse(original_url).hostname or ""

    events.append(f"Waiting for callback to original domain: {original_domain}")

    while time.time() < deadline:
        current_url = page.url or ""
        current_domain = urlparse(current_url).hostname or ""

        # Check if we're back at the original domain (callback completed)
        if current_domain == original_domain:
            events.append(f"OAuth callback received! Back at: {current_url}")

            # Additional check: not on an error page
            try:
                body_text = await page.text_content("body")
                body_lower = (body_text or "").lower()
                if "error" in body_lower or "denied" in body_lower or "failed" in body_lower:
                    return False, "OAuth callback returned error page"
            except:
                pass

            return True, None

        # Check for authorization code in URL (callback in progress)
        if "code=" in current_url or "access_token=" in current_url or "id_token=" in current_url:
            events.append(f"OAuth callback in progress (code detected): {current_url[:80]}...")
            # Wait for final redirect
            await page.wait_for_load_state('networkidle', timeout=5000)
            continue

        # Wait a bit before checking again
        await page.wait_for_timeout(500)

    return False, f"OAuth callback timeout - still at {current_domain}, expected {original_domain}"


async def _handle_pre_oauth_prompts(page, events: List[str], recorded_actions: List[RecordedAction]) -> None:
    """
    Handle pre-OAuth prompts like language pickers, disclaimers, and splash pages.

    Similar to form_based pattern's _handle_pre_login_prompts but for OAuth flows.
    Many OAuth flows start with a language picker or disclaimer before the actual OAuth redirect.

    This function detects common prompt buttons and clicks them automatically.
    """
    PROMPT_KEYWORDS = [
        "english", "français", "french", "lang",
        "continue", "accept", "agree", "confirm", "proceed", "next"
    ]

    # Elements to skip - these are navigation/header elements, not prompts
    SKIP_IDS = [
        "languageToggleLink",    # Portal language toggle
        "languageToggle",         # Generic language toggle
        "language-toggle",        # Kebab-case variant
        "language_toggle",        # Snake-case variant
    ]

    SKIP_CLASSES = [
        "language-selector",
        "lang-switch",
        "header-lang",
        "nav-lang",
    ]

    language_clicked = False  # Track if we already clicked a language button

    # Try up to 3 times to handle nested prompts
    for attempt in range(3):
        try:
            # Find buttons or links with prompt keywords
            buttons = await page.query_selector_all("button, a[role='button'], input[type='button'], input[type='submit']")

            for button in buttons:
                try:
                    # Check if button is visible
                    if not await button.is_visible():
                        continue

                    # Skip navigation/header elements
                    button_id = (await button.get_attribute("id") or "").lower()
                    button_class = (await button.get_attribute("class") or "").lower()

                    # Skip if ID matches excluded elements
                    if any(skip_id.lower() in button_id for skip_id in SKIP_IDS):
                        events.append(f"Skipping navigation element (ID): {button_id}")
                        continue

                    # Skip if class matches excluded elements
                    if any(skip_class in button_class for skip_class in SKIP_CLASSES):
                        events.append(f"Skipping navigation element (class): {button_class}")
                        continue

                    # Get button text/label
                    text = (await button.text_content() or "").strip()
                    value = (await button.get_attribute("value") or "").strip()
                    aria_label = (await button.get_attribute("aria-label") or "").strip()

                    label = " ".join([text, value, aria_label]).lower()

                    # Check if it matches prompt keywords
                    if any(keyword in label for keyword in PROMPT_KEYWORDS):
                        # Check if this is a language button
                        is_language_button = any(kw in label for kw in ["english", "français", "french", "lang"])

                        # Skip if we already clicked a language button (prevent toggle loops)
                        if is_language_button and language_clicked:
                            events.append(f"Skipping additional language button: '{text or value or aria_label}' (already clicked one)")
                            continue

                        events.append(f"Found pre-OAuth prompt button: '{text or value or aria_label}'")

                        # Click the button
                        await button.click()
                        events.append("Clicked pre-OAuth prompt button")

                        if is_language_button:
                            language_clicked = True

                        recorded_actions.append(RecordedAction(
                            action="click",
                            selector=f"button:has-text('{text}')" if text else "button",
                            note=f"Dismissed pre-OAuth prompt: {text or value or aria_label}"
                        ))

                        # Wait for page to load after clicking
                        await page.wait_for_load_state('networkidle', timeout=5000)

                        # Successfully clicked a prompt, break to check for more
                        break

                except Exception as e:
                    # Button might be stale, continue to next
                    continue
            else:
                # No prompt button found, we're done
                return

        except Exception as e:
            # Error finding buttons, we're done
            events.append(f"Pre-OAuth prompt handling complete (no more prompts found)")
            return
