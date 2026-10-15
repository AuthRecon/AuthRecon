"""
OAuth 2.0 / OpenID Connect Authentication Automation Module

Handles authentication flows for:
- "Sign in with Google"
- "Sign in with GitHub"
- "Sign in with LinkedIn"
- Auth0 custom domains
- AWS Cognito
- Generic OAuth 2.0 authorization code flow

Common in:
- Modern SaaS applications
- Developer platforms
- Social login integrations
"""
from __future__ import annotations

from app.services.live_timeline import live_events
import time
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from ..browser import create_chrome_options, create_webdriver
from ..navigation import selenium_get_with_http2_fallback
from ..security_context_extractor import extract_security_context
from ..types import FormAuthResult, ScreenshotCapture, RecordedAction, AutomationFailure
from ..username_utils import get_username_variants
from ..pre_run_discovery import discover_auth_elements
from .form_login import _extract_heading, _extract_feedback_message


# OAuth provider-specific selectors
GOOGLE_USERNAME_SELECTORS: List[str] = [
    "input[type='email']",
    "input[name='identifier']",
    "input#identifierId",
]

GOOGLE_PASSWORD_SELECTORS: List[str] = [
    "input[type='password']",
    "input[name='password']",
    "input[name='Passwd']",
]

GITHUB_USERNAME_SELECTORS: List[str] = [
    "input[name='login']",
    "input#login_field",
    "input[type='text']",
]

GITHUB_PASSWORD_SELECTORS: List[str] = [
    "input[name='password']",
    "input#password",
    "input[type='password']",
]

GENERIC_SUBMIT_SELECTORS: List[str] = [
    "button[type='submit']",
    "input[type='submit']",
    "button#next",
    "button[name='commit']",
    ".button-primary",
    "[id*='submit']",
    "[id*='next']",
    "[id*='continue']",
]

# Microsoft Entra ID / Azure AD selectors
MICROSOFT_USERNAME_SELECTORS: List[str] = [
    "input[name='loginfmt']",
    "input#i0116",
    "input[type='email']",
]

MICROSOFT_PASSWORD_SELECTORS: List[str] = [
    "input[name='passwd']",
    "input#i0118",
    "input[type='password']",
]

MICROSOFT_SUBMIT_SELECTORS: List[str] = [
    "button#idSIButton9",
    "input#idSIButton9",
    "button[type='submit']",
    "input[type='submit']",
]

MICROSOFT_DECLINE_KMSI_SELECTORS: List[str] = [
    "button#idBtn_Back",
    "input#idBtn_Back",
]


def run_oauth_login(
    target_url: str,
    username: str,
    password: str,
    *,
    headless: bool = True,
    timeout_seconds: int = 45,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Automated OAuth 2.0 / OIDC Login.

    Supports:
    - Google OAuth ("Sign in with Google")
    - GitHub OAuth
    - Generic OAuth 2.0 authorization code flow
    - State parameter tracking
    - Redirect chain capture

    Args:
        target_url: URL to authenticate against
        username: Username/email for authentication
        password: Password for authentication
        headless: Run browser in headless mode
        timeout_seconds: Maximum time to wait for operations
        login_hint: Optional hint for selecting login entrypoint
        domain_prefix: Optional domain prefix for DOMAIN\\username format

    Returns:
        FormAuthResult with authentication details

    Raises:
        ValueError: If username or password not provided
        AutomationFailure: If authentication fails
    """
    if not username:
        raise ValueError("Username must be provided for OAuth automation.")
    if not password:
        raise ValueError("Password must be provided for OAuth automation.")

    options = create_chrome_options(headless=headless)
    driver = create_webdriver(options)

    events: List[str] = live_events()
    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []

    try:
        driver.set_page_load_timeout(timeout_seconds)
        driver = selenium_get_with_http2_fallback(
            driver, target_url, headless=headless, page_load_timeout=timeout_seconds
        )
        _wait_for_document_ready(driver)
        events.append("Loaded OAuth initiation page.")

        # Handle pre-OAuth prompts (language pickers, disclaimers, etc.)
        from ..patterns.form_login import _handle_pre_login_prompts
        _handle_pre_login_prompts(driver, events.append, recorded_actions)

        # Wait for OAuth redirect
        time.sleep(2)
        current_url = driver.current_url.lower()

        # Detect OAuth provider
        provider = _detect_oauth_provider(current_url)
        events.append(f"Detected OAuth provider: {provider}")

        # === PRE-RUN DISCOVERY: Aggressively scan for auth elements ===
        events.append("Running pre-run discovery to map all authentication elements...")
        discovery_result = discover_auth_elements(driver, driver.current_url)

        # Log discovery results
        events.append(f"Discovery complete: {discovery_result.recommended_approach} (confidence: {discovery_result.confidence}%)")
        events.append(f"  Found {len(discovery_result.forms)} forms, {len(discovery_result.endpoints)} endpoints, {len(discovery_result.clickable_auth_elements)} clickable elements")

        # Log all discovery notes
        for note in discovery_result.notes:
            events.append(f"  Discovery: {note}")

        # Handle login hint - select correct entrypoint if multiple login buttons exist
        if login_hint:
            from ..entrypoint_selection import select_login_entrypoint, click_entrypoint_safe
            entrypoint, candidates = select_login_entrypoint(driver, login_hint)
            if entrypoint:
                events.append(f"Selected login path: '{candidates[0].text}' (hint: '{login_hint}')")
                if click_entrypoint_safe(entrypoint, driver):
                    events.append("Clicked login entrypoint button.")
                    recorded_actions.append(
                        RecordedAction(
                            action="click",
                            selector=_selector_for_element(driver, entrypoint),
                            note=f"Selected login path: {candidates[0].text}",
                        )
                    )
                    _wait_for_document_ready(driver)
                    time.sleep(1)

        pre_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "oauth_step_01_pre"))

        # Provider-specific authentication
        if provider == "google":
            _authenticate_google(driver, username, password, events, recorded_actions, screenshots)
        elif provider == "github":
            _authenticate_github(driver, username, password, events, recorded_actions, screenshots)
        else:
            # Generic OAuth flow
            _authenticate_generic(driver, username, password, events, recorded_actions, screenshots, domain_prefix)

        # Wait for callback redirect
        success, error_message = _wait_for_oauth_callback(driver, timeout_seconds, target_url)
        if not success:
            error_capture = _capture(driver, "oauth_step_error")
            screenshots.append(error_capture)
            message = error_message or "Credentials rejected or OAuth flow failed."
            events.append(f"OAuth authentication failed: {message}")
            html_failure = driver.page_source or ""
            raise AutomationFailure(
                message=message,
                screenshots=screenshots,
                events=events,
                html=html_failure,
            )

        events.append("OAuth authentication flow completed.")
        post_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "oauth_step_final"))

        # Extract pattern candidates from authenticated page
        heading = _extract_heading(driver)
        success_message = _extract_feedback_message(driver)

        # Extract comprehensive security context (Phase 1: cookies only)
        security_context = extract_security_context(driver, target_url)

        return FormAuthResult(
            final_url=driver.current_url,
            page_title=driver.title or None,
            heading=heading,
            success_message=success_message,
            cookies=driver.get_cookies(),
            security_context=security_context,
            screenshots=screenshots,
            events=events,
            pre_auth_html=pre_auth_html,
            post_auth_html=post_auth_html,
            username_selector="[OAuth-managed]",
            password_selector="[OAuth-managed]",
            submit_selector="[OAuth-managed]",
            submit_method="oauth_flow",
            recorded_actions=recorded_actions,
        )
    finally:
        driver.quit()


def _detect_oauth_provider(url: str) -> str:
    """Detect OAuth provider from URL."""
    url_lower = url.lower()
    if "accounts.google.com" in url_lower:
        return "google"
    if "github.com" in url_lower:
        return "github"
    if "linkedin.com" in url_lower:
        return "linkedin"
    if "auth0.com" in url_lower:
        return "auth0"
    if "cognito" in url_lower:
        return "cognito"
    # Microsoft Entra ID / Azure AD
    if "login.microsoftonline.com" in url_lower:
        return "microsoft"
    if "login.live.com" in url_lower:
        return "microsoft"
    if "login.windows.net" in url_lower:
        return "microsoft"
    return "generic"


def _authenticate_google(
    driver: webdriver.Chrome,
    username: str,
    password: str,
    events: List[str],
    actions: List[RecordedAction],
    screenshots: List[ScreenshotCapture]
) -> None:
    """Google OAuth-specific authentication flow."""
    # Step 1: Enter email
    email_field = _wait_for_first(driver, GOOGLE_USERNAME_SELECTORS)
    if email_field is None:
        raise RuntimeError("Google OAuth page did not expose email field.")

    email_field.clear()
    email_field.send_keys(username)
    events.append("Entered email address (Google OAuth).")
    actions.append(RecordedAction(action="type", selector="input[type='email']", value="${USERNAME}", note="Google email"))

    # Click Next
    next_button = _wait_for_first(driver, GENERIC_SUBMIT_SELECTORS)
    if next_button:
        _safe_click(driver, next_button)
        events.append("Clicked 'Next' (Google OAuth).")
        time.sleep(2)

    screenshots.append(_capture(driver, "oauth_google_step_02_password"))

    # Step 2: Enter password
    password_field = _wait_for_first(driver, GOOGLE_PASSWORD_SELECTORS)
    if password_field is None:
        raise RuntimeError("Google OAuth page did not expose password field.")

    password_field.clear()
    password_field.send_keys(password)
    events.append("Entered password (Google OAuth).")
    actions.append(RecordedAction(action="type", selector="input[type='password']", value="${PASSWORD}", note="Google password"))

    # Click Sign in
    signin_button = _wait_for_first(driver, GENERIC_SUBMIT_SELECTORS)
    if signin_button:
        _safe_click(driver, signin_button)
        events.append("Clicked 'Sign in' (Google OAuth).")
        time.sleep(2)


def _authenticate_github(
    driver: webdriver.Chrome,
    username: str,
    password: str,
    events: List[str],
    actions: List[RecordedAction],
    screenshots: List[ScreenshotCapture]
) -> None:
    """GitHub OAuth-specific authentication flow."""
    # GitHub is single-step: username + password on same page
    username_field = _wait_for_first(driver, GITHUB_USERNAME_SELECTORS)
    if username_field is None:
        raise RuntimeError("GitHub OAuth page did not expose username field.")

    username_field.clear()
    username_field.send_keys(username)
    events.append("Entered username (GitHub OAuth).")
    actions.append(RecordedAction(action="type", selector="input[name='login']", value="${USERNAME}", note="GitHub username"))

    password_field = _wait_for_first(driver, GITHUB_PASSWORD_SELECTORS)
    if password_field is None:
        raise RuntimeError("GitHub OAuth page did not expose password field.")

    password_field.clear()
    password_field.send_keys(password)
    events.append("Entered password (GitHub OAuth).")
    actions.append(RecordedAction(action="type", selector="input[name='password']", value="${PASSWORD}", note="GitHub password"))

    screenshots.append(_capture(driver, "oauth_github_credentials"))

    signin_button = _wait_for_first(driver, GENERIC_SUBMIT_SELECTORS)
    if signin_button:
        _safe_click(driver, signin_button)
        events.append("Clicked 'Sign in' (GitHub OAuth).")
        time.sleep(2)


def _authenticate_generic(
    driver: webdriver.Chrome,
    username: str,
    password: str,
    events: List[str],
    actions: List[RecordedAction],
    screenshots: List[ScreenshotCapture],
    domain_prefix: str | None
) -> None:
    """Generic OAuth authentication (tries common patterns)."""
    # Get username variants
    username_variants = get_username_variants(username, domain_prefix)
    username_to_use = username_variants[0]

    # Try to find username/email field
    username_selectors = ["input[type='email']", "input[type='text']", "input[name='username']", "input[name='email']"]
    username_field = _wait_for_first(driver, username_selectors, timeout=10)

    if username_field:
        # Get specific selector for username field
        username_selector = _selector_for_element(driver, username_field)

        username_field.clear()
        username_field.send_keys(username_to_use)
        events.append("Entered username (generic OAuth).")
        actions.append(RecordedAction(
            action="type",
            selector=username_selector or "input[type='email']",
            value="${USERNAME}",
            note="OAuth username"
        ))

        # Try to find password field
        password_field = _wait_for_first(driver, ["input[type='password']"], timeout=5)

        if password_field:
            # Single-step form
            password_selector = _selector_for_element(driver, password_field)

            password_field.clear()
            password_field.send_keys(password)
            events.append("Entered password (generic OAuth).")
            actions.append(RecordedAction(
                action="type",
                selector=password_selector or "input[type='password']",
                value="${PASSWORD}",
                note="OAuth password"
            ))

            screenshots.append(_capture(driver, "oauth_generic_credentials"))

            submit_button = _wait_for_first(driver, GENERIC_SUBMIT_SELECTORS)
            if submit_button:
                submit_selector = _selector_for_element(driver, submit_button)
                _safe_click(driver, submit_button)
                events.append("Submitted credentials (generic OAuth).")
                actions.append(RecordedAction(
                    action="click",
                    selector=submit_selector or "button[type='submit']",
                    note="Submit credentials"
                ))
                time.sleep(2)
        else:
            # Two-step form - click next first
            next_button = _wait_for_first(driver, GENERIC_SUBMIT_SELECTORS)
            if next_button:
                next_selector = _selector_for_element(driver, next_button)
                _safe_click(driver, next_button)
                events.append("Clicked 'Next' (generic OAuth).")
                actions.append(RecordedAction(
                    action="click",
                    selector=next_selector or "button[type='submit']",
                    note="Click Next button"
                ))
                time.sleep(2)

                # Now find password field
                password_field = _wait_for_first(driver, ["input[type='password']"], timeout=10)
                if password_field:
                    password_selector = _selector_for_element(driver, password_field)

                    password_field.clear()
                    password_field.send_keys(password)
                    events.append("Entered password (generic OAuth step 2).")
                    actions.append(RecordedAction(
                        action="type",
                        selector=password_selector or "input[type='password']",
                        value="${PASSWORD}",
                        note="OAuth password step 2"
                    ))

                    screenshots.append(_capture(driver, "oauth_generic_password"))

                    submit_button = _wait_for_first(driver, GENERIC_SUBMIT_SELECTORS)
                    if submit_button:
                        submit_selector = _selector_for_element(driver, submit_button)
                        _safe_click(driver, submit_button)
                        events.append("Submitted password (generic OAuth).")
                        actions.append(RecordedAction(
                            action="click",
                            selector=submit_selector or "button[type='submit']",
                            note="Submit password"
                        ))
                        time.sleep(2)


def _wait_for_oauth_callback(driver: webdriver.Chrome, timeout_seconds: int, original_url: str) -> tuple[bool, str | None]:
    """
    Wait for OAuth callback redirect back to original application.

    OAuth flow: App → Provider → Callback with code → App exchanges code for token
    """
    deadline = time.time() + timeout_seconds
    original_domain = urlparse(original_url).hostname or ""

    while time.time() < deadline:
        current_url = driver.current_url or ""
        current_domain = urlparse(current_url).hostname or ""

        # Check if we're back at the original domain (callback completed)
        if current_domain == original_domain:
            # Additional check: not on an error page
            try:
                body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
                if "error" in body_text or "denied" in body_text or "failed" in body_text:
                    return False, "OAuth callback returned error"
            except Exception:
                pass

            return True, None

        # Check for authorization code in URL (callback in progress)
        if "code=" in current_url or "access_token=" in current_url:
            # Callback received, wait for final redirect
            time.sleep(2)
            continue

        time.sleep(0.5)

    return False, "OAuth callback timeout - did not redirect back to application"


def _wait_for_document_ready(driver: webdriver.Chrome) -> None:
    """Wait for document ready state."""
    driver.implicitly_wait(0)
    for _ in range(60):
        state = driver.execute_script("return document.readyState")
        if state == "complete":
            return
        time.sleep(0.1)


def _capture(driver: webdriver.Chrome, label: str) -> ScreenshotCapture:
    """Capture screenshot with label."""
    filename = f"{label}.png"
    return ScreenshotCapture(
        file_name=filename,
        data=driver.get_screenshot_as_png(),
        description=label.replace("_", " ").title()
    )


def _wait_for_first(driver: webdriver.Chrome, selectors: List[str], timeout: int = 20) -> Optional[WebElement]:
    """Wait for first matching element from list of selectors."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for selector in selectors:
            try:
                element = driver.find_element(By.CSS_SELECTOR, selector)
                if _is_interactable(element) or element.tag_name.lower() == "input":
                    return element
            except NoSuchElementException:
                continue
        time.sleep(0.25)
    return None


def _safe_click(driver: webdriver.Chrome, element: WebElement) -> None:
    """Click element with JavaScript fallback."""
    try:
        element.click()
    except Exception:
        driver.execute_script("arguments[0].click();", element)


def _selector_for_element(driver: webdriver.Chrome, element: Optional[WebElement]) -> str | None:
    """Generate CSS selector for element."""
    if element is None:
        return None

    tag = (element.tag_name or "").lower() or "*"

    # Try id first
    element_id = element.get_attribute("id")
    if element_id:
        return f"css={tag}#{element_id}"

    # Try name
    name = element.get_attribute("name")
    if name:
        return f'css={tag}[name="{name}"]'

    # Try class
    class_attr = element.get_attribute("class")
    if class_attr:
        first_class = class_attr.strip().split()[0]
        if first_class:
            return f"css={tag}.{first_class}"

    return f"css={tag}"


def _is_interactable(element: WebElement) -> bool:
    """Check if element is interactable."""
    try:
        return element.is_displayed() and element.is_enabled()
    except StaleElementReferenceException:
        return False
