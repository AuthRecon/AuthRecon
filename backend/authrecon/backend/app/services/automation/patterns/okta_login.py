"""Okta authentication automation module."""

from __future__ import annotations

from app.services.live_timeline import live_events
import time
from typing import Callable, List, Optional, Tuple

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
from app.services.automation.typing_guard import ensure_safe_to_type


# Okta Sign-In Widget Selectors
OKTA_USERNAME_SELECTORS: List[str] = [
    "input[name='username']",
    "input[data-se='o-form-input-username']",
    "input#okta-signin-username",
    "input[type='text'][autocomplete='username']",
    "input[type='email'][autocomplete='username']",
    "input[type='text']",  # Fallback for generic text input
]

OKTA_PASSWORD_SELECTORS: List[str] = [
    "input[name='password']",
    "input[data-se='o-form-input-password']",
    "input#okta-signin-password",
    "input[type='password']",
]

OKTA_SUBMIT_SELECTORS: List[str] = [
    "input[type='submit']",
    "button[type='submit']",
    "button[data-se='submit']",
    "input[value='Sign In']",
    "button[value='Sign In']",
    ".okta-form-submit",
    "button.button-primary",
]

OKTA_ERROR_SELECTORS: List[str] = [
    ".okta-form-infobox-error",
    ".okta-form-error",
    "div[data-se='o-form-error-container']",
    ".o-form-error-container",
    "[role='alert']",
    ".error-message",
    "#error",
]

OKTA_MFA_SELECTORS: List[str] = [
    ".mfa-verify",
    "[data-se='mfa-verify']",
    ".okta-verify-container",
    "#okta-verify",
    ".authenticator-verify-list",
]

MFA_KEYWORDS = [
    "verify",
    "authentication",
    "security code",
    "enter code",
    "push notification",
    "authenticator app",
    "text message",
    "sms",
    "duo security",
    "extra verification",
]

# Okta hosted domains
OKTA_HOSTS = (
    "okta.com",
    "okta-emea.com",
    "oktacdn.com",
)


def run_okta_login(
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
    Automated Okta Sign-In Widget/Form Login.

    Supports:
    - Okta Sign-In Widget (JavaScript-based)
    - Okta branded login forms
    - Custom domain SSO redirects
    - Two-step flows (username → password)
    - MFA detection (treated as automation failure)

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
        raise ValueError("Username must be provided for Okta automation.")
    if not password:
        raise ValueError("Password must be provided for Okta automation.")

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
        events.append("Loaded Okta sign-in page.")

        # Wait for Okta widget to render (JavaScript may need time)
        _wait_for_okta_widget(driver, timeout=10)
        events.append("Okta widget/form detected and ready.")

        # === PRE-RUN DISCOVERY: Aggressively scan for auth elements ===
        events.append("Running pre-run discovery to map all authentication elements...")
        discovery_result = discover_auth_elements(driver, target_url)

        # Log discovery results
        events.append(f"Discovery complete: {discovery_result.recommended_approach} (confidence: {discovery_result.confidence}%)")
        events.append(f"  Found {len(discovery_result.forms)} forms, {len(discovery_result.endpoints)} endpoints, {len(discovery_result.clickable_auth_elements)} clickable elements")
        if discovery_result.iframes_found > 0:
            events.append(f"  Detected {discovery_result.iframes_found} iframes")
        if discovery_result.shadow_roots_found > 0:
            events.append(f"  Detected {discovery_result.shadow_roots_found} shadow DOM roots")

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
                    time.sleep(1)  # Brief pause for any dynamic content
                else:
                    events.append("Warning: Failed to click login entrypoint.")
            else:
                events.append(f"Warning: No matching login button found for hint '{login_hint}'")

        pre_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "okta_step_01_pre"))

        # Detect if this is single-step or two-step flow
        password_visible = _is_password_visible(driver)
        is_two_step = not password_visible

        if is_two_step:
            events.append("Detected two-step flow (username → password)")
        else:
            events.append("Detected single-step flow (username + password)")

        # Step 1: Enter username
        username_field = _wait_for_first(driver, OKTA_USERNAME_SELECTORS)
        if username_field is None:
            raise RuntimeError("Okta login page did not expose a username field.")
        username_selector = _selector_for_element(driver, username_field)

        # Get username variants (supports DOMAIN\username)
        username_variants = get_username_variants(username, domain_prefix)
        username_to_use = username_variants[0]

        if domain_prefix:
            events.append(f"Using username format: {username_to_use} (domain prefix: {domain_prefix})")

        username_field.clear()
        username_field.send_keys(username_to_use)
        events.append("Populated username field.")
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=username_selector,
                value="${USERNAME}",
                note="Entered Okta username/email",
            )
        )

        password_selector = None

        if is_two_step:
            # Two-step flow: submit username, wait for password field
            next_button = _wait_for_first(driver, OKTA_SUBMIT_SELECTORS)
            if next_button is None:
                raise RuntimeError("Okta login page did not expose a Next button after username entry.")
            next_selector = _selector_for_element(driver, next_button)
            _safe_click(driver, next_button)
            events.append("Submitted username step.")
            recorded_actions.append(
                RecordedAction(
                    action="click",
                    selector=next_selector,
                    note="Clicked Okta Next button",
                )
            )

            time.sleep(1.0)
            password_field = _wait_for_first(driver, OKTA_PASSWORD_SELECTORS)
            if password_field is None:
                raise RuntimeError("Okta login page did not expose a password field after username submission.")
            password_selector = _selector_for_element(driver, password_field)
        else:
            # Single-step flow: password field already visible
            password_field = _wait_for_first(driver, OKTA_PASSWORD_SELECTORS)
            if password_field is None:
                raise RuntimeError("Okta login page did not expose a password field.")
            password_selector = _selector_for_element(driver, password_field)

        # Step 2: Enter password
        password_field.clear()
        ensure_safe_to_type(driver.current_url)
        password_field.send_keys(password)
        events.append("Populated password field.")
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=password_selector,
                value="${PASSWORD}",
                note="Entered Okta password",
            )
        )
        screenshots.append(_capture(driver, "okta_step_02_password"))

        # Step 3: Submit login
        sign_in_button = _wait_for_first(driver, OKTA_SUBMIT_SELECTORS)
        if sign_in_button is None:
            raise RuntimeError("Okta login page did not expose a Sign in button after password entry.")
        submit_selector = _selector_for_element(driver, sign_in_button)
        _safe_click(driver, sign_in_button)
        events.append("Submitted password step.")
        recorded_actions.append(
            RecordedAction(
                action="click",
                selector=submit_selector,
                note="Clicked Okta sign-in button",
            )
        )

        time.sleep(1.5)

        # Wait for post-authentication
        success, error_message = _wait_for_post_auth(driver, timeout_seconds)
        if not success:
            error_capture = _capture(driver, "okta_step_error")
            screenshots.append(error_capture)
            message = error_message or "Credentials rejected or additional verification required."
            events.append(f"Okta sign-in failed: {message}")
            html_failure = driver.page_source or ""
            raise AutomationFailure(
                message=message,
                screenshots=screenshots,
                events=events,
                html=html_failure,
            )

        events.append("Authentication flow completed.")
        post_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "okta_step_03_post"))

        # Extract comprehensive security context (Phase 1: cookies only)
        security_context = extract_security_context(driver, target_url)

        return FormAuthResult(
            final_url=driver.current_url,
            page_title=driver.title or None,
            heading=None,
            success_message=None,
            cookies=driver.get_cookies(),
            security_context=security_context,
            screenshots=screenshots,
            events=events,
            pre_auth_html=pre_auth_html,
            post_auth_html=post_auth_html,
            username_selector=username_selector,
            password_selector=password_selector,
            submit_selector=submit_selector,
            submit_method="click",
            recorded_actions=recorded_actions,
        )
    finally:
        driver.quit()


def _wait_for_document_ready(driver: webdriver.Chrome) -> None:
    """Wait for document ready state."""
    driver.implicitly_wait(0)
    for _ in range(60):
        state = driver.execute_script("return document.readyState")
        if state == "complete":
            return
        time.sleep(0.1)


def _wait_for_okta_widget(driver: webdriver.Chrome, timeout: int = 10) -> None:
    """Wait for Okta Sign-In Widget to load and render."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            # Check for Okta widget container
            script = """
            return (
                document.querySelector('.okta-sign-in') !== null ||
                document.querySelector('[data-se="o-form"]') !== null ||
                document.querySelector('#okta-sign-in') !== null ||
                document.querySelector('input[name="username"]') !== null ||
                document.querySelector('input[name="password"]') !== null
            );
            """
            if driver.execute_script(script):
                return
        except Exception:
            pass
        time.sleep(0.25)
    # Timeout is not fatal - might be a regular form without widget


def _is_password_visible(driver: webdriver.Chrome) -> bool:
    """Check if password field is visible (single-step) or hidden (two-step)."""
    try:
        password_field = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        return password_field.is_displayed()
    except NoSuchElementException:
        return False
    except Exception:
        return False


def _wait_for_post_auth(driver: webdriver.Chrome, timeout_seconds: int) -> tuple[bool, str | None]:
    """
    Wait for post-authentication redirect or detect errors/MFA.

    Returns:
        (success, error_message) tuple
    """
    deadline = time.time() + timeout_seconds
    last_error: str | None = None

    while time.time() < deadline:
        current_url = (driver.current_url or "").lower()

        # Check for error messages
        error_message = _extract_error_message(driver)
        if error_message:
            last_error = error_message
            return False, last_error

        # Check for MFA challenge
        mfa_message = _detect_mfa_challenge(driver)
        if mfa_message:
            return False, f"MFA required: {mfa_message}"

        # Success: redirected away from Okta domain
        if not any(host in current_url for host in OKTA_HOSTS):
            return True, None

        time.sleep(0.5)

    return False, last_error or "Authentication timeout - no redirect detected"


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
    attr_checks: List[Tuple[str, Callable[[str], str]]] = [
        ("id", lambda v: f"css={tag}#{_css_escape(v)}"),
        ("name", lambda v: _attr_selector(tag, "name", v)),
        ("data-test", lambda v: _attr_selector(tag, "data-test", v)),
        ("data-se", lambda v: _attr_selector(tag, "data-se", v)),
        ("aria-label", lambda v: _attr_selector(tag, "aria-label", v)),
        ("placeholder", lambda v: _attr_selector(tag, "placeholder", v)),
    ]

    for attr, builder in attr_checks:
        value = element.get_attribute(attr)
        if value:
            return builder(value)

    class_attr = element.get_attribute("class")
    if class_attr:
        first_class = class_attr.strip().split()[0]
        if first_class:
            return f"css={tag}.{_css_escape(first_class)}"

    css_path = driver.execute_script(
        """
        function cssPath(el) {
            if (!(el instanceof Element)) return null;
            const path = [];
            while (el && el.nodeType === 1) {
                let selector = el.nodeName.toLowerCase();
                if (el.id) {
                    selector += '#' + CSS.escape(el.id);
                    path.unshift(selector);
                    return path.join(' > ');
                }
                const className = el.className && typeof el.className === 'string' ? el.className.trim() : '';
                if (className) {
                    selector += '.' + className.split(/\\s+/).map(CSS.escape).join('.');
                }
                let sibling = el;
                let nth = 1;
                while ((sibling = sibling.previousElementSibling) != null) {
                    if (sibling.nodeName === el.nodeName) nth++;
                }
                if (nth > 1) {
                    selector += `:nth-of-type(${nth})`;
                }
                path.unshift(selector);
                el = el.parentElement;
            }
            return path.join(' > ');
        }
        return cssPath(arguments[0]);
        """,
        element,
    )
    if css_path:
        return f"css={css_path}"

    return None


def _css_escape(value: str) -> str:
    """Escape CSS selector special characters."""
    specials = {":", ".", "#", "[", "]", "(", ")", " ", "'", '"', "/", "\\"}
    escaped = []
    for char in value:
        if char in specials:
            escaped.append(f"\\{char}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _attr_selector(tag: str, attribute: str, value: str) -> str:
    """Build attribute selector."""
    sanitized = value.replace('"', '\\"')
    return f'css={tag}[{attribute}="{sanitized}"]'


def _is_interactable(element: WebElement) -> bool:
    """Check if element is interactable."""
    try:
        return element.is_displayed() and element.is_enabled()
    except StaleElementReferenceException:
        return False


def _extract_error_message(driver: webdriver.Chrome) -> str | None:
    """Extract error message from Okta error containers."""
    for selector in OKTA_ERROR_SELECTORS:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
        except Exception:
            continue
        for element in elements:
            try:
                if not element.is_displayed():
                    continue
                text = (element.text or "").strip()
                if text:
                    return text
            except StaleElementReferenceException:
                continue
    return None


def _detect_mfa_challenge(driver: webdriver.Chrome) -> str | None:
    """Detect MFA/additional verification prompts."""
    # Check MFA-specific selectors
    for selector in OKTA_MFA_SELECTORS:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
        except Exception:
            continue
        for element in elements:
            try:
                if not element.is_displayed():
                    continue
                text = (element.text or "").strip().lower()
                if text and any(keyword in text for keyword in MFA_KEYWORDS):
                    return element.text.strip()
            except StaleElementReferenceException:
                continue

    # Check page body for MFA keywords
    try:
        body_text = (driver.find_element(By.TAG_NAME, "body").text or "").lower()
        for keyword in MFA_KEYWORDS:
            if keyword in body_text:
                return keyword.capitalize()
    except Exception:
        pass

    return None
