"""
LDAP/ADFS Authentication Automation Module

Handles authentication flows for:
- Active Directory Federation Services (ADFS)
- LDAP-backed login pages
- Domain\\Username format authentication
- STS (Security Token Service) redirects
- Windows Integrated Auth detection

Common in:
- Government portals (e.g., sso.example.gov)
- Enterprise intranets
- On-premise Active Directory environments
"""
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
from ..security_context_extractor import extract_security_context
from ..username_utils import get_username_variants
from ..security_context_extractor import extract_security_context
from ..pre_run_discovery import discover_auth_elements
from ..security_context_extractor import extract_security_context
from app.services.automation.typing_guard import ensure_safe_to_type


# LDAP/ADFS username field selectors
LDAP_USERNAME_SELECTORS: List[str] = [
    "input[name='UserName']",
    "input[name='username']",
    "input[name='UserId']",
    "input[id*='Username']",
    "input[id*='UserName']",
    "input[id*='userId']",
    "input[placeholder*='domain']",
    "input[placeholder*='Username']",
    "input[type='text']",
]

# LDAP/ADFS password field selectors
LDAP_PASSWORD_SELECTORS: List[str] = [
    "input[name='Password']",
    "input[name='password']",
    "input[name='Passwd']",
    "input[id*='Password']",
    "input[id*='password']",
    "input[type='password']",
]

# LDAP/ADFS submit button selectors
LDAP_SUBMIT_SELECTORS: List[str] = [
    "input[type='submit']",
    "button[type='submit']",
    "input[value*='Sign']",
    "input[value*='Login']",
    "button[name='submit']",
    "span[id*='submitButton']",
    ".submit-button",
]

# LDAP/ADFS error selectors
LDAP_ERROR_SELECTORS: List[str] = [
    "#errorText",
    ".error",
    ".error-message",
    "[id*='Error']",
    "[class*='error']",
    "span[id*='ErrorMessage']",
    "div[role='alert']",
]

# ADFS/STS host patterns
ADFS_HOSTS = (
    "adfs",
    "sts",
    "federation",
    "sso",
)


def run_ldap_login(
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
    Automated LDAP/ADFS Login.

    Supports:
    - ADFS login pages
    - LDAP-backed authentication
    - DOMAIN\\username format
    - STS redirect chains
    - Windows Integrated Auth detection

    Args:
        target_url: URL to authenticate against
        username: Username for authentication
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
        raise ValueError("Username must be provided for LDAP/ADFS automation.")
    if not password:
        raise ValueError("Password must be provided for LDAP/ADFS automation.")

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
        events.append("Loaded LDAP/ADFS sign-in page.")

        # Wait for ADFS/LDAP page to render
        time.sleep(2)
        events.append("ADFS/LDAP page detected and ready.")

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
                    time.sleep(1)
                else:
                    events.append("Warning: Failed to click login entrypoint.")
            else:
                events.append(f"Warning: No matching login button found for hint '{login_hint}'")

        pre_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "ldap_step_01_pre"))

        # Step 1: Enter username (with domain prefix if provided)
        username_field = _wait_for_first(driver, LDAP_USERNAME_SELECTORS)
        if username_field is None:
            raise RuntimeError("LDAP/ADFS login page did not expose a username field.")
        username_selector = _selector_for_element(driver, username_field)

        # Get username variants (supports DOMAIN\username)
        username_variants = get_username_variants(username, domain_prefix)
        username_to_use = username_variants[0]

        if domain_prefix:
            events.append(f"Using LDAP username format: {username_to_use} (domain prefix: {domain_prefix})")

        username_field.clear()
        username_field.send_keys(username_to_use)
        events.append("Populated username field.")
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=username_selector,
                value="${USERNAME}",
                note="Entered LDAP/ADFS username",
            )
        )

        # Step 2: Enter password
        password_field = _wait_for_first(driver, LDAP_PASSWORD_SELECTORS)
        if password_field is None:
            raise RuntimeError("LDAP/ADFS login page did not expose a password field.")
        password_selector = _selector_for_element(driver, password_field)

        password_field.clear()
        ensure_safe_to_type(driver.current_url)
        password_field.send_keys(password)
        events.append("Populated password field.")
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=password_selector,
                value="${PASSWORD}",
                note="Entered LDAP/ADFS password",
            )
        )
        screenshots.append(_capture(driver, "ldap_step_02_password"))

        # Step 3: Submit login
        sign_in_button = _wait_for_first(driver, LDAP_SUBMIT_SELECTORS)
        if sign_in_button is None:
            raise RuntimeError("LDAP/ADFS login page did not expose a submit button.")
        submit_selector = _selector_for_element(driver, sign_in_button)
        _safe_click(driver, sign_in_button)
        events.append("Submitted credentials.")
        recorded_actions.append(
            RecordedAction(
                action="click",
                selector=submit_selector,
                note="Clicked LDAP/ADFS sign-in button",
            )
        )

        time.sleep(2)

        # Wait for post-authentication (handle STS redirects)
        success, error_message = _wait_for_post_auth(driver, timeout_seconds, target_url)
        if not success:
            error_capture = _capture(driver, "ldap_step_error")
            screenshots.append(error_capture)
            message = error_message or "Credentials rejected or additional verification required."
            events.append(f"LDAP/ADFS sign-in failed: {message}")
            html_failure = driver.page_source or ""
            raise AutomationFailure(
                message=message,
                screenshots=screenshots,
                events=events,
                html=html_failure,
            )

        events.append("Authentication flow completed.")
        post_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "ldap_step_03_post"))

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


def _wait_for_post_auth(driver: webdriver.Chrome, timeout_seconds: int, original_url: str) -> tuple[bool, str | None]:
    """
    Wait for post-authentication redirect or detect errors.

    LDAP/ADFS often has STS redirect chains, so we check:
    - URL changed from original
    - No error messages
    - Redirected away from ADFS/STS domain

    Returns:
        (success, error_message) tuple
    """
    deadline = time.time() + timeout_seconds
    last_error: str | None = None

    # Parse original URL to detect ADFS/STS domains
    from urllib.parse import urlparse
    original_parsed = urlparse(original_url)
    original_host = original_parsed.hostname or ""

    while time.time() < deadline:
        current_url = (driver.current_url or "").lower()
        current_parsed = urlparse(driver.current_url or "")
        current_host = current_parsed.hostname or ""

        # Check for error messages
        error_message = _extract_error_message(driver)
        if error_message:
            last_error = error_message
            return False, last_error

        # Success indicators:
        # 1. Redirected away from ADFS/STS domain
        is_still_on_adfs = any(host in current_host for host in ADFS_HOSTS)
        is_back_to_original = current_host == original_host and current_url != original_url.lower()

        if not is_still_on_adfs or is_back_to_original:
            # Additional check: make sure we're not on an error page
            if not _is_login_page(driver):
                return True, None

        time.sleep(0.5)

    return False, last_error or "Authentication timeout - no redirect detected"


def _is_login_page(driver: webdriver.Chrome) -> bool:
    """Check if current page is still a login page (has password field)."""
    try:
        password_fields = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
        return len(password_fields) > 0
    except Exception:
        return False


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
    """Extract error message from LDAP/ADFS error containers."""
    for selector in LDAP_ERROR_SELECTORS:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
        except Exception:
            continue
        for element in elements:
            try:
                if not element.is_displayed():
                    continue
                text = (element.text or "").strip()
                if text and len(text) > 5:  # Ignore very short text
                    return text
            except StaleElementReferenceException:
                continue
    return None
