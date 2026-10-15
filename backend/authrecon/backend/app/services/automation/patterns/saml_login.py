from __future__ import annotations

from app.services.live_timeline import live_events
import time
import base64
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
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


# Common SAML endpoints and parameters
SAML_PATHS = [
    "/saml/login",
    "/saml/sso",
    "/saml/acs",
    "/saml/consume",
    "/saml2/login",
    "/sso/saml",
    "/auth/saml",
    "/idp/profile/SAML2/Redirect/SSO",
    "/simplesaml/module.php/saml/sp/saml2-acs.php",
]

SAML_FORM_SELECTORS = [
    "form[action*='saml']",
    "form[action*='acs']",
    "form[action*='sso']",
    "form[action*='consume']",
]

SAML_PARAMETERS = [
    "SAMLRequest",
    "SAMLResponse",
    "RelayState",
    "SigAlg",
    "Signature",
]

# Common SAML IdP form selectors
USERNAME_SELECTORS: List[str] = [
    "input[name='username']",
    "input[name='email']",
    "input[name='j_username']",  # Shibboleth
    "input[name='user']",
    "input#username",
    "input#email",
    "input[type='email']",
    "input[type='text'][autocomplete*='username']",
]

PASSWORD_SELECTORS: List[str] = [
    "input[name='password']",
    "input[name='j_password']",  # Shibboleth
    "input#password",
    "input[type='password']",
]

SUBMIT_SELECTORS: List[str] = [
    "button[type='submit']",
    "input[type='submit']",
    "button[name='_eventId_proceed']",  # Shibboleth
    "button.form-button",
    "button#submit",
    "input[name='submit']",
]

ERROR_SELECTORS: List[str] = [
    ".error",
    ".alert-danger",
    ".alert-error",
    "[role='alert']",
    ".form-error",
    "#error",
    "p.form-error",
]


def _wait_for_document_ready(driver: webdriver.Chrome, timeout: int = 10) -> None:
    """Wait for the page to be fully loaded."""
    try:
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
    except TimeoutException:
        pass


def _is_saml_url(url: str) -> bool:
    """Check if URL contains SAML-related paths or parameters."""
    parsed = urlparse(url)

    # Check if path contains SAML indicators
    for path in SAML_PATHS:
        if path.lower() in parsed.path.lower():
            return True

    # Check if query parameters contain SAML indicators
    params = parse_qs(parsed.query)
    for param in SAML_PARAMETERS:
        if param in params:
            return True

    return False


def _has_saml_form(driver: webdriver.Chrome) -> bool:
    """Detect if the current page has a SAML form."""
    try:
        # Check for forms with SAML-related actions
        for selector in SAML_FORM_SELECTORS:
            forms = driver.find_elements(By.CSS_SELECTOR, selector)
            if forms:
                return True

        # Check for hidden SAML parameters in forms
        saml_inputs = driver.find_elements(By.CSS_SELECTOR, "input[name='SAMLRequest'], input[name='SAMLResponse']")
        if saml_inputs:
            return True

        return False
    except Exception:
        return False


def _find_element_by_selectors(driver: webdriver.Chrome, selectors: List[str]) -> Optional[WebElement]:
    """Try to find an element using a list of CSS selectors."""
    for selector in selectors:
        try:
            element = driver.find_element(By.CSS_SELECTOR, selector)
            if element and element.is_displayed():
                return element
        except NoSuchElementException:
            continue
    return None


def _get_selector_for_element(driver: webdriver.Chrome, element: Optional[WebElement]) -> str | None:
    """Generate a CSS selector for the given element."""
    if element is None:
        return None

    # Try ID first
    elem_id = element.get_attribute("id")
    if elem_id:
        return f"css=#{elem_id}"

    # Try name attribute
    elem_name = element.get_attribute("name")
    if elem_name:
        tag = element.tag_name.lower()
        return f"css={tag}[name='{elem_name}']"

    # Fall back to generic selector
    return f"css={element.tag_name.lower()}"


def _check_for_errors(driver: webdriver.Chrome) -> Optional[str]:
    """Check if there are any error messages on the page."""
    for selector in ERROR_SELECTORS:
        try:
            errors = driver.find_elements(By.CSS_SELECTOR, selector)
            for error in errors:
                if error.is_displayed() and error.text.strip():
                    return error.text.strip()
        except Exception:
            continue
    return None


def run_saml_login(
    target_url: str,
    username: str,
    password: str,
    *,
    headless: bool = True,
    timeout_seconds: int = 30,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Attempt SAML 2.0 authentication flow.

    This pattern handles:
    - SAML SP-initiated flows
    - SAML IdP-initiated flows
    - Both POST and Redirect bindings
    - Common IdP implementations (Shibboleth, SimpleSAMLphp, OneLogin, etc.)

    Args:
        target_url: The SAML login URL or SP login page
        username: Username for authentication
        password: Password for authentication
        headless: Run browser in headless mode
        timeout_seconds: Page load timeout
        domain_prefix: Optional domain prefix for username (e.g., "DOMAIN\\username")

    Returns:
        FormAuthResult with authentication details

    Raises:
        ValueError: If username/password not provided
        AutomationFailure: If SAML flow cannot be completed
    """
    if not username:
        raise ValueError("Username must be provided for SAML authentication.")
    if not password:
        raise ValueError("Password must be provided for SAML authentication.")

    options = create_chrome_options(headless=headless)
    driver = create_webdriver(options)

    events: list[str] = live_events()
    screenshots: list[ScreenshotCapture] = []
    recorded_actions: list[RecordedAction] = []

    try:
        driver.set_page_load_timeout(timeout_seconds)
        driver = selenium_get_with_http2_fallback(
            driver, target_url, headless=headless, page_load_timeout=timeout_seconds
        )
        _wait_for_document_ready(driver)
        events.append("Loaded SAML login page.")

        # Check if we're already at a SAML endpoint
        current_url = driver.current_url
        if _is_saml_url(current_url):
            events.append(f"SAML endpoint detected: {urlparse(current_url).path}")

        # Check for SAML forms
        if _has_saml_form(driver):
            events.append("SAML form detected on page (SAMLRequest/SAMLResponse)")

        # Capture pre-auth state
        pre_auth_html = driver.page_source or ""
        screenshots.append(
            ScreenshotCapture(
                file_name="saml_pre_login.png",
                data=driver.get_screenshot_as_png(),
                description="SAML login page before authentication.",
            )
        )

        # Wait for potential SAML redirect to IdP
        time.sleep(2)
        _wait_for_document_ready(driver)

        # Check if we were redirected to IdP
        if driver.current_url != target_url:
            events.append(f"Redirected to IdP: {urlparse(driver.current_url).netloc}")
            screenshots.append(
                ScreenshotCapture(
                    file_name="saml_idp.png",
                    data=driver.get_screenshot_as_png(),
                    description="SAML Identity Provider login page.",
                )
            )

        # Run discovery to find authentication elements
        events.append("Running discovery on IdP login page...")
        discovery_result = discover_auth_elements(driver, driver.current_url)
        events.append(f"Discovery: {discovery_result.recommended_approach} (confidence: {discovery_result.confidence}%)")

        # Locate username field
        username_field = _find_element_by_selectors(driver, USERNAME_SELECTORS)
        if username_field is None:
            raise AutomationFailure(
                "Unable to locate username field on SAML IdP page.",
                screenshots=screenshots,
                events=events,
                html=driver.page_source,
            )

        # Get username variants (support domain prefixes)
        username_variants = get_username_variants(username, domain_prefix)
        username_to_use = username_variants[0]

        if domain_prefix:
            events.append(f"Using username format: {username_to_use} (domain: {domain_prefix})")

        # Enter username
        username_field.clear()
        username_field.send_keys(username_to_use)
        events.append("Entered username.")

        username_selector = _get_selector_for_element(driver, username_field)
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=username_selector,
                value="${USERNAME}",
                note="Entered username on SAML IdP",
            )
        )

        # Locate password field
        password_field = _find_element_by_selectors(driver, PASSWORD_SELECTORS)
        if password_field is None:
            raise AutomationFailure(
                "Unable to locate password field on SAML IdP page.",
                screenshots=screenshots,
                events=events,
                html=driver.page_source,
            )

        # Enter password
        password_field.clear()
        password_field.send_keys(password)
        events.append("Entered password.")

        password_selector = _get_selector_for_element(driver, password_field)
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=password_selector,
                value="${PASSWORD}",
                note="Entered password on SAML IdP",
            )
        )

        # Find and click submit button
        submit_button = _find_element_by_selectors(driver, SUBMIT_SELECTORS)
        if submit_button is None:
            # Try submitting the form directly
            try:
                password_field.submit()
                events.append("Submitted form (no submit button found).")
            except Exception:
                raise AutomationFailure(
                    "Unable to find submit button or submit form.",
                    screenshots=screenshots,
                    events=events,
                    html=driver.page_source,
                )
        else:
            submit_button.click()
            events.append("Clicked submit button.")

            submit_selector = _get_selector_for_element(driver, submit_button)
            recorded_actions.append(
                RecordedAction(
                    action="click",
                    selector=submit_selector,
                    note="Clicked SAML IdP submit button",
                )
            )

        # Wait for SAML assertion and redirect back to SP
        time.sleep(3)
        _wait_for_document_ready(driver)

        # Check for errors
        error_msg = _check_for_errors(driver)
        if error_msg:
            events.append(f"Error detected: {error_msg}")
            screenshots.append(
                ScreenshotCapture(
                    file_name="saml_error.png",
                    data=driver.get_screenshot_as_png(),
                    description="SAML authentication error.",
                )
            )

        # Capture post-auth state
        final_url = driver.current_url
        events.append(f"Final URL: {final_url}")

        if _is_saml_url(final_url):
            events.append("Still on SAML endpoint - may need additional handling.")

        post_auth_html = driver.page_source or ""
        screenshots.append(
            ScreenshotCapture(
                file_name="saml_post_auth.png",
                data=driver.get_screenshot_as_png(),
                description="Page after SAML authentication.",
            )
        )

        # Extract page info
        try:
            page_title = driver.title
        except Exception:
            page_title = None

        # Try to find success indicators
        heading = None
        success_message = None

        try:
            h1_elements = driver.find_elements(By.TAG_NAME, "h1")
            if h1_elements:
                heading = h1_elements[0].text.strip()
        except Exception:
            pass

        # Collect cookies
        cookies = []
        try:
            cookies = driver.get_cookies()
        except Exception:
            cookies = []

        events.append(f"Authentication completed. Cookies: {len(cookies)}")

        # Extract comprehensive security context (Phase 1: cookies only)
        security_context = extract_security_context(driver, target_url)

        return FormAuthResult(
            final_url=final_url,
            page_title=page_title,
            heading=heading,
            success_message=success_message,
            cookies=cookies,
            security_context=security_context,
            screenshots=screenshots,
            events=events,
            pre_auth_html=pre_auth_html,
            post_auth_html=post_auth_html,
            username_selector=username_selector,
            password_selector=password_selector,
            submit_selector=_get_selector_for_element(driver, submit_button) if submit_button else None,
            submit_method="click" if submit_button else "form_submit",
            recorded_actions=recorded_actions,
        )

    except AutomationFailure:
        raise
    except Exception as e:
        screenshots.append(
            ScreenshotCapture(
                file_name="saml_exception.png",
                data=driver.get_screenshot_as_png(),
                description=f"Exception during SAML auth: {str(e)}",
            )
        )
        raise AutomationFailure(
            f"SAML authentication failed: {str(e)}",
            screenshots=screenshots,
            events=events,
            html=driver.page_source,
        )
    finally:
        driver.quit()


def attempt_saml_login(
    target_url: str,
    username: str,
    password: str,
    headless: bool = True,
    timeout_seconds: int = 30,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Convenience wrapper for run_saml_login.

    Matches the interface of other pattern modules.
    """
    return run_saml_login(
        target_url=target_url,
        username=username,
        password=password,
        headless=headless,
        timeout_seconds=timeout_seconds,
        domain_prefix=domain_prefix,
    )
