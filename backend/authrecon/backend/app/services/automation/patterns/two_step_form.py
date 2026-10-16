"""
Two-Step Form Authentication Automation

Handles authentication flows where username/email and password are entered
on separate pages (e.g., Microsoft, Google, Okta-style flows).

Flow:
1. Load initial page → Enter email/username → Submit
2. Page transition or form change → Enter password → Submit
3. Verify authentication success
"""
from __future__ import annotations

from app.services.live_timeline import live_events
import time
from typing import Optional, List

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from ..browser import create_chrome_options, create_webdriver
from ..navigation import selenium_get_with_http2_fallback
from ..security_context_extractor import extract_security_context
from ..types import ScreenshotCapture, RecordedAction, FormAuthResult, AutomationFailure, CredentialRejected
from ..username_utils import get_username_variants
from ..pre_run_discovery import discover_auth_elements
from .form_login import _extract_feedback_message, _extract_heading
from app.services.automation.typing_guard import ensure_safe_to_type


def _find_input_by_type(driver: webdriver.Chrome, input_type: str, keywords: list[str]) -> Optional[webdriver.remote.webelement.WebElement]:
    """Find an input field by type and associated keywords in attributes."""
    # Try by type attribute first
    try:
        inputs = driver.find_elements(By.CSS_SELECTOR, f'input[type="{input_type}"]')
        if len(inputs) == 1:
            return inputs[0]
        # Multiple matches, try to narrow by keywords
        for inp in inputs:
            for attr in ["name", "id", "placeholder", "aria-label", "autocomplete"]:
                value = inp.get_attribute(attr) or ""
                if any(kw.lower() in value.lower() for kw in keywords):
                    return inp
        # Return first match if no keyword match
        if inputs:
            return inputs[0]
    except NoSuchElementException:
        pass

    # Fallback: search by keywords in common attributes
    for kw in keywords:
        try:
            xpath = f"//input[contains(translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{kw.lower()}') or contains(translate(@id, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{kw.lower()}') or contains(translate(@placeholder, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{kw.lower()}')]"
            inp = driver.find_element(By.XPATH, xpath)
            if inp:
                return inp
        except NoSuchElementException:
            continue

    return None


def _find_submit_button(driver: webdriver.Chrome, keywords: list[str] = None) -> Optional[webdriver.remote.webelement.WebElement]:
    """Find submit button by type, text, or keywords."""
    keywords = keywords or ["submit", "next", "continue", "sign in", "login", "go"]

    # Try submit/button inputs first
    try:
        buttons = driver.find_elements(By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"], button:not([type="button"])')
        if len(buttons) == 1:
            return buttons[0]
        # Multiple matches, try to match by text/keywords
        for btn in buttons:
            text = (btn.text or "").lower()
            value = (btn.get_attribute("value") or "").lower()
            if any(kw.lower() in text or kw.lower() in value for kw in keywords):
                return btn
        # Return first match if no keyword match
        if buttons:
            return buttons[0]
    except NoSuchElementException:
        pass

    # Fallback: generic button search
    try:
        xpath = "//button | //input[@type='submit']"
        btn = driver.find_element(By.XPATH, xpath)
        return btn
    except NoSuchElementException:
        pass

    return None


def run_two_step_form_login(
    start_url: str,
    username: str,
    password: str,
    *,
    headless: bool = True,
    timeout_seconds: int = 30,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    """
    Execute a two-step form-based authentication flow.

    Args:
        start_url: The initial authentication URL
        username: Username or email to submit in step 1
        password: Password to submit in step 2
        headless: Run browser in headless mode
        timeout_seconds: Maximum time to wait for each step

    Returns:
        FormAuthResult with screenshots, cookies, and recorded actions
    """
    options = create_chrome_options(headless=headless)
    driver = None

    screenshots: List[ScreenshotCapture] = []
    recorded_actions: List[RecordedAction] = []
    events: List[str] = live_events()

    try:
        driver = create_webdriver(options)

        # === STEP 1: Load initial page and enter username ===
        events.append("Loading initial authentication page")
        driver = selenium_get_with_http2_fallback(driver, start_url, headless=headless)
        wait = WebDriverWait(driver, timeout_seconds)
        time.sleep(1.5)

        # === PRE-RUN DISCOVERY: Aggressively scan for auth elements ===
        events.append("Running pre-run discovery to map all authentication elements...")
        discovery_result = discover_auth_elements(driver, start_url)
        for selector in discovery_result.reveal_selectors:
            recorded_actions.append(RecordedAction(action="click", selector=selector, note="Reveal login form"))

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
                    recorded_actions.append(RecordedAction(
                        action="click",
                        selector=f"// Login entrypoint: {candidates[0].text}",
                        note=f"Selected login path: {candidates[0].text}",
                    ))
                    time.sleep(1.5)  # Brief pause for any dynamic content
                else:
                    events.append("Warning: Failed to click login entrypoint.")
            else:
                events.append(f"Warning: No matching login button found for hint '{login_hint}'")

        # Screenshot 1: Initial page load
        screenshots.append(ScreenshotCapture(
            file_name="01_initial_page.png",
            data=driver.get_screenshot_as_png(),
            description="Initial page on arrival",
        ))
        pre_auth_html = driver.page_source
        step1_url = driver.current_url

        recorded_actions.append(RecordedAction(
            action="open",
            selector=start_url,
            note="Navigate to two-step login page",
        ))

        # Find username/email field
        events.append("Locating username/email field")
        username_field = _find_input_by_type(driver, "text", ["email", "username", "user", "login"])
        if not username_field:
            username_field = _find_input_by_type(driver, "email", ["email", "username"])

        if not username_field:
            raise AutomationFailure(
                "Could not locate username/email input field on initial page",
                screenshots=screenshots,
                events=events,
                html=pre_auth_html,
            )

        # Screenshot 2: Username field found (before typing)
        screenshots.append(ScreenshotCapture(
            file_name="02_username_field_ready.png",
            data=driver.get_screenshot_as_png(),
            description="Username/email field located and ready for input",
        ))

        # Get username variants (supports DOMAIN\username)
        username_variants = get_username_variants(username, domain_prefix)
        username_to_use = username_variants[0]

        if domain_prefix:
            events.append(f"Using username format: {username_to_use} (domain prefix: {domain_prefix})")

        # Enter username
        events.append(f"Entering username: {username_to_use}")
        username_field.clear()
        username_field.send_keys(username_to_use)
        time.sleep(0.5)

        # Screenshot 3: Username entered
        screenshots.append(ScreenshotCapture(
            file_name="03_username_entered.png",
            data=driver.get_screenshot_as_png(),
            description="Username/email entered in field",
        ))

        username_selector = f"css=[name='{username_field.get_attribute('name')}']" if username_field.get_attribute('name') else "css=input[type='text']"
        recorded_actions.append(RecordedAction(
            action="type",
            selector=username_selector,
            value="${USERNAME}",
            note="Enter username/email",
        ))

        # Find and click submit button for step 1
        events.append("Submitting username")
        submit_btn = _find_submit_button(driver, ["next", "continue", "submit"])
        if not submit_btn:
            raise AutomationFailure(
                "Could not locate submit button for username step",
                screenshots=screenshots,
                events=events,
                html=driver.page_source,
            )

        recorded_actions.append(RecordedAction(
            action="click",
            selector="css=[type='submit']",
            note="Submit username",
        ))
        submit_btn.click()
        time.sleep(2)

        # === STEP 2: Enter password ===
        events.append("Waiting for password field to appear")
        password_field = None
        for attempt in range(5):
            password_field = _find_input_by_type(driver, "password", ["password", "pass", "pwd"])
            if password_field:
                break
            time.sleep(0.5)

        if not password_field:
            raise AutomationFailure(
                "Could not locate password input field after submitting username",
                screenshots=screenshots,
                events=events,
                html=driver.page_source,
            )

        step2_url = driver.current_url
        if step2_url != step1_url:
            events.append(f"Page transitioned to password step: {step2_url}")

        # Screenshot 4: Password page loaded
        screenshots.append(ScreenshotCapture(
            file_name="04_password_page.png",
            data=driver.get_screenshot_as_png(),
            description="Password page after username submission",
        ))

        # Enter password
        events.append("Entering password")
        password_field.clear()
        ensure_safe_to_type(driver.current_url)
        password_field.send_keys(password)
        time.sleep(0.5)

        # Screenshot 5: Password entered
        screenshots.append(ScreenshotCapture(
            file_name="05_password_entered.png",
            data=driver.get_screenshot_as_png(),
            description="Password entered in field (masked)",
        ))

        pwd_selector = f"css=[name='{password_field.get_attribute('name')}']" if password_field.get_attribute('name') else "css=input[type='password']"
        recorded_actions.append(RecordedAction(
            action="type",
            selector=pwd_selector,
            value="${PASSWORD}",
            note="Enter password",
        ))

        # Find and click final submit button
        events.append("Submitting password")
        final_submit = _find_submit_button(driver, ["sign in", "login", "submit", "continue"])
        if not final_submit:
            # Try submitting via Enter key
            password_field.send_keys(Keys.RETURN)
            recorded_actions.append(RecordedAction(
                action="send_keys",
                selector=pwd_selector,
                value="${KEY_ENTER}",
                note="Submit password via Enter",
            ))
        else:
            final_submit.click()
            recorded_actions.append(RecordedAction(
                action="click",
                selector="css=[type='submit']",
                note="Submit password",
            ))

        time.sleep(2)

        # === STEP 3: Verify success ===
        events.append("Verifying authentication success")
        final_url = driver.current_url
        post_auth_html = driver.page_source

        # Screenshot 6: Final authenticated page
        screenshots.append(ScreenshotCapture(
            file_name="06_authenticated.png",
            data=driver.get_screenshot_as_png(),
            description="Final page after successful authentication",
        ))

        # Collect cookies
        cookies = driver.get_cookies()

        # Check for success/failure indicators
        # Visible text only: raw HTML almost always contains words like
        # "error" in CSS/JS, which made successful logins look failed.
        try:
            page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        except Exception:
            page_text = ""
        auth_success_indicators = ["dashboard", "welcome", "logout", "sign out", "profile", "account"]
        auth_failure_indicators = ["incorrect", "invalid", "failed", "error", "try again"]

        has_success = any(indicator in page_text for indicator in auth_success_indicators)
        has_failure = any(indicator in page_text for indicator in auth_failure_indicators)

        # Real text from the landed page: it becomes the scanner's
        # "pattern to verify", so it must actually be on that page.
        success_message = None
        heading = _extract_heading(driver)
        page_title = driver.title if driver.title else None

        if has_failure:
            events.append("Authentication failed: Error indicators detected")
            raise CredentialRejected(
                "Authentication failed: Invalid credentials or authentication error detected",
                screenshots=screenshots,
                events=events,
                html=post_auth_html,
            )
        elif final_url != step2_url or has_success:
            events.append("Authentication succeeded: Redirect or success indicators detected")
            success_message = _extract_feedback_message(driver)
        else:
            events.append("Warning: Could not definitively verify authentication success")

        # Extract comprehensive security context (Phase 1: cookies only)
        security_context = extract_security_context(driver, final_url)

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
            password_selector=pwd_selector,
            submit_selector="css=[type='submit']",
            submit_method="click",
            recorded_actions=recorded_actions,
        )

    except AutomationFailure:
        raise
    except Exception as exc:
        raise AutomationFailure(
            f"Two-step form automation error: {str(exc)}",
            screenshots=screenshots,
            events=events,
            html=driver.page_source if driver else "",
        )
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
