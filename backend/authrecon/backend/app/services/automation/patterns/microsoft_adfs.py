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


EMAIL_SELECTORS: List[str] = [
    "input[name='loginfmt']",
    "input#i0116",
    "input[type='email']",
    "input#username",
    "input[name='username']",
    "input[aria-labelledby='username_label']",
]

PASSWORD_SELECTORS: List[str] = [
    "input[name='passwd']",
    "input#i0118",
    "input[type='password']",
    "input#password",
    "input[name='password']",
]

STS_USERNAME_SELECTORS: List[str] = [
    "input#userNameInput",
    "input[name='UserName']",
    "input[name='username']",
]

STS_PASSWORD_SELECTORS: List[str] = [
    "input#passwordInput",
    "input[name='PassWord']",
    "input[name='password']",
]

STS_SUBMIT_SELECTORS: List[str] = [
    "button#submitButton",
    "input#submitButton",
    "button[type='submit']",
    "button.btn.btn-lg.btn-default",
    "span#submitButton",
]

SUBMIT_SELECTORS: List[str] = [
    "button#idSIButton9",
    "input#idSIButton9",
    "button[type='submit']",
    "input[type='submit']",
    "button.btn.btn-lg.btn-default",
]

DECLINE_STAY_SIGNED_IN_SELECTORS: List[str] = [
    "button#idBtn_Back",
    "input#idBtn_Back",
    "button[data-report-event='Kmsi_No']",
    "input[data-report-event='Kmsi_No']",
]

LOGIN_HOSTS = (
    "login.microsoftonline.com",
    "login.live.com",
    "account.live.com",
    "login.windows.net",
)

ERROR_SELECTORS: List[str] = [
    "#passwordError",
    "#usernameError",
    "#errorText",
    "div[role='alert']",
    ".alert-error",
    ".text-error",
    "[data-test-id='error']",
    "span[role='alert']",
]

MFA_SELECTORS: List[str] = [
    "#idDiv_SAOTCAS_Description",
    "#idDiv_SAASignInIntro",
    "#idDiv_MSAOTCC_Description",
    ".mfaTitle",
    ".saSignInMessage",
]

MFA_KEYWORDS = [
    "approve sign in request",
    "enter code",
    "verify your identity",
    "we sent a notification",
    "two-step verification",
    "microsoft authenticator",
    "text +",
    "text message",
    "use your security key",
    "try another way to sign in",
]


def run_azure_login(
    target_url: str,
    username: str,
    password: str,
    *,
    headless: bool = True,
    timeout_seconds: int = 45,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
) -> FormAuthResult:
    if not username:
        raise ValueError("Username must be provided for Azure AD automation.")
    if not password:
        raise ValueError("Password must be provided for Azure AD automation.")

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
        events.append("Loaded Azure sign-in portal.")
        screenshots.append(_capture(driver, "azure_step_00_target"))
        _wait_for_login_form(driver)

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
                if _follow_entrypoint(driver, entrypoint, recorded_actions, f"Selected login path: {candidates[0].text}"):
                    events.append(f"Navigated via login entrypoint to {driver.current_url}")
                    _wait_for_document_ready(driver)
                    time.sleep(1)  # Brief pause for any dynamic content
                elif click_entrypoint_safe(entrypoint, driver):
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
                    events.append("Warning: Failed to activate login entrypoint.")
            else:
                events.append(f"Warning: No matching login button found for hint '{login_hint}'")

        _handle_language_selection(driver, events, recorded_actions)
        screenshots.append(_capture(driver, "azure_step_00_entrypoint"))
        events.append(f"Current auth URL: {driver.current_url}")
        pre_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "azure_step_01_pre"))
        if _is_sts_url(driver.current_url):
            return _run_sts_flow(
                driver,
                username=username,
                password=password,
                domain_prefix=domain_prefix,
                events=events,
                screenshots=screenshots,
                recorded_actions=recorded_actions,
            )
        _wait_for_login_form(driver)

        username_field = _wait_for_first(driver, EMAIL_SELECTORS)
        if username_field is None:
            username_field = _fallback_username_field(driver)
        if username_field is None:
            raise RuntimeError("Azure login page did not expose a username field.")
        username_selector = _selector_for_element(driver, username_field)

        # Get username variants (supports DOMAIN\username)
        username_variants = get_username_variants(username, domain_prefix)
        username_to_use = username_variants[0]

        if domain_prefix:
            events.append(f"Using username format: {username_to_use} (domain prefix: {domain_prefix})")

        username_field.clear()
        username_field.send_keys(username_to_use)
        events.append("Populated username field.")
        screenshots.append(_capture(driver, "azure_step_01_username"))
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=username_selector,
                value="${USERNAME}",
                note="Entered Azure username/email",
            )
        )

        continue_button = _wait_for_first(driver, SUBMIT_SELECTORS)
        if continue_button is None:
            raise RuntimeError("Azure login page did not expose a Next button after username entry.")
        continue_selector = _selector_for_element(driver, continue_button)
        _safe_click(driver, continue_button)
        events.append("Submitted username step.")
        recorded_actions.append(
            RecordedAction(
                action="click",
                selector=continue_selector,
                note="Clicked Azure Next/Submit button",
            )
        )

        time.sleep(1.0)
        sts_result = _handoff_to_sts_if_available(
            driver,
            username=username,
            password=password,
            domain_prefix=domain_prefix,
            events=events,
            screenshots=screenshots,
            recorded_actions=recorded_actions,
            pre_auth_html=pre_auth_html,
            reason="Azure entrypoint redirected to STS after username submission; switching automation path.",
        )
        if sts_result:
            return sts_result
        password_field = _wait_for_first(driver, PASSWORD_SELECTORS)
        if password_field is None:
            raise RuntimeError("Azure login page did not expose a password field after username submission.")
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
                note="Entered Azure password",
            )
        )
        screenshots.append(_capture(driver, "azure_step_02_password"))

        sign_in_button = _wait_for_first(driver, SUBMIT_SELECTORS)
        if sign_in_button is None:
            sts_result = _handoff_to_sts_if_available(
                driver,
                username=username,
                password=password,
                domain_prefix=domain_prefix,
                events=events,
                screenshots=screenshots,
                recorded_actions=recorded_actions,
                pre_auth_html=pre_auth_html,
                reason="Azure password step redirected to STS; switching automation path.",
            )
            if sts_result:
                return sts_result
            error_capture = _capture(driver, "azure_step_error_no_submit")
            screenshots.append(error_capture)
            _dump_dom(driver, "azure_no_submit")
            raise RuntimeError("Azure login page did not expose a Sign in button after password entry.")
        submit_selector = _selector_for_element(driver, sign_in_button)
        _safe_click(driver, sign_in_button)
        events.append("Submitted password step.")
        recorded_actions.append(
            RecordedAction(
                action="click",
                selector=submit_selector,
                note="Clicked Azure sign-in button",
            )
        )

        time.sleep(1.0)
        if _dismiss_stay_signed_prompt(driver, events.append, recorded_actions):
            events.append("Declined 'Stay signed in' prompt.")
        
        success, error_message = _wait_for_post_auth(driver, timeout_seconds, events)
        if not success:
            error_capture = _capture(driver, "azure_step_error")
            screenshots.append(error_capture)
            message = error_message or "Credentials rejected or additional verification required."
            events.append(f"Azure sign-in failed: {message}")
            html_failure = driver.page_source or ""
            raise AutomationFailure(
                message=message,
                screenshots=screenshots,
                events=events,
                html=html_failure,
            )

        events.append("Authentication flow completed.")
        if _handle_post_login_consent(
            driver,
            events=events,
            screenshots=screenshots,
            recorded_actions=recorded_actions,
        ):
            events.append("Accepted post-login consent prompt.")

        post_auth_html = driver.page_source or ""
        screenshots.append(_capture(driver, "azure_step_03_post"))

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
    driver.implicitly_wait(0)
    for _ in range(60):
        state = driver.execute_script("return document.readyState")
        if state == "complete":
            return
        time.sleep(0.1)


def _wait_for_post_auth(
    driver: webdriver.Chrome,
    timeout_seconds: int,
    events: List[str],
) -> tuple[bool, str | None]:
    deadline = time.time() + timeout_seconds
    last_error: str | None = None
    challenge_start: float | None = None
    challenge_text: str | None = None
    previous_url: str | None = None

    while time.time() < deadline:
        current_url = (driver.current_url or "").lower()
        if current_url != previous_url:
            events.append(f"Post-auth poll location: {current_url}")
            previous_url = current_url
        on_login_host = any(host in current_url for host in LOGIN_HOSTS)

        if not on_login_host:
            events.append(f"Left Azure login host; now at {current_url}")
            return True, None

        error_message = _extract_error_message(driver)
        if error_message:
            events.append(f"Azure error hint '{error_message}' detected at {current_url}")
            last_error = error_message
            return False, last_error

        challenge_message = _detect_additional_challenge(driver)
        if challenge_message:
            if challenge_start is None:
                challenge_start = time.time()
                challenge_text = challenge_message
                events.append(f"Detected possible MFA challenge '{challenge_message}' at {driver.current_url}")
            elif time.time() - challenge_start > 5:
                events.append("MFA challenge persisted for >5s; aborting Azure automation.")
                return False, challenge_text or challenge_message
        else:
            challenge_start = None
            challenge_text = None

        time.sleep(0.5)

    return False, last_error or challenge_text


def _capture(driver: webdriver.Chrome, label: str) -> ScreenshotCapture:
    filename = f"{label}.png"
    current_url = (driver.current_url or "").strip() or "about:blank"
    description = f"{label.replace('_', ' ').title()} @ {current_url}"
    return ScreenshotCapture(
        file_name=filename,
        data=driver.get_screenshot_as_png(),
        description=description,
    )


def _wait_for_first(driver: webdriver.Chrome, selectors: List[str], timeout: int = 20) -> Optional[WebElement]:
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


def _fallback_username_field(driver: webdriver.Chrome, timeout: int = 15) -> Optional[WebElement]:
    """Fallback lookup for non-Microsoft username fields (e.g., custom ADFS forms)."""
    selectors = [
        "form#loginForm input#username",
        "form#loginForm input[name='username']",
        "form#loginForm input[type='text']",
        "input[aria-labelledby='username_label']",
        "input[title='Username']",
    ]
    deadline = time.time() + timeout
    while time.time() < deadline:
        for selector in selectors:
            try:
                element = driver.find_element(By.CSS_SELECTOR, selector)
                if _is_interactable(element):
                    return element
            except (NoSuchElementException, StaleElementReferenceException):
                continue
        time.sleep(0.2)
    return None


def _wait_for_login_form(driver: webdriver.Chrome, timeout: int = 15) -> None:
    """Wait until the standard login form or custom loginForm is present."""
    deadline = time.time() + timeout
    selectors = [
        "form#loginForm input#username",
        "form#loginForm",
        "input[name='loginfmt']",
        "input#i0116",
        "input[aria-labelledby='username_label']",
    ]
    while time.time() < deadline:
        for selector in selectors:
            try:
                element = driver.find_element(By.CSS_SELECTOR, selector)
                if element:
                    return
            except Exception:
                continue
        time.sleep(0.2)

def _handle_language_selection(
    driver: webdriver.Chrome,
    events: List[str],
    recorded_actions: List[RecordedAction],
) -> None:
    try:
        lang_button = driver.find_element(By.CSS_SELECTOR, "#englishButton, #frenchButton, a[href*='language'], a[href*='locale']")
        if lang_button and _is_interactable(lang_button):
            selector = _selector_for_element(driver, lang_button)
            _safe_click(driver, lang_button)
            events.append("Language selection detected; clicked language button.")
            recorded_actions.append(
                RecordedAction(
                    action="click",
                    selector=selector or "language-button",
                    note="Selected language on ADFS splash page",
                )
            )
            _wait_for_document_ready(driver)
    except NoSuchElementException:
        return
    except Exception:
        return


def _is_sts_url(url: str | None) -> bool:
    if not url:
        return False
    lower = url.lower()
    return "adfs/ls" in lower or "/adfs/" in lower


def _handoff_to_sts_if_available(
    driver: webdriver.Chrome,
    *,
    username: str,
    password: str,
    domain_prefix: str | None,
    events: List[str],
    screenshots: List[ScreenshotCapture],
    recorded_actions: List[RecordedAction],
    pre_auth_html: str,
    reason: str,
) -> FormAuthResult | None:
    """Switch to STS automation if the current page is an ADFS login."""
    if not _is_sts_url(driver.current_url):
        return None
    events.append(reason)
    result = _run_sts_flow(
        driver,
        username=username,
        password=password,
        domain_prefix=domain_prefix,
        events=events,
        screenshots=screenshots,
        recorded_actions=recorded_actions,
    )
    if pre_auth_html and not result.pre_auth_html:
        result.pre_auth_html = pre_auth_html
    return result


def _run_sts_flow(
    driver: webdriver.Chrome,
    *,
    username: str,
    password: str,
    domain_prefix: str | None,
    events: List[str],
    screenshots: List[ScreenshotCapture],
    recorded_actions: List[RecordedAction],
) -> FormAuthResult:
    events.append("Detected STS/ADFS login page; executing STS flow.")
    screenshots.append(_capture(driver, "sts_step_form"))
    username_field = _wait_for_first(driver, STS_USERNAME_SELECTORS, timeout=20)
    if username_field is None:
        raise RuntimeError("STS login page did not expose a username field.")
    username_selector = _selector_for_element(driver, username_field)

    username_variants = get_username_variants(username, domain_prefix)
    username_to_use = username_variants[0]
    username_field.clear()
    username_field.send_keys(username_to_use)
    events.append("STS: populated username field.")
    recorded_actions.append(
        RecordedAction(
            action="type",
            selector=username_selector,
            value="${USERNAME}",
            note="Entered STS username/email",
        )
    )

    password_field = _wait_for_first(driver, STS_PASSWORD_SELECTORS, timeout=20)
    if password_field is None:
        raise RuntimeError("STS login page did not expose a password field.")
    password_selector = _selector_for_element(driver, password_field)
    password_field.clear()
    ensure_safe_to_type(driver.current_url)
    password_field.send_keys(password)
    events.append("STS: populated password field.")
    screenshots.append(_capture(driver, "sts_step_filled"))
    recorded_actions.append(
        RecordedAction(
            action="type",
            selector=password_selector,
            value="${PASSWORD}",
            note="Entered STS password",
        )
    )

    submit_button = _wait_for_first(driver, STS_SUBMIT_SELECTORS, timeout=10)
    if submit_button is None:
        raise RuntimeError("STS login page did not expose a submit button.")
    submit_selector = _selector_for_element(driver, submit_button)
    _safe_click(driver, submit_button)
    events.append("STS: submitted credentials.")
    recorded_actions.append(
        RecordedAction(
            action="click",
            selector=submit_selector,
            note="Clicked STS submit button",
        )
    )

    screenshots.append(_capture(driver, "sts_step_post_submit"))
    _wait_for_document_ready(driver)
    post_auth_html = driver.page_source or ""

    return FormAuthResult(
        final_url=driver.current_url,
        page_title=driver.title or None,
        heading=None,
        success_message=None,
        cookies=driver.get_cookies(),
        screenshots=screenshots,
        events=events,
        pre_auth_html="",
        post_auth_html=post_auth_html,
        username_selector=username_selector,
        password_selector=password_selector,
        submit_selector=submit_selector,
        submit_method="click",
        recorded_actions=recorded_actions,
    )


def _is_sts_url(url: str | None) -> bool:
    if not url:
        return False
    lower = url.lower()
    return "adfs/ls" in lower or "/adfs/" in lower


def _follow_entrypoint(
    driver: webdriver.Chrome,
    element: WebElement,
    recorded_actions: List[RecordedAction],
    note: str,
) -> bool:
    """Follow entrypoint links that wrap buttons (common on Vital Statistics splash page)."""
    href = element.get_attribute("href")
    anchor_selector = None

    if not href:
        try:
            anchor = element.find_element(By.XPATH, "./ancestor::a[1]")
            href = anchor.get_attribute("href")
            if href:
                element = anchor
                anchor_selector = _selector_for_element(driver, element)
        except Exception:
            href = None

    if href:
        driver.get(href)
        recorded_actions.append(
            RecordedAction(
                action="navigate",
                selector=anchor_selector or href,
                note=note,
            )
        )
        return True

    return False


def _safe_click(driver: webdriver.Chrome, element: WebElement) -> None:
    try:
        element.click()
    except Exception:
        driver.execute_script("arguments[0].click();", element)


def _selector_for_element(driver: webdriver.Chrome, element: Optional[WebElement]) -> str | None:
    if element is None:
        return None

    try:
        tag = (element.tag_name or "").lower() or "*"
    except StaleElementReferenceException:
        return None
    attr_checks: List[Tuple[str, Callable[[str], str]]] = [
        ("id", lambda v: f"css={tag}#{_css_escape(v)}"),
        ("name", lambda v: _attr_selector(tag, "name", v)),
        ("data-test", lambda v: _attr_selector(tag, "data-test", v)),
        ("aria-label", lambda v: _attr_selector(tag, "aria-label", v)),
        ("placeholder", lambda v: _attr_selector(tag, "placeholder", v)),
    ]

    for attr, builder in attr_checks:
        try:
            value = element.get_attribute(attr)
        except StaleElementReferenceException:
            return None
        if value:
            return builder(value)

    try:
        class_attr = element.get_attribute("class")
    except StaleElementReferenceException:
        return None
    if class_attr:
        first_class = class_attr.strip().split()[0]
        if first_class:
            return f"css={tag}.{_css_escape(first_class)}"

    try:
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
                    selector += '.' + className.split(/\s+/).map(CSS.escape).join('.');
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
    except StaleElementReferenceException:
        return None
    if css_path:
        return f"css={css_path}"

    return None


def _css_escape(value: str) -> str:
    specials = {":", ".", "#", "[", "]", "(", ")", " ", "'", '"', "/", "\\"}
    escaped = []
    for char in value:
        if char in specials:
            escaped.append(f"\\{char}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _attr_selector(tag: str, attribute: str, value: str) -> str:
    sanitized = value.replace('"', '\\"')
    return f'css={tag}[{attribute}="{sanitized}"]'


def _is_interactable(element: WebElement) -> bool:
    try:
        return element.is_displayed() and element.is_enabled()
    except StaleElementReferenceException:
        return False


def _extract_error_message(driver: webdriver.Chrome) -> str | None:
    for selector in ERROR_SELECTORS:
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


def _detect_additional_challenge(driver: webdriver.Chrome) -> str | None:
    for selector in MFA_SELECTORS:
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

    return None


CONSENT_ACCEPT_SELECTORS: List[str] = [
    "button[data-testid='tou-agree-button']",
    "button#tou-accept",
    "form[action*='agree'] button[type='submit']",
    "form[action*='terms'] button[type='submit']",
    "button[name='button_pressed'][value='agree']",
]


def _handle_post_login_consent(
    driver: webdriver.Chrome,
    *,
    events: List[str],
    screenshots: List[ScreenshotCapture],
    recorded_actions: List[RecordedAction],
) -> bool:
    """Accept post-login consent or terms prompts when present."""
    deadline = time.time() + 10
    acknowledged = False
    while time.time() < deadline:
        accept_button = _find_consent_accept_control(driver)
        if accept_button:
            selector = _selector_for_element(driver, accept_button)
            _safe_click(driver, accept_button)
            recorded_actions.append(
                RecordedAction(
                    action="click",
                    selector=selector or "consent-accept-button",
                    note="Accepted post-login consent prompt",
                )
            )
            time.sleep(0.5)
            acknowledged = True
            _wait_for_document_ready(driver)
            screenshots.append(_capture(driver, "post_login_consent"))
            break
        time.sleep(0.5)
    return acknowledged


def _find_consent_accept_control(driver: webdriver.Chrome) -> Optional[WebElement]:
    for selector in CONSENT_ACCEPT_SELECTORS:
        try:
            element = driver.find_element(By.CSS_SELECTOR, selector)
            if _is_interactable(element):
                return element
        except NoSuchElementException:
            continue

    try:
        element = driver.execute_script(
            """
            const candidates = Array.from(document.querySelectorAll('button, input[type="submit"]'));
            return candidates.find(el => {
                const text = (el.textContent || el.value || '').trim().toLowerCase();
                if (!text) return false;
                return text.includes('agree') || text.includes('accept');
            }) || null;
            """
        )
        if element is not None and _is_interactable(element):
            return element
    except Exception:
        return None

    return None
def _dismiss_stay_signed_prompt(
    driver: webdriver.Chrome,
    record_event: Callable[[str], None],
    recorded_actions: List[RecordedAction],
) -> bool:
    deadline = time.time() + 12
    while time.time() < deadline:
        candidate = _find_stay_signed_decline(driver)
        if candidate is not None:
            selector = _selector_for_element(driver, candidate)
            _safe_click(driver, candidate)
            recorded_actions.append(
                RecordedAction(
                    action="click",
                    selector=selector,
                    note="Declined stay-signed-in prompt",
                )
            )
            return True
        if not _is_stay_signed_prompt(driver):
            return False
        time.sleep(0.5)
    record_event("Stay signed in prompt detected but decline control not found.")
    return False


def _find_stay_signed_decline(driver: webdriver.Chrome) -> Optional[WebElement]:
    for selector in DECLINE_STAY_SIGNED_IN_SELECTORS:
        try:
            element = driver.find_element(By.CSS_SELECTOR, selector)
            if _is_interactable(element):
                return element
        except NoSuchElementException:
            continue

    try:
        element = driver.execute_script(
            """
            const controls = Array.from(document.querySelectorAll('button, input'));
            return controls.find(el => {
                const value = (el.value || '').trim().toLowerCase();
                const text = (el.textContent || '').trim().toLowerCase();
                const report = (el.getAttribute('data-report-event') || '').toLowerCase();
                return report === 'kmsi_no' || value === 'no' || text === 'no';
            }) || null;
            """
        )
        if element is not None and _is_interactable(element):
            return element
    except Exception:
        pass
    return None


def _is_stay_signed_prompt(driver: webdriver.Chrome) -> bool:
    try:
        title = (driver.title or "").strip().lower()
        if "stay signed in" in title:
            return True
    except Exception:
        pass

    try:
        body_text = (driver.find_element(By.TAG_NAME, "body").text or "").lower()
        if "stay signed in" in body_text:
            return True
    except Exception:
        pass

    return False


def _dump_dom(driver: webdriver.Chrome, label: str) -> None:
    try:
        html = driver.page_source
        path = f"/tmp/authrecon_{label}_{int(time.time())}.html"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(html)
    except Exception:
        return
