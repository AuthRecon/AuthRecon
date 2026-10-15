from __future__ import annotations

from app.services.live_timeline import live_events
import re
import time
from typing import Callable, Optional, List

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement

from ..browser import create_chrome_options, create_webdriver
from ..navigation import selenium_get_with_http2_fallback
from ..selectors import plain_css
from ..types import ScreenshotCapture, RecordedAction, FormAuthResult, CredentialRejected
from ..username_utils import get_username_variants
from ..pre_run_discovery import discover_auth_elements
from ..pre_run_discovery_click_reveal import _click_reveal_elements
from ..security_context_extractor import extract_security_context

# Auth-related keywords (multi-lingual) to improve field detection without manual hints
AUTH_KEYWORDS = [
    "user", "username", "email", "login", "account", "identifier", "domain", "tenant",
    "connexion", "usuario", "correo", "acceso", "anmelden", "konto",
    "benutzer", "identifiant", "iniciar", "accedi", "benutzername",
    "accès", "connexion", "accesso", "entrar"
]


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


def _selector_for_element(driver: webdriver.Chrome, element: Optional[WebElement]) -> str | None:
    if element is None:
        return None

    tag = (element.tag_name or "").lower() or "*"
    attr_checks: list[tuple[str, Callable[[str], str]]] = [
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


def run_form_login(
    target_url: str,
    username: str,
    password: str,
    *,
    headless: bool = True,
    timeout_seconds: int = 30,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    playbook_selectors: dict | None = None,  # Phase 4: Deterministic execution
) -> FormAuthResult:
    if not username:
        raise ValueError("Username must be provided for form auth automation.")
    if not password:
        raise ValueError("Password must be provided for form auth automation.")

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
        events.append("Loaded login page.")

        # === PHASE 4: Check for playbook selectors (deterministic execution) ===
        if playbook_selectors and not playbook_selectors.get("is_generic"):
            # Use proven selectors from historical learning
            events.append("Using playbook selectors (deterministic execution)...")
            events.append(f"  Playbook confidence: Historical pattern learned from previous success")
            discovery_result = None  # Skip discovery
        else:
            # === PRE-RUN DISCOVERY: Aggressively scan for auth elements ===
            if playbook_selectors and playbook_selectors.get("is_generic"):
                events.append("Playbook selectors are generic fallbacks, running discovery...")
            else:
                events.append("Running pre-run discovery to map all authentication elements...")
            discovery_result = discover_auth_elements(driver, target_url)
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
        screenshots.append(
            ScreenshotCapture(
                file_name="pre_login.png",
                data=driver.get_screenshot_as_png(),
                description="Login form before credentials were submitted.",
            )
        )

        _handle_pre_login_prompts(driver, events.append, recorded_actions)
        # Click common reveal/login toggles before scanning for fields
        _record_reveal(_click_reveal_elements(driver), recorded_actions)

        domain_options = _find_domain_options(driver)
        if domain_options:
            events.append(f"Detected domain/tenant selector with options: {', '.join(domain_options[:3])}")

        # === FIELD SELECTION: Playbook selectors (deterministic) vs Discovery (heuristic) ===
        username_field = None
        password_field = None

        # Phase 4: Use playbook selectors if provided (deterministic execution)
        if playbook_selectors and not playbook_selectors.get("is_generic"):
            events.append("Attempting to locate fields using playbook selectors...")
            try:
                username_selector = plain_css(playbook_selectors.get("username_selector"))
                password_selector = plain_css(playbook_selectors.get("password_selector"))

                if username_selector:
                    username_field = driver.find_element(By.CSS_SELECTOR, username_selector)
                    events.append(f"Found username field using playbook selector: {username_selector}")

                if password_selector:
                    password_field = driver.find_element(By.CSS_SELECTOR, password_selector)
                    events.append(f"Found password field using playbook selector: {password_selector}")
            except Exception as e:
                events.append(f"Warning: Playbook selectors failed ({e}), falling back to heuristic detection")
                # Fall through to discovery/heuristic methods below

        # Try to use discovered form fields first (if we found high-confidence forms)
        # (skipped when the playbook already found both fields)
        high_conf_forms = (
            [f for f in discovery_result.forms if f.confidence_score >= 70]
            if discovery_result and not (username_field and password_field)
            else []
        )
        if high_conf_forms:
            best_form = max(high_conf_forms, key=lambda f: f.confidence_score)
            events.append(f"Using high-confidence form (score: {best_form.confidence_score})")
            try:
                # Use the discovered fields if they're still valid
                if best_form.username_field and best_form.username_field.is_displayed():
                    username_field = best_form.username_field
                    events.append("Using pre-discovered username field")
                if best_form.password_field and best_form.password_field.is_displayed():
                    password_field = best_form.password_field
                    events.append("Using pre-discovered password field")
            except Exception:
                # Fields became stale, fall back to manual search
                events.append("Pre-discovered fields became stale, falling back to manual search")
                pass

        # Fallback to traditional field location if discovery didn't find fields
        if username_field is None:
            username_field = _locate_username_field(driver)
            if username_field is None:
                _record_reveal(_click_reveal_elements(driver), recorded_actions)
                _wait_for_document_ready(driver)
                time.sleep(0.5)
                username_field = _locate_username_field(driver)
            if username_field is None:
                raise RuntimeError("Unable to locate a username/email field on the login page.")

        # Get username variants to try (supports DOMAIN\username format)
        username_variants = get_username_variants(username, domain_prefix)
        for opt in domain_options:
            opt_clean = opt.replace("@", "").strip()
            if not opt_clean:
                continue
            username_variants.append(f"{opt_clean}\\{username}")
            username_variants.append(f"{username}@{opt_clean}")
        # De-duplicate while preserving order
        seen = set()
        username_variants = [u for u in username_variants if not (u in seen or seen.add(u))]
        username_to_use = username_variants[0]  # Use first variant (most likely format)

        if domain_prefix:
            events.append(f"Using username format: {username_to_use} (domain prefix: {domain_prefix})")

        _clear_and_type(username_field, username_to_use)
        events.append("Populated username field.")
        username_selector = _selector_for_element(driver, username_field)
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=username_selector,
                value="${USERNAME}",
                note="Entered username",
            )
        )

        # Use discovered password field if not already set
        if password_field is None:
            password_field = _locate_password_field(driver)
            if password_field is None:
                _record_reveal(_click_reveal_elements(driver), recorded_actions)
                time.sleep(0.5)
                password_field = _locate_password_field(driver)
            if password_field is None:
                raise RuntimeError("Unable to locate a password field on the login page.")
        _clear_and_type(password_field, password)
        events.append("Populated password field.")
        password_selector = _selector_for_element(driver, password_field)
        recorded_actions.append(
            RecordedAction(
                action="type",
                selector=password_selector,
                value="${PASSWORD}",
                note="Entered password",
            )
        )

        # Toggle required/supportive checkboxes (e.g., consent, remember me) before submitting
        _toggle_supporting_checkboxes(driver, events.append, recorded_actions)

        # Phase 4: Try playbook submit selector first (deterministic execution)
        submit_action = None
        if playbook_selectors and not playbook_selectors.get("is_generic"):
            submit_selector = plain_css(playbook_selectors.get("submit_selector"))
            if submit_selector:
                try:
                    submit_button = driver.find_element(By.CSS_SELECTOR, submit_selector)
                    submit_button.click()
                    events.append(f"Clicked submit button using playbook selector: {submit_selector}")
                    submit_action = ("click", submit_selector)
                except Exception as e:
                    events.append(f"Warning: Playbook submit selector failed ({e}), falling back to heuristic detection")

        # Fall back to heuristic submit detection if playbook didn't work
        if submit_action is None:
            submit_action = _submit_login(driver, password_field, events.append)
        if submit_action is None:
            raise RuntimeError("Unable to find a submit button or form to submit credentials.")
        submit_method, submit_selector = submit_action
        if submit_method == "click":
            recorded_actions.append(
                RecordedAction(
                    action="click",
                    selector=submit_selector,
                    note="Clicked submit/login control",
                )
            )
        elif submit_method == "enter_key":
            recorded_actions.append(
                RecordedAction(
                    action="send_keys",
                    selector=password_selector,
                    value="${KEY_ENTER}",
                    note="Submitted credentials via Enter key",
                )
            )
        else:
            recorded_actions.append(
                RecordedAction(
                    action="submit_form",
                    selector=password_selector,
                    note="Submitted enclosing form",
                )
            )

        _wait_for_login_completion(driver, timeout_seconds=timeout_seconds)
        events.append("Authentication flow completed.")

        _ensure_no_error_feedback(driver)

        heading = _extract_heading(driver)
        success_message = _extract_feedback_message(driver)
        post_auth_html = driver.page_source or ""
        screenshots.append(
            ScreenshotCapture(
                file_name="post_login.png",
                data=driver.get_screenshot_as_png(),
                description="Landing page after successful authentication.",
            )
        )

        # Extract comprehensive security context (Phase 1: cookies only)
        security_context = extract_security_context(driver, target_url)

        return FormAuthResult(
            final_url=driver.current_url,
            page_title=driver.title or None,
            heading=heading,
            success_message=success_message,
            cookies=driver.get_cookies(),
            security_context=security_context,  # New comprehensive extraction
            screenshots=screenshots,
            events=events,
            pre_auth_html=pre_auth_html,
            post_auth_html=post_auth_html,
            username_selector=username_selector,
            password_selector=password_selector,
            submit_selector=submit_selector,
            submit_method=submit_method,
            recorded_actions=recorded_actions,
        )
    finally:
        driver.quit()


def _wait_for_document_ready(driver: webdriver.Chrome) -> None:
    driver.implicitly_wait(0)
    for _ in range(30):
        state = driver.execute_script("return document.readyState")
        if state == "complete":
            return
        time.sleep(0.1)


PROMPT_KEYWORDS = [
    "english",
    "français",
    "french",
    "lang",
    "continue",
    "accept",
    "agree",
    "confirm",
    "proceed",
    "next",
]


def _handle_pre_login_prompts(
    driver: webdriver.Chrome,
    record_event: Callable[[str], None],
    recorded_actions: List[RecordedAction],
) -> None:
    """Click language pickers, disclaimers, or splash buttons before form fields."""

    language_clicked = False  # Track if we already clicked a language button

    # Common login form button IDs/names to skip (these are NOT pre-login prompts)
    LOGIN_FORM_BUTTON_IDS = ["login-button", "submit", "signin", "login", "next-button", "continue-button"]

    for attempt in range(3):
        candidate = _find_prompt_button(driver, language_clicked)
        if not candidate:
            record_event(f"Pre-login prompt handling complete (attempt {attempt + 1}, no more prompts found)")
            return

        # Get button details for logging
        button_id = (candidate.get_attribute("id") or "").lower()
        button_name = (candidate.get_attribute("name") or "").lower()
        label_parts = [
            (candidate.text or "").strip(),
            (candidate.get_attribute("value") or "").strip(),
            (candidate.get_attribute("aria-label") or "").strip(),
        ]
        label = " ".join(part for part in label_parts if part).lower()
        is_language_button = any(kw in label for kw in ["english", "français", "french", "lang"])

        # Skip if this is a login form submit button
        if any(form_id in button_id for form_id in LOGIN_FORM_BUTTON_IDS):
            record_event(f"Skipping login form button: ID='{button_id}', stopping pre-login prompt handling")
            return

        if any(form_id in button_name for form_id in LOGIN_FORM_BUTTON_IDS):
            record_event(f"Skipping login form button: name='{button_name}', stopping pre-login prompt handling")
            return

        # Log what we're clicking
        record_event(f"Found prompt button (attempt {attempt + 1}): ID='{button_id}', text='{label[:50]}', is_language={is_language_button}")

        selector = _selector_for_element(driver, candidate)
        try:
            candidate.click()
        except Exception:
            driver.execute_script("arguments[0].click();", candidate)
        record_event("Dismissed pre-login prompt.")

        if is_language_button:
            language_clicked = True
            record_event("Marked language_clicked = True, will skip additional language buttons")

        recorded_actions.append(
            RecordedAction(
                action="click",
                selector=selector,
                note="Acknowledged pre-login prompt",
            )
        )
        time.sleep(1.0)

        # After clicking a language button, stop immediately (login form is next)
        if is_language_button:
            record_event("Clicked language button, stopping pre-login prompt handling (login form should be next)")
            return


def _find_prompt_button(driver: webdriver.Chrome, language_clicked: bool = False):
    # Elements to skip - these are navigation/header elements, not prompts
    SKIP_IDS = [
        "languageToggleLink",
        "languageToggle",
        "language-toggle",
        "language_toggle",
    ]

    SKIP_CLASSES = [
        "language-selector",
        "lang-switch",
        "header-lang",
        "nav-lang",
    ]

    skipped_elements = []  # Track what we skip for debugging

    candidates = driver.find_elements(
        By.CSS_SELECTOR,
        "button, a[role='button'], a.btn, a[class*='btn'], input[type='button'], input[type='submit']",
    )
    for element in candidates:
        try:
            if not _is_interactable(element):
                continue

            # Skip navigation/header elements
            element_id = (element.get_attribute("id") or "").lower()
            element_class = (element.get_attribute("class") or "").lower()

            # Skip if ID matches excluded elements
            if any(skip_id.lower() in element_id for skip_id in SKIP_IDS):
                skipped_elements.append(f"ID:{element_id}")
                continue

            # Skip if class matches excluded elements
            if any(skip_class in element_class for skip_class in SKIP_CLASSES):
                skipped_elements.append(f"class:{element_class}")
                continue

            label_parts = [
                (element.text or "").strip(),
                (element.get_attribute("value") or "").strip(),
                (element.get_attribute("aria-label") or "").strip(),
                (element.get_attribute("data-testid") or "").strip(),
            ]
            label = " ".join(part for part in label_parts if part).lower()
            if any(keyword in label for keyword in PROMPT_KEYWORDS):
                # Check if this is a language button
                is_language_button = any(kw in label for kw in ["english", "français", "french", "lang"])

                # Skip if we already clicked a language button
                if is_language_button and language_clicked:
                    skipped_elements.append(f"lang_already_clicked:{label[:30]}")
                    continue

                return element
        except StaleElementReferenceException:
            continue
    return None


def _find_domain_options(driver: webdriver.Chrome) -> List[str]:
    """Discover domain/tenant select options near auth fields."""
    options: List[str] = []
    selects = driver.find_elements(By.CSS_SELECTOR, "select")
    for sel in selects:
        try:
            if not _is_interactable(sel):
                continue
            label_text = (sel.get_attribute("aria-label") or "") + " " + (sel.get_attribute("name") or "")
            if any(kw in label_text.lower() for kw in AUTH_KEYWORDS):
                for opt in sel.find_elements(By.TAG_NAME, "option"):
                    text = (opt.get_attribute("value") or opt.text or "").strip()
                    if text and text.lower() != "select":
                        options.append(text)
                        break  # use first option as default
        except Exception:
            continue
    return options


def _toggle_supporting_checkboxes(
    driver: webdriver.Chrome,
    record_event: Callable[[str], None],
    recorded_actions: List[RecordedAction],
) -> None:
    """Toggle common checkboxes (remember me, accept terms) to improve success rates."""
    keywords = ["remember", "stay signed", "keep me", "terms", "privacy", "agree", "accept", "continue", "consent"]
    checkboxes = driver.find_elements(By.CSS_SELECTOR, "input[type='checkbox'], [role='switch']")
    for cb in checkboxes:
        try:
            if not _is_interactable(cb):
                continue
            cb_id = cb.get_attribute("id") or ""
            label_text = ""
            if cb_id:
                try:
                    label_el = driver.find_element(By.CSS_SELECTOR, f"label[for='{cb_id}']")
                    label_text = (label_el.text or "").strip()
                except Exception:
                    label_text = ""
            label_parts = [
                cb.get_attribute("aria-label") or "",
                cb.get_attribute("name") or "",
                cb_id,
                cb.get_attribute("value") or "",
                label_text,
            ]
            label = " ".join(label_parts).lower()
            if any(kw in label for kw in keywords):
                selector = _selector_for_element(driver, cb)
                try:
                    cb.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", cb)
                record_event("Toggled supportive checkbox.")
                recorded_actions.append(
                    RecordedAction(
                        action="click",
                        selector=selector,
                        note="Toggled supportive checkbox",
                    )
                )
        except StaleElementReferenceException:
            continue


def _locate_username_field(driver: webdriver.Chrome):
    return _find_best_input(
        driver,
        include_if=lambda element: _is_username_candidate(element),
        fallback=lambda elements: next(
            (el for el in elements if _is_user_like(el) and _is_interactable(el)), None
        ),
    )


def _locate_password_field(driver: webdriver.Chrome):
    return _find_best_input(
        driver,
        include_if=lambda element: (element.get_attribute("type") or "").lower() == "password",
        fallback=lambda elements: next(
            (el for el in elements if (el.get_attribute("type") or "").lower() == "password"), None
        ),
    )


def _find_best_input(
    driver: webdriver.Chrome,
    *,
    include_if: Callable[[object], bool],
    fallback: Callable[[list], object | None],
):
    candidates = []
    inputs = driver.find_elements(By.CSS_SELECTOR, "input, textarea")
    for element in inputs:
        try:
            if not _is_interactable(element):
                continue
            if include_if(element):
                score = _score_field(element)
                candidates.append((score, element))
        except StaleElementReferenceException:
            continue
    if candidates:
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]
    return fallback(inputs)


def _score_field(element) -> int:
    score = 0
    field_type = (element.get_attribute("type") or "").lower()
    if field_type in {"text", "email"}:
        score += 2
    name = (element.get_attribute("name") or "").lower()
    element_id = (element.get_attribute("id") or "").lower()
    placeholder = (element.get_attribute("placeholder") or "").lower()
    aria = (element.get_attribute("aria-label") or "").lower()
    joined = " ".join([name, element_id, placeholder, aria])
    for keyword in AUTH_KEYWORDS:
        if keyword in joined:
            score += 3
    if field_type == "email":
        score += 1
    if "name" in joined:
        score += 1
    return score


def _is_username_candidate(element) -> bool:
    field_type = (element.get_attribute("type") or "").lower()
    if field_type in {"password", "hidden", "submit", "button", "checkbox", "radio"}:
        return False
    name = (element.get_attribute("name") or "").lower()
    element_id = (element.get_attribute("id") or "").lower()
    placeholder = (element.get_attribute("placeholder") or "").lower()
    aria = (element.get_attribute("aria-label") or "").lower()
    joined = " ".join([name, element_id, placeholder, aria])
    return any(keyword in joined for keyword in AUTH_KEYWORDS) or field_type in {"text", "email", "tel"}


def _is_user_like(element) -> bool:
    field_type = (element.get_attribute("type") or "").lower()
    return field_type in {"text", "email"}


def _is_interactable(element) -> bool:
    return element.is_displayed() and element.is_enabled()


def _clear_and_type(element, value: str) -> None:
    element.click()
    element.clear()
    element.send_keys(value)


def _submit_login(
    driver: webdriver.Chrome,
    password_field,
    record_event: Callable[[str], None],
) -> tuple[str, str | None] | None:
    submit_candidate_selectors = [
        "button[type='submit']",
        "input[type='submit']",
        "button[name*='login']",
        "button[id*='login']",
        "button[class*='login']",
        "button[aria-label*='login']",
        "button[data-action*='login']",
        "a[role='button']",
        "a[id*='log']",
        "a[id*='sign']",
        "a[class*='login']",
        "a[class*='btn']",
        "a[data-action*='login']",
        "[data-test='login-button']",
    ]
    selector = ", ".join(submit_candidate_selectors)
    submitters = driver.find_elements(By.CSS_SELECTOR, selector)
    for submit in submitters:
        try:
            if _is_interactable(submit):
                submit_selector = _selector_for_element(driver, submit)
                try:
                    submit.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", submit)
                record_event("Clicked submit button.")
                return ("click", submit_selector)
        except StaleElementReferenceException:
            continue

    try:
        form = password_field.find_element(By.XPATH, "ancestor::form")
        form.submit()
        record_event("Submitted login form.")
        return ("form_submit", None)
    except NoSuchElementException:
        pass

    try:
        password_field.send_keys(Keys.RETURN)
        record_event("Submitted credentials via Enter key.")
        return ("enter_key", None)
    except Exception:
        return None


def _login_form_present(driver: webdriver.Chrome) -> bool:
    try:
        password_fields = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
        for field in password_fields:
            if _is_interactable(field):
                return True
        return False
    except StaleElementReferenceException:
        return True


# Chrome errors raised when a check runs while the page is navigating away
# (e.g. right after submitting the login form). They mean "look again".
_NAVIGATION_RACE_MARKERS = (
    "does not belong to the document",
    "inspected target navigated or closed",
    "cannot find context with specified id",
    "no such execution context",
    "target frame detached",
    "node is detached from document",
)


def _is_navigation_race(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in _NAVIGATION_RACE_MARKERS)


def _record_reveal(selector: str | None, recorded_actions: List[RecordedAction]) -> None:
    if selector:
        recorded_actions.append(RecordedAction(action="click", selector=selector, note="Reveal login form"))


def _wait_for_login_completion(driver: webdriver.Chrome, *, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            if not _login_form_present(driver):
                return
            if _has_failure_feedback(driver):
                message = _extract_feedback_message(driver)
                raise CredentialRejected(f"Login failed: {message or 'invalid credentials'}")
        except (StaleElementReferenceException, WebDriverException) as exc:
            if not isinstance(exc, StaleElementReferenceException) and not _is_navigation_race(exc):
                raise
            # The page is mid-navigation; check again on the next tick.
        time.sleep(0.25)
    raise RuntimeError("Timed out waiting for login to complete.")


def _ensure_no_error_feedback(driver: webdriver.Chrome) -> None:
    if _has_failure_feedback(driver):
        message = _extract_feedback_message(driver)
        raise CredentialRejected(f"Login failed: {message or 'invalid credentials'}")


def _has_failure_feedback(driver: webdriver.Chrome) -> bool:
    messages = driver.find_elements(By.CSS_SELECTOR, ".flash.error, .alert-error, .error, [data-test='error']")
    for message in messages:
        try:
            if message.is_displayed():
                return True
        except StaleElementReferenceException:
            continue
    # Many sites style the error with their own classes; fall back to the text
    # of visible alert-like elements. Recognising a rejection matters: it is
    # what stops the worker resubmitting the same bad password (lockout risk).
    for message in driver.find_elements(By.CSS_SELECTOR, _FEEDBACK_SELECTORS):
        try:
            if message.is_displayed() and is_credential_rejection_text(message.text):
                return True
        except StaleElementReferenceException:
            continue
    return False


_FEEDBACK_SELECTORS = (
    ".flash, .alert, [role='alert'], [aria-live], .notification, .message, "
    ".invalid-feedback, .error-message, .errors, .form-error, .login-error, .help-block"
)

# Phrases sites use for "wrong username/password". Deliberately specific:
# a match makes the run stop without retrying.
_REJECTION_RE = re.compile(
    r"(invalid|incorrect|wrong|unrecogni[sz]ed|bad)\s+(user\s*name|username|user|e-?mail|password|credentials?|login|sign[- ]?in)"
    r"|(user\s*name|username|e-?mail|password|credentials?)[^.!]{0,40}?\b(is|are|was|were)\s+(invalid|incorrect|wrong|not\s+recogni[sz]ed)"
    r"|(login|sign[- ]?in|authentication)\s+(failed|unsuccessful)"
    r"|(username|e-?mail)\s+(and|or)\s+password\s+(do(es)?\s*n[o']t|did\s*n[o']t)\s+match",
    re.IGNORECASE,
)


def is_credential_rejection_text(text: str | None) -> bool:
    return bool(text) and bool(_REJECTION_RE.search(text))


def _extract_feedback_message(driver: webdriver.Chrome) -> str | None:
    selectors = [
        ".flash.success",
        ".flash",
        ".alert-success",
        ".alert",
        "[role='alert']",
        ".notification",
        ".message",
    ]
    for selector in selectors:
        try:
            element = driver.find_element(By.CSS_SELECTOR, selector)
            text = element.text.strip()
            if text:
                return text
        except NoSuchElementException:
            continue
        except StaleElementReferenceException:
            continue
    return None


def _extract_heading(driver: webdriver.Chrome) -> str | None:
    for selector in ("h1", "h2", "h3", ".heading", ".title"):
        try:
            element = driver.find_element(By.CSS_SELECTOR, selector)
            text = element.text.strip()
            if text:
                return text
        except NoSuchElementException:
            continue
        except StaleElementReferenceException:
            continue
    return None
