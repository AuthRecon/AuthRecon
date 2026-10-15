"""Pre-run discovery module for aggressive authentication endpoint and form detection."""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException

from .pre_run_discovery_click_reveal import _click_reveal_elements


@dataclass
class DiscoveredForm:
    """Represents a discovered login form."""
    action: str
    method: str
    username_field: Optional[WebElement] = None
    password_field: Optional[WebElement] = None
    submit_button: Optional[WebElement] = None
    confidence_score: int = 0
    location: str = "main_page"  # main_page, iframe, shadow_dom
    notes: List[str] = field(default_factory=list)


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered authentication endpoint."""
    url: str
    source: str  # "link", "button", "form_action", "js_reference", "common_path"
    text: Optional[str] = None
    confidence_score: int = 0


@dataclass
class DiscoveryResult:
    """Results from pre-run discovery."""
    forms: List[DiscoveredForm] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    clickable_auth_elements: List[dict] = field(default_factory=list)
    iframes_found: int = 0
    shadow_roots_found: int = 0
    recommended_approach: str = "form_based"
    confidence: int = 0
    notes: List[str] = field(default_factory=list)
    # Selectors of "reveal login" controls discovery clicked, in order; a
    # .side file has to replay these clicks before typing into the form.
    reveal_selectors: List[str] = field(default_factory=list)


# Keywords that indicate authentication elements
AUTH_KEYWORDS = [
    "sign in",
    "log in",
    "login",
    "signin",
    "authenticate",
    "access",
    "enter",
    "submit",
    "connexion",
    "accedi",
    "iniciar",
    "anmelden",
    "usuario",
]


def discover_auth_elements(driver: webdriver.Chrome, target_url: str) -> DiscoveryResult:
    """
    Aggressively discover all authentication-related elements on a page.

    This runs BEFORE attempting login to map out all possible auth methods.
    """
    result = DiscoveryResult()

    # Discovery used to "probe" a list of common auth paths but never sent a
    # request: it listed them all and reported every one as found. Sending extra requests
    # to a target the operator didn't ask for is a scope question, so discovery
    # now only reports what it actually observes on the page.

    result.forms = _discover_forms(driver)
    if not result.forms:
        revealed = _click_reveal_elements(driver)
        if revealed:
            result.reveal_selectors.append(revealed)
        result.forms = _discover_forms(driver)
    result.notes.append(f"Found {len(result.forms)} forms on main page")

    # Step 3: Find all clickable auth elements (buttons, links)
    result.clickable_auth_elements = _find_clickable_auth_elements(driver)
    result.notes.append(f"Found {len(result.clickable_auth_elements)} clickable auth elements")

    # Step 4: Check for iframes (common in SSO)
    result.iframes_found = _count_iframes(driver)
    if result.iframes_found > 0:
        result.notes.append(f"Found {result.iframes_found} iframes - may contain auth forms")
        iframe_forms = _discover_iframe_forms(driver)
        result.forms.extend(iframe_forms)

    # Step 5: Check for shadow DOM (modern web components)
    result.shadow_roots_found = _count_shadow_roots(driver)
    if result.shadow_roots_found > 0:
        result.notes.append(f"Detected {result.shadow_roots_found} shadow DOM roots - modern auth components likely")

    # Step 6: Scan page JavaScript for auth-related references
    js_endpoints = _scan_javascript_for_auth(driver)
    result.endpoints.extend(js_endpoints)
    if js_endpoints:
        result.notes.append(f"Found {len(js_endpoints)} auth endpoints in JavaScript")

    # Step 7: Determine recommended approach
    result.recommended_approach, result.confidence = _determine_approach(result)

    return result


def _discover_forms(driver: webdriver.Chrome) -> List[DiscoveredForm]:
    """Find all forms on the current page and analyze them."""
    forms = []

    try:
        form_elements = driver.find_elements(By.TAG_NAME, "form")

        for idx, form_el in enumerate(form_elements):
            try:
                discovered_form = DiscoveredForm(
                    action=form_el.get_attribute("action") or "",
                    method=form_el.get_attribute("method") or "get",
                    location="main_page"
                )

                # Look for username/email field
                username_field = _find_username_field_in_form(form_el)
                if username_field:
                    discovered_form.username_field = username_field
                    discovered_form.confidence_score += 40
                    discovered_form.notes.append("Has username/email field")

                # Look for password field
                password_field = _find_password_field_in_form(form_el)
                if password_field:
                    discovered_form.password_field = password_field
                    discovered_form.confidence_score += 50
                    discovered_form.notes.append("Has password field")

                # Look for submit button
                submit_btn = _find_submit_button_in_form(form_el)
                if submit_btn:
                    discovered_form.submit_button = submit_btn
                    discovered_form.confidence_score += 10

                # Only add if it looks like auth form
                if discovered_form.confidence_score > 30:
                    forms.append(discovered_form)

            except StaleElementReferenceException:
                continue

    except Exception as e:
        pass

    return forms


def _find_username_field_in_form(form: WebElement) -> Optional[WebElement]:
    """Find username/email field within a form."""
    selectors = [
        "input[type='email']",
        "input[type='text'][name*='user']",
        "input[type='text'][name*='email']",
        "input[type='text'][name*='login']",
        "input[type='text'][name*='account']",
        "input[type='text'][id*='user']",
        "input[type='text'][id*='email']",
        "input[type='text'][id*='login']",
        "input[type='text'][id*='account']",
        "input[placeholder*='email' i]",
        "input[placeholder*='username' i]",
        "input[placeholder*='account' i]",
        "input[aria-label*='email' i]",
        "input[aria-label*='username' i]",
        "input[aria-label*='account' i]",
        "input[type='tel']",
    ]

    for selector in selectors:
        try:
            field = form.find_element(By.CSS_SELECTOR, selector)
            if field and field.is_displayed():
                return field
        except NoSuchElementException:
            continue

    return None


def _find_password_field_in_form(form: WebElement) -> Optional[WebElement]:
    """Find password field within a form."""
    try:
        return form.find_element(By.CSS_SELECTOR, "input[type='password']")
    except NoSuchElementException:
        return None


def _find_submit_button_in_form(form: WebElement) -> Optional[WebElement]:
    """Find submit button within a form."""
    selectors = [
        "button[type='submit']",
        "input[type='submit']",
        "button:not([type='button'])",
    ]

    for selector in selectors:
        try:
            btn = form.find_element(By.CSS_SELECTOR, selector)
            if btn and btn.is_displayed():
                return btn
        except NoSuchElementException:
            continue

    return None


def _find_clickable_auth_elements(driver: webdriver.Chrome) -> List[dict]:
    """Find all buttons, links, and clickable elements that might trigger auth."""
    elements = []

    # Find all buttons
    try:
        buttons = driver.find_elements(By.TAG_NAME, "button")
        for btn in buttons:
            try:
                text = (btn.text or "").lower().strip()
                if any(keyword in text for keyword in AUTH_KEYWORDS):
                    elements.append({
                        "type": "button",
                        "text": btn.text,
                        "element": btn,
                        "score": _score_auth_element_text(text)
                    })
            except StaleElementReferenceException:
                continue
    except Exception:
        pass

    # Find all links
    try:
        links = driver.find_elements(By.TAG_NAME, "a")
        for link in links:
            try:
                text = (link.text or "").lower().strip()
                href = link.get_attribute("href") or ""

                if any(keyword in text for keyword in AUTH_KEYWORDS) or any(path in href for path in ["/login", "/signin", "/auth"]):
                    elements.append({
                        "type": "link",
                        "text": link.text,
                        "href": href,
                        "element": link,
                        "score": _score_auth_element_text(text)
                    })
            except StaleElementReferenceException:
                continue
    except Exception:
        pass

    # Find elements with onclick handlers
    try:
        onclick_elements = driver.find_elements(By.CSS_SELECTOR, "[onclick]")
        for el in onclick_elements:
            try:
                text = (el.text or "").lower().strip()
                if any(keyword in text for keyword in AUTH_KEYWORDS):
                    elements.append({
                        "type": "onclick_element",
                        "text": el.text,
                        "element": el,
                        "score": _score_auth_element_text(text)
                    })
            except StaleElementReferenceException:
                continue
    except Exception:
        pass

    # Sort by score (highest first)
    elements.sort(key=lambda x: x["score"], reverse=True)

    return elements


def _score_auth_element_text(text: str) -> int:
    """Score how likely an element's text indicates authentication."""
    text_lower = text.lower()

    # Exact matches (highest priority)
    if text_lower in ["sign in", "log in", "login", "signin"]:
        return 100

    # Starts with auth keyword
    if text_lower.startswith(("sign in", "log in", "login")):
        return 90

    # Contains auth keyword
    if "sign in" in text_lower or "log in" in text_lower:
        return 80
    if "login" in text_lower or "signin" in text_lower:
        return 70
    if "authenticate" in text_lower or "access" in text_lower:
        return 60
    if "enter" in text_lower or "submit" in text_lower:
        return 40

    return 0


def _count_iframes(driver: webdriver.Chrome) -> int:
    """Count iframes on the page (often used for SSO)."""
    try:
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        return len(iframes)
    except Exception:
        return 0


def _discover_iframe_forms(driver: webdriver.Chrome) -> List[DiscoveredForm]:
    """Search inside iframes for auth forms."""
    iframe_forms = []

    try:
        iframes = driver.find_elements(By.TAG_NAME, "iframe")

        for idx, iframe in enumerate(iframes):
            try:
                driver.switch_to.frame(iframe)

                # Look for forms inside iframe
                forms = _discover_forms(driver)
                for form in forms:
                    form.location = f"iframe_{idx}"
                    form.notes.append(f"Found in iframe #{idx}")
                    iframe_forms.append(form)

                # Switch back to main content
                driver.switch_to.default_content()

            except Exception:
                driver.switch_to.default_content()
                continue

    except Exception:
        driver.switch_to.default_content()

    return iframe_forms


def _count_shadow_roots(driver: webdriver.Chrome) -> int:
    """Detect shadow DOM usage (modern web components)."""
    try:
        # Execute JS to count shadow roots
        script = """
        return document.querySelectorAll('*').length > 0 &&
               Array.from(document.querySelectorAll('*'))
                    .filter(el => el.shadowRoot)
                    .length;
        """
        count = driver.execute_script(script)
        return count or 0
    except Exception:
        return 0


def _scan_javascript_for_auth(driver: webdriver.Chrome) -> List[DiscoveredEndpoint]:
    """Scan page JavaScript for authentication endpoint references."""
    endpoints = []

    try:
        # Look for API endpoints in page source
        script = """
        const text = document.documentElement.innerHTML;
        const authPatterns = [
            /['"](\\/api\\/auth[^'"]*)['"]/g,
            /['"](\\/api\\/login[^'"]*)['"]/g,
            /['"](\\/oauth[^'"]*)['"]/g,
            /['"](\\/saml[^'"]*)['"]/g,
        ];

        const found = new Set();
        authPatterns.forEach(pattern => {
            const matches = text.matchAll(pattern);
            for (const match of matches) {
                found.add(match[1]);
            }
        });

        return Array.from(found);
        """

        found_paths = driver.execute_script(script)

        for path in (found_paths or []):
            endpoints.append(DiscoveredEndpoint(
                url=urljoin(driver.current_url, path),
                source="js_reference",
                confidence_score=50
            ))

    except Exception:
        pass

    # Check for Okta Sign-In Widget
    try:
        okta_widget_detected = _detect_okta_widget(driver)
        if okta_widget_detected:
            endpoints.append(DiscoveredEndpoint(
                url=driver.current_url,
                source="okta_widget",
                text="Okta Sign-In Widget detected",
                confidence_score=95
            ))
    except Exception:
        pass

    return endpoints


def _detect_okta_widget(driver: webdriver.Chrome) -> bool:
    """Detect Okta Sign-In Widget via JavaScript and HTML markers."""
    try:
        script = """
        return (
            document.querySelector('.okta-sign-in') !== null ||
            document.querySelector('[data-se="o-form"]') !== null ||
            window.OktaSignIn !== undefined ||
            document.documentElement.innerHTML.includes('okta-sign-in-widget') ||
            document.querySelector('#okta-sign-in') !== null
        );
        """
        return driver.execute_script(script) or False
    except Exception:
        return False


def _determine_approach(result: DiscoveryResult) -> tuple[str, int]:
    """
    Determine the recommended authentication approach based on discoveries.

    Confidence calculation is based on REAL evidence counts, not magic numbers.
    """

    # If we found high-confidence forms, recommend form-based
    high_conf_forms = [f for f in result.forms if f.confidence_score >= 70]
    if high_conf_forms:
        # Confidence = highest form score found
        best_form_score = max(f.confidence_score for f in high_conf_forms)
        return "form_based", best_form_score

    # If we found medium-confidence forms
    medium_conf_forms = [f for f in result.forms if f.confidence_score >= 40]
    if medium_conf_forms:
        # Confidence = highest form score found
        best_form_score = max(f.confidence_score for f in medium_conf_forms)
        return "form_based", best_form_score

    # If we found auth endpoints in JS, might be SPA
    js_endpoints = [e for e in result.endpoints if e.source == "js_reference"]
    if js_endpoints:
        # Confidence based on number of JS auth references found (capped at 90)
        confidence = min(50 + (len(js_endpoints) * 10), 90)
        return "api_based", confidence

    # If we found iframes, likely SSO
    if result.iframes_found > 0:
        # Confidence based on iframe count (more iframes = more likely SSO)
        confidence = min(50 + (result.iframes_found * 15), 80)
        return "sso_iframe", confidence

    # If we found clickable auth elements but no forms
    if result.clickable_auth_elements and not result.forms:
        # Confidence based on top scoring clickable element
        best_element_score = max(el["score"] for el in result.clickable_auth_elements)
        # Normalize to 0-100 scale (element scores are 0-100 already)
        confidence = min(best_element_score, 70)  # Cap at 70 since no form found
        return "click_then_form", confidence

    # Default fallback - low confidence, no strong evidence
    return "form_based", 20
