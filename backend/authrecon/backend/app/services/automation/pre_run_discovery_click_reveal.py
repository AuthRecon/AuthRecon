from selenium.webdriver.common.by import By
from selenium.common.exceptions import StaleElementReferenceException


def _click_reveal_elements(driver) -> str | None:
    """
    Click common "reveal login" elements (buttons/links) to surface hidden forms.

    Best effort: ignores errors, only targets elements with auth keywords.

    Does nothing when a password field is already visible: the form is already
    revealed, and clicking a "Login" control there would submit the form with
    empty fields — a failed login attempt against the target (lockout risk),
    plus a page reload under the handler's feet. Never clicks submit controls.

    Returns a Selenium IDE selector for the element it clicked (or None), so
    callers can record the click: a .side file that skips it would try to type
    into a form that is still hidden when the scanner replays it.
    """
    if _visible_password_field(driver):
        return None
    # Duplicated lightweight keyword list to avoid circular import with pre_run_discovery
    auth_keywords = [
        "sign", "log", "login", "auth", "access", "enter", "reveal", "show", "continue", "next"
    ]

    def _score_text(text: str) -> int:
        text_lower = text.lower()
        if "login" in text_lower or "log in" in text_lower or "sign in" in text_lower:
            return 100
        if any(word in text_lower for word in ("auth", "access", "enter", "continue", "next")):
            return 70
        if "reveal" in text_lower or "show" in text_lower:
            return 60
        return 0

    selectors = [
        "button",
        "a",
        "[role='button']",
        "[onclick]",
    ]
    for sel in selectors:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, sel)
            for el in elements:
                try:
                    text = (el.text or "").lower().strip()
                    if not text:
                        text = (el.get_attribute("aria-label") or "").lower().strip()
                    if _is_submit_control(el):
                        continue
                    if any(kw in text for kw in auth_keywords):
                        score = _score_text(text)
                        if score < 40:
                            continue
                        selector = _replay_selector(driver, el)
                        try:
                            el.click()
                        except Exception:
                            driver.execute_script("arguments[0].click();", el)
                        return selector  # click one and re-scan
                except StaleElementReferenceException:
                    continue
        except Exception:
            continue
    return None


_REPLAY_SELECTOR_JS = """
const e = arguments[0];
const tag = e.tagName.toLowerCase();
if (e.id) return 'css=#' + CSS.escape(e.id);
const name = e.getAttribute('name');
if (name) return 'css=' + tag + '[name="' + name.replace(/"/g, '\\"') + '"]';
const text = (e.innerText || '').trim();
if (text && text.length < 80 && !text.includes("'")) {
  return "xpath=//" + tag + "[normalize-space()='" + text.replace(/\\s+/g, ' ') + "']";
}
return null;
"""


def _replay_selector(driver, el) -> str | None:
    try:
        return driver.execute_script(_REPLAY_SELECTOR_JS, el)
    except Exception:
        return None


def _visible_password_field(driver) -> bool:
    try:
        for field in driver.find_elements(By.CSS_SELECTOR, "input[type='password']"):
            try:
                if field.is_displayed():
                    return True
            except StaleElementReferenceException:
                continue
    except Exception:
        return False
    return False


def _is_submit_control(el) -> bool:
    """Submit buttons/inputs, or a button inside a form that has a password field."""
    try:
        tag = (el.tag_name or "").lower()
        kind = (el.get_attribute("type") or "").lower()
        if kind == "submit" or (tag == "button" and kind in ("", "submit") and el.find_elements(
            By.XPATH, "ancestor::form[.//input[@type='password']]"
        )):
            return True
    except Exception:
        return True  # can't tell: don't risk submitting a form
    return False
