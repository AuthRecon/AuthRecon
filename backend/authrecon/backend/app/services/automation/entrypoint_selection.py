"""
Login entrypoint selection for multi-path authentication pages.

Handles scenarios where a login page contains multiple "Sign In" buttons
(e.g., "Medical Sign In", "Funeral Home Sign In", "Public Login", "Partner Login").
Uses hint-based fuzzy matching to select the correct login path.
"""
import logging
from dataclasses import dataclass
from typing import Any

from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.common.by import By

logger = logging.getLogger(__name__)


@dataclass
class EntrypointCandidate:
    """Represents a potential login button/link."""
    element: WebElement
    text: str
    score: int
    selector_info: str  # For debugging


def score_element(element_text: str, hint: str | None) -> int:
    """
    Score an element based on hint matching.

    Returns:
        - 100: Exact match
        - 90: Starts with hint
        - 80: Contains hint as whole word
        - 70: Contains hint as substring
        - 60-80: Fuzzy match above threshold
        - 0: No match
    """
    if not hint:
        # No hint provided - use auto-detect scoring for login keywords
        return _auto_detect_score(element_text)

    text = element_text.lower().strip()
    hint_lower = hint.lower().strip()

    # Exact match (highest priority)
    if hint_lower == text:
        return 100

    # Starts with hint
    if text.startswith(hint_lower):
        return 90

    # Contains hint as whole word
    if f" {hint_lower} " in f" {text} ":
        return 80

    # Contains hint as substring
    if hint_lower in text:
        return 70

    # Fuzzy match (fallback)
    try:
        from rapidfuzz import fuzz
        ratio = fuzz.partial_ratio(hint_lower, text)
        if ratio > 60:
            return int(ratio)
    except ImportError:
        logger.debug("rapidfuzz not available, skipping fuzzy matching")

    return 0


def _auto_detect_score(element_text: str) -> int:
    """Auto-detect login buttons when no hint is provided."""
    text = element_text.lower().strip()

    # High priority keywords
    if any(keyword in text for keyword in ["sign in", "log in", "login"]):
        return 85

    # Medium priority keywords
    if any(keyword in text for keyword in ["authenticate", "access", "enter"]):
        return 70

    # Generic submit buttons
    if text in ["submit", "continue", "next"]:
        return 50

    return 0


def select_login_entrypoint(
    driver: WebDriver,
    login_hint: str | None = None,
    timeout: float = 5.0
) -> tuple[WebElement | None, list[EntrypointCandidate]]:
    """
    Select the correct login entrypoint from a page with multiple login buttons.

    Args:
        driver: Selenium WebDriver instance
        login_hint: Optional keyword to match against button text (e.g., "funeral", "medical")
        timeout: Maximum time to wait for elements

    Returns:
        Tuple of (selected_element, all_candidates)
        - selected_element: The best matching WebElement, or None if no match
        - all_candidates: List of all candidates found with their scores (for debugging)
    """
    candidates: list[EntrypointCandidate] = []

    # Selectors to search for clickable login elements
    selectors = [
        (By.CSS_SELECTOR, "button"),
        (By.CSS_SELECTOR, "a"),
        (By.CSS_SELECTOR, "input[type='submit']"),
        (By.CSS_SELECTOR, "input[type='button']"),
        (By.CSS_SELECTOR, "*[role='button']"),
        (By.CSS_SELECTOR, "*[onclick]"),
    ]

    for by, selector in selectors:
        try:
            elements = driver.find_elements(by, selector)
            for element in elements:
                # Skip if not displayed or not enabled
                if not element.is_displayed() or not element.is_enabled():
                    continue

                # Extract visible text (try multiple sources)
                text = element.text.strip()

                # Fallback 1: value attribute (for input elements)
                if not text:
                    text = (element.get_attribute("value") or "").strip()

                # Fallback 2: aria-label (common for accessible buttons)
                if not text:
                    text = (element.get_attribute("aria-label") or "").strip()

                # Fallback 3: title attribute
                if not text:
                    text = (element.get_attribute("title") or "").strip()

                # Fallback 4: innerText via JavaScript (handles nested elements)
                if not text:
                    try:
                        text = (driver.execute_script("return arguments[0].innerText;", element) or "").strip()
                    except Exception:
                        pass

                if not text:
                    continue

                # Score this candidate
                score = score_element(text, login_hint)

                if score > 0:
                    candidates.append(
                        EntrypointCandidate(
                            element=element,
                            text=text,
                            score=score,
                            selector_info=f"{by}={selector}"
                        )
                    )
        except Exception as e:
            logger.debug(f"Error finding elements with {by}={selector}: {e}")
            continue

    if not candidates:
        logger.warning("No login entrypoint candidates found on page")
        return None, []

    # Sort by score (highest first)
    candidates.sort(key=lambda c: c.score, reverse=True)

    # Select the highest scoring candidate
    best_candidate = candidates[0]

    # Log selection
    if login_hint:
        logger.info(
            f"Selected login entrypoint: '{best_candidate.text}' "
            f"(score: {best_candidate.score}, hint: '{login_hint}')"
        )
    else:
        logger.info(
            f"Auto-detected login entrypoint: '{best_candidate.text}' "
            f"(score: {best_candidate.score})"
        )

    if len(candidates) > 1:
        logger.debug("Other candidates found:")
        for candidate in candidates[1:6]:  # Log top 5 alternatives
            logger.debug(f"  - '{candidate.text}' (score: {candidate.score})")

    return best_candidate.element, candidates


def click_entrypoint_safe(element: WebElement, driver: WebDriver) -> bool:
    """
    Safely click a login entrypoint element with fallback strategies.

    Args:
        element: The WebElement to click
        driver: WebDriver instance for JavaScript fallback

    Returns:
        True if click succeeded, False otherwise
    """
    try:
        # Strategy 1: Normal click
        element.click()
        return True
    except Exception as e1:
        logger.debug(f"Normal click failed: {e1}, trying hover + click")
        try:
            # Strategy 2: Hover then click (for elements requiring hover)
            from selenium.webdriver.common.action_chains import ActionChains
            actions = ActionChains(driver)
            actions.move_to_element(element).pause(0.5).click().perform()
            return True
        except Exception as e2:
            logger.debug(f"Hover click failed: {e2}, trying JavaScript click")
            try:
                # Strategy 3: JavaScript click (fallback)
                driver.execute_script("arguments[0].click();", element)
                return True
            except Exception as e3:
                logger.error(f"All click strategies failed: {e3}")
                return False
