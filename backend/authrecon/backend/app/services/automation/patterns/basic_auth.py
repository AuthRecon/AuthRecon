from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote, urlsplit, urlunsplit

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from app.core.urls import strip_userinfo

from ..browser import create_chrome_options, create_webdriver
from ..navigation import selenium_get_with_http2_fallback
from ..security_context_extractor import extract_security_context

if TYPE_CHECKING:
    from app.schemas.security_context import SecurityContext


@dataclass(slots=True)
class BasicAuthResult:
    final_url: str
    page_title: str | None
    cookies: list[dict]  # Full cookies for downstream use
    security_context: SecurityContext | None  # New comprehensive extraction
    screenshot: bytes
    html_source: str


def run_basic_auth(
    target_url: str,
    username: str,
    password: str,
    *,
    headless: bool = True,
    timeout_seconds: int = 30,
) -> BasicAuthResult:
    """
    Execute a simple HTTP basic authentication flow against the provided target.

    Returns the landing URL, page title, captured screenshot bytes, and cookie names.
    """
    if not username:
        raise ValueError("Username must be provided for basic auth automation.")
    if password is None:
        raise ValueError("Password must be provided for basic auth automation.")

    launch_url = _inject_basic_auth_credentials(target_url, username, password)
    options = _build_chrome_options(headless=headless)

    driver = _init_webdriver(options)
    try:
        driver.set_page_load_timeout(timeout_seconds)
        driver = selenium_get_with_http2_fallback(
            driver, launch_url, headless=headless, page_load_timeout=timeout_seconds
        )

        # The browser reports the URL it loaded, user:password@ included.
        final_url = strip_userinfo(driver.current_url)
        page_title = driver.title
        screenshot = driver.get_screenshot_as_png()
        cookies = driver.get_cookies()
        html_source = driver.page_source

        # Extract comprehensive security context (Phase 1: cookies only)
        security_context = extract_security_context(driver, target_url)

        return BasicAuthResult(
            final_url=final_url,
            page_title=page_title or None,
            cookies=cookies,  # Legacy
            security_context=security_context,  # New comprehensive extraction
            screenshot=screenshot,
            html_source=html_source or "",
        )
    finally:
        driver.quit()


def _init_webdriver(options: Options) -> webdriver.Chrome:
    return create_webdriver(options)


def _build_chrome_options(*, headless: bool) -> Options:
    return create_chrome_options(headless=headless)


def _inject_basic_auth_credentials(target_url: str, username: str, password: str) -> str:
    parsed = urlsplit(target_url)
    netloc = parsed.netloc
    credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@{netloc}"
    return urlunsplit(
        (
            parsed.scheme,
            credentials,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )
