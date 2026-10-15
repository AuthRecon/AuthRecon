"""Navigation resilience shared by the Selenium and Playwright engines.

Some targets stall parallel HTTP/2 streams: the first couple of requests
succeed and the rest hang, so Chromium's initial navigation times out. When
the first navigation to the target times out we relaunch the browser once
with ``--disable-http2`` and retry. Default behaviour is unchanged: HTTP/2 is
only disabled after a timeout.

Notes recorded here are fixed strings (never URLs, which can carry basic-auth
credentials); the worker drains them into the run timeline.
"""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

DISABLE_HTTP2_ARG = "--disable-http2"
HTTP2_FALLBACK_NOTE = (
    "Navigation to the target timed out; retrying once with HTTP/2 disabled "
    "(some servers stall parallel HTTP/2 requests)."
)

_TIMEOUT_MARKERS = ("net::ERR_TIMED_OUT", "net::ERR_CONNECTION_TIMED_OUT")

_pending_notes: list[str] = []


def record_note(message: str) -> None:
    # Written to the live timeline straight away when a run has one; queued
    # for the worker to record afterwards otherwise.
    from app.services.live_timeline import _prefix, write

    if not write(f"{_prefix.get()}{message}"):
        _pending_notes.append(message)


def drain_notes() -> list[str]:
    notes = list(_pending_notes)
    _pending_notes.clear()
    return notes


def is_navigation_timeout(exc: BaseException) -> bool:
    """True for Selenium/Playwright navigation timeouts (not other failures)."""
    try:
        from selenium.common.exceptions import TimeoutException as SeleniumTimeout

        if isinstance(exc, SeleniumTimeout):
            return True
    except ImportError:  # pragma: no cover - selenium is a hard dependency
        pass
    try:
        from playwright.async_api import TimeoutError as PlaywrightAsyncTimeout
        from playwright.sync_api import TimeoutError as PlaywrightSyncTimeout

        if isinstance(exc, (PlaywrightAsyncTimeout, PlaywrightSyncTimeout)):
            return True
    except ImportError:  # pragma: no cover - playwright is a hard dependency
        pass
    message = str(exc)
    return any(marker in message for marker in _TIMEOUT_MARKERS)


def should_retry_without_http2(exc: BaseException, *, http2_disabled: bool) -> bool:
    """Retry exactly once: only after a timeout, and only if HTTP/2 is still on."""
    return not http2_disabled and is_navigation_timeout(exc)


def with_http2_disabled(args: list[str] | None) -> list[str]:
    merged = list(args or [])
    if DISABLE_HTTP2_ARG not in merged:
        merged.append(DISABLE_HTTP2_ARG)
    return merged


def selenium_get_with_http2_fallback(
    driver: Any,
    url: str,
    *,
    headless: bool,
    page_load_timeout: int | None = None,
    create_driver: Callable[..., Any] | None = None,
) -> Any:
    """``driver.get(url)``; on timeout, relaunch with HTTP/2 off and retry once.

    Returns the driver to keep using (a new one if the retry happened). The
    caller's ``finally: driver.quit()`` must refer to the returned driver.
    """
    try:
        driver.get(url)
        return driver
    except Exception as exc:
        if not should_retry_without_http2(exc, http2_disabled=False):
            raise
    logger.warning("Initial navigation timed out; retrying with HTTP/2 disabled")
    record_note(HTTP2_FALLBACK_NOTE)
    try:
        driver.quit()
    except Exception:
        pass
    if create_driver is None:
        from .browser import create_chrome_options, create_webdriver

        def create_driver() -> Any:
            return create_webdriver(create_chrome_options(headless=headless, disable_http2=True))

    new_driver = create_driver()
    if page_load_timeout:
        new_driver.set_page_load_timeout(page_load_timeout)
    new_driver.get(url)
    return new_driver


async def playwright_goto_with_http2_fallback(
    open_page: Callable[[bool], Awaitable[tuple[Any, Any, Any]]],
    browser: Any,
    context: Any,
    page: Any,
    url: str,
    **goto_kwargs: Any,
) -> tuple[Any, Any, Any, BaseException | None]:
    """``page.goto``; on timeout, reopen via ``open_page(True)`` and retry once.

    ``open_page(disable_http2)`` must launch the browser and build the
    context/page exactly as the caller originally did. Returns the
    (browser, context, page) to keep using plus the final timeout, if any, so
    the caller keeps its existing timeout handling (continue or fail).
    Non-timeout errors propagate unchanged.
    """
    try:
        await page.goto(url, **goto_kwargs)
        return browser, context, page, None
    except Exception as exc:
        if not should_retry_without_http2(exc, http2_disabled=False):
            raise
    logger.warning("Initial navigation timed out; retrying with HTTP/2 disabled")
    record_note(HTTP2_FALLBACK_NOTE)
    for closable in (context, browser):
        try:
            await closable.close()
        except Exception:
            pass
    browser, context, page = await open_page(True)
    try:
        await page.goto(url, **goto_kwargs)
    except Exception as exc:
        if not is_navigation_timeout(exc):
            raise
        return browser, context, page, exc
    return browser, context, page, None
