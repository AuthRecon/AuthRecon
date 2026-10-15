"""HTTP/2 fallback: when to retry, and that both engines retry exactly once."""
from __future__ import annotations

import asyncio

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeout
from selenium.common.exceptions import TimeoutException, WebDriverException

from app.services.automation import navigation as nav
from app.services.automation.browser import create_chrome_options


@pytest.fixture(autouse=True)
def _clean_notes():
    nav.drain_notes()
    yield
    nav.drain_notes()


@pytest.mark.parametrize(
    "exc, expected",
    [
        (TimeoutException("page load"), True),
        (PlaywrightTimeout("Timeout 30000ms exceeded."), True),
        (WebDriverException("unknown error: net::ERR_TIMED_OUT"), True),
        (WebDriverException("unknown error: net::ERR_NAME_NOT_RESOLVED"), False),
        (ValueError("bad selector"), False),
    ],
)
def test_is_navigation_timeout(exc, expected):
    assert nav.is_navigation_timeout(exc) is expected


def test_retry_decision():
    assert nav.should_retry_without_http2(TimeoutException(), http2_disabled=False)
    assert not nav.should_retry_without_http2(TimeoutException(), http2_disabled=True)
    assert not nav.should_retry_without_http2(ValueError(), http2_disabled=False)


def test_with_http2_disabled_does_not_duplicate():
    assert nav.with_http2_disabled(["--a"]) == ["--a", nav.DISABLE_HTTP2_ARG]
    assert nav.with_http2_disabled([nav.DISABLE_HTTP2_ARG]) == [nav.DISABLE_HTTP2_ARG]
    assert nav.with_http2_disabled(None) == [nav.DISABLE_HTTP2_ARG]


def test_chrome_options_only_disable_http2_when_asked():
    assert nav.DISABLE_HTTP2_ARG not in create_chrome_options().arguments
    assert nav.DISABLE_HTTP2_ARG in create_chrome_options(disable_http2=True).arguments


def test_note_never_contains_a_url():
    assert "http://" not in nav.HTTP2_FALLBACK_NOTE and "https://" not in nav.HTTP2_FALLBACK_NOTE


# --- Selenium ---------------------------------------------------------------


class FakeDriver:
    def __init__(self, fail_with=None):
        self.fail_with = fail_with
        self.visited = []
        self.quit_called = False
        self.page_load_timeout = None

    def get(self, url):
        self.visited.append(url)
        if self.fail_with:
            raise self.fail_with

    def quit(self):
        self.quit_called = True

    def set_page_load_timeout(self, seconds):
        self.page_load_timeout = seconds


def test_selenium_success_does_not_retry():
    driver = FakeDriver()
    created = []
    result = nav.selenium_get_with_http2_fallback(
        driver, "https://target.invalid/login", headless=True, create_driver=lambda: created.append(1)
    )
    assert result is driver and not created and nav.drain_notes() == []


def test_selenium_timeout_retries_once_with_new_driver():
    first = FakeDriver(fail_with=TimeoutException("timed out"))
    second = FakeDriver()
    result = nav.selenium_get_with_http2_fallback(
        first, "https://target.invalid/login", headless=True, page_load_timeout=30,
        create_driver=lambda: second,
    )
    assert result is second
    assert first.quit_called
    assert second.visited == ["https://target.invalid/login"]
    assert second.page_load_timeout == 30
    assert nav.drain_notes() == [nav.HTTP2_FALLBACK_NOTE]


def test_selenium_non_timeout_error_is_not_retried():
    driver = FakeDriver(fail_with=WebDriverException("net::ERR_NAME_NOT_RESOLVED"))
    with pytest.raises(WebDriverException):
        nav.selenium_get_with_http2_fallback(
            driver, "https://target.invalid/", headless=True,
            create_driver=lambda: pytest.fail("must not relaunch"),
        )
    assert nav.drain_notes() == []


def test_selenium_second_timeout_propagates():
    first = FakeDriver(fail_with=TimeoutException())
    second = FakeDriver(fail_with=TimeoutException())
    with pytest.raises(TimeoutException):
        nav.selenium_get_with_http2_fallback(
            first, "https://target.invalid/", headless=True, create_driver=lambda: second
        )


# --- Playwright -------------------------------------------------------------


class FakeClosable:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


class FakePage:
    def __init__(self, fail_with=None):
        self.fail_with = fail_with
        self.calls = []

    async def goto(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.fail_with:
            raise self.fail_with


def _pw(first_page, second_page):
    browser, context = FakeClosable(), FakeClosable()
    reopened = []

    async def open_page(disable_http2):
        reopened.append(disable_http2)
        return "browser2", "context2", second_page

    async def go():
        return await nav.playwright_goto_with_http2_fallback(
            open_page, browser, context, first_page, "https://target.invalid/",
            wait_until="networkidle", timeout=1000,
        )

    return go, browser, context, reopened


def test_playwright_success_keeps_original_objects():
    page = FakePage()
    go, browser, context, reopened = _pw(page, None)
    assert asyncio.run(go()) == (browser, context, page, None)
    assert reopened == [] and nav.drain_notes() == []


def test_playwright_timeout_reopens_with_http2_disabled():
    second = FakePage()
    go, browser, context, reopened = _pw(FakePage(fail_with=PlaywrightTimeout("t")), second)
    result = asyncio.run(go())
    assert result == ("browser2", "context2", second, None)
    assert reopened == [True]
    assert browser.closed and context.closed
    assert second.calls == [("https://target.invalid/", {"wait_until": "networkidle", "timeout": 1000})]
    assert nav.drain_notes() == [nav.HTTP2_FALLBACK_NOTE]


def test_playwright_retry_timeout_is_returned_not_raised():
    second = FakePage(fail_with=PlaywrightTimeout("again"))
    go, *_ = _pw(FakePage(fail_with=PlaywrightTimeout("t")), second)
    browser, context, page, err = asyncio.run(go())
    assert page is second and isinstance(err, PlaywrightTimeout)


def test_playwright_non_timeout_error_propagates():
    go, _, _, reopened = _pw(FakePage(fail_with=RuntimeError("net::ERR_NAME_NOT_RESOLVED")), None)
    with pytest.raises(RuntimeError):
        asyncio.run(go())
    assert reopened == []
