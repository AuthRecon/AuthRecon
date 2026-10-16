from __future__ import annotations

import logging
import os

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

DEFAULT_CHROME_BINARY = "/usr/bin/chromium"
DEFAULT_CHROMEDRIVER = "/usr/bin/chromedriver"


def create_chrome_options(*, headless: bool = True, disable_http2: bool = False) -> Options:
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"🖥️  Creating Chrome options with headless={headless}")

    options = Options()
    chrome_binary = os.getenv("CHROME_BINARY", DEFAULT_CHROME_BINARY)
    if chrome_binary:
        options.binary_location = chrome_binary

    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-extensions")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--allow-insecure-localhost")
    options.page_load_strategy = "eager"
    if disable_http2:
        # Fallback after an HTTP/2 stall; see navigation.py.
        options.add_argument("--disable-http2")

    if headless:
        options.add_argument("--headless=new")
        logger.info("  ✓ Running in headless mode")
    else:
        logger.info("  ✓ Running with visible browser (VNC streaming enabled)")

    # Enable performance logging to capture network events and response headers
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    # Target pages are untrusted: never save anything they try to download.
    options.add_experimental_option("prefs", {"download_restrictions": 3})

    return options


def create_webdriver(options: Options | None = None) -> webdriver.Chrome:
    chrome_options = options or create_chrome_options()
    # With BROWSER_ISOLATION on, browsers run in the isolated authrecon-browser
    # container (services/automation/remote_browser.py): headless ones, and
    # headful ones on the live view's display there.
    from app.services.automation.remote_browser import create_remote_chrome, current_display, isolation_enabled

    if isolation_enabled() and ("--headless=new" in chrome_options.arguments or current_display()):
        driver = create_remote_chrome(chrome_options)
        harden_driver(driver)
        return driver
    driver_path = os.getenv("CHROMEDRIVER_PATH", DEFAULT_CHROMEDRIVER)
    if driver_path and os.path.exists(driver_path):
        service = Service(executable_path=driver_path)
        driver = webdriver.Chrome(service=service, options=chrome_options)
    else:
        driver = webdriver.Chrome(options=chrome_options)
    harden_driver(driver)
    return driver


def harden_driver(driver: webdriver.Chrome) -> None:
    """Untrusted-page guards for a Selenium Chrome session (services/target_guard.py):
    the browser refuses requests to AuthRecon's own services, cloud metadata and
    loopback (including requests a page's scripts make), and denies downloads."""
    from app.services.target_guard import BROWSER_BLOCK_PATTERNS

    try:
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": list(BROWSER_BLOCK_PATTERNS)})
    except Exception:  # pragma: no cover - CDP unavailable: target checks still apply
        logging.getLogger(__name__).warning("Could not set browser URL blocking", exc_info=True)
    try:
        driver.execute_cdp_cmd("Browser.setDownloadBehavior", {"behavior": "deny"})
    except Exception:  # pragma: no cover - the download_restrictions pref still applies
        pass

