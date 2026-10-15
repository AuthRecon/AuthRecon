from __future__ import annotations

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

    return options


def create_webdriver(options: Options | None = None) -> webdriver.Chrome:
    chrome_options = options or create_chrome_options()
    driver_path = os.getenv("CHROMEDRIVER_PATH", DEFAULT_CHROMEDRIVER)
    if driver_path and os.path.exists(driver_path):
        service = Service(executable_path=driver_path)
        return webdriver.Chrome(service=service, options=chrome_options)
    return webdriver.Chrome(options=chrome_options)

