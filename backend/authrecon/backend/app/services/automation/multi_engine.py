"""
Multi-Engine Authentication Execution.

ARCHITECTURE (Current - v0.1):
  Worker calls Selenium (existing) → generates .side file, cookies, screenshots
  Worker calls this module → optionally runs Playwright for HAR capture

ARCHITECTURE (Future - v2.0):
  Worker calls this module with engine preferences
  This module orchestrates Selenium | Playwright | HTTPX independently
  Returns unified results with per-engine artifacts

CURRENT IMPLEMENTATION:
  Simple wrapper that runs Playwright post-auth using Selenium's cookies.
  Generates real HAR files without disrupting existing Selenium flow.

FUTURE ENHANCEMENTS:
  - Full independent engine execution (no cross-dependencies)
  - Database schema: engine_results table
  - UI: per-engine result display
  - Engine selection via API/env vars
  - Playwright full auth patterns (not just post-auth HAR)

---

Example Usage (Current):

    # In worker after Selenium succeeds:
    from app.services.automation.multi_engine import capture_playwright_har_post_auth

    selenium_result = run_form_login(...)  # Existing Selenium

    # Add Playwright HAR (optional, non-breaking)
    har_bytes = await capture_playwright_har_post_auth(
        run_id=run.id,
        target_url=selenium_result.final_url,
        cookies=selenium_result.cookies
    )

    if har_bytes:
        # Save as artifact
        artifacts.append(Artifact(type='har', data=har_bytes))

---

Example Usage (Future v2.0):

    from app.services.automation.multi_engine import run_multi_engine_auth

    results = await run_multi_engine_auth(
        run_id=run.id,
        target_url=run.target_url,
        credentials={...},
        engines=['selenium', 'playwright', 'httpx'],  # User preference
        parallel=False  # Sequential execution
    )

    # Returns:
    # {
    #   'selenium': EngineResult(success=True, artifacts=[...]),
    #   'playwright': EngineResult(success=True, artifacts=[...]),
    #   'httpx': EngineResult(success=False, error="...")
    # }
"""

import os
import logging
from typing import Dict, List, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


async def capture_playwright_har_post_auth(
    run_id: str,
    target_url: str,
    cookies: List[Dict[str, Any]],
    timeout_seconds: int = 30
) -> bytes | None:
    """
    Capture HAR file using Playwright after Selenium authentication.

    This is a SIMPLE v0.1 implementation that:
    1. Takes cookies from successful Selenium auth
    2. Launches Playwright with HAR recording
    3. Sets cookies in Playwright context
    4. Navigates to post-auth pages
    5. Returns HAR bytes

    DOES NOT re-attempt authentication - Selenium already proved it works.
    DOES NOT fail the run if Playwright fails - HAR is bonus artifact.

    Args:
        run_id: AuthRecon run ID (for HAR filename)
        target_url: Post-auth URL to visit (usually final_url from Selenium)
        cookies: Cookies captured by Selenium (session tokens)
        timeout_seconds: Max time for Playwright operations

    Returns:
        bytes: Complete HAR file as bytes
        None: If Playwright disabled, fails, or no network events captured

    Environment Variables:
        ENABLE_PLAYWRIGHT_HAR: "true" to enable (default: "false")

    Example:
        selenium_result = run_form_login(...)

        if selenium_result.success:
            har_bytes = await capture_playwright_har_post_auth(
                run_id="RUN-ABC123",
                target_url=selenium_result.final_url,
                cookies=selenium_result.cookies
            )
    """

    # Check if Playwright HAR capture is enabled
    if os.getenv("ENABLE_PLAYWRIGHT_HAR", "false").lower() != "true":
        logger.info(f"Playwright HAR capture disabled for {run_id} (ENABLE_PLAYWRIGHT_HAR=false)")
        return None

    try:
        from playwright.async_api import async_playwright
        import tempfile
        from pathlib import Path

        logger.info(f"Starting Playwright HAR capture for {run_id}")

        har_path = Path(tempfile.gettempdir()) / f"{run_id}-playwright-post-auth.har"

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[]
            )

            try:
                # Create context with HAR recording
                context = await browser.new_context(
                    record_har_path=str(har_path),
                    record_har_omit_content=False,  # Include bodies
                    record_har_mode='minimal',  # Skip large static assets
                    ignore_https_errors=True,
                    user_agent='AuthRecon/1.0 (Playwright HAR Capture)',
                )

                # Set Selenium's cookies
                playwright_cookies = []
                for cookie in cookies:
                    pw_cookie = {
                        'name': cookie.get('name'),
                        'value': cookie.get('value'),
                        'domain': cookie.get('domain', ''),
                        'path': cookie.get('path', '/'),
                    }
                    if cookie.get('secure') is not None:
                        pw_cookie['secure'] = cookie.get('secure')
                    if cookie.get('httpOnly') is not None:
                        pw_cookie['httpOnly'] = cookie.get('httpOnly')
                    if cookie.get('sameSite'):
                        pw_cookie['sameSite'] = cookie.get('sameSite')

                    playwright_cookies.append(pw_cookie)

                await context.add_cookies(playwright_cookies)
                logger.info(f"Set {len(playwright_cookies)} cookies in Playwright context")

                # Navigate to post-auth page
                page = await context.new_page()
                page.set_default_timeout(timeout_seconds * 1000)

                logger.info(f"Navigating to {target_url} with Selenium's cookies")
                await page.goto(target_url, wait_until='networkidle', timeout=timeout_seconds * 1000)

                # Let page settle and capture all network activity
                await page.wait_for_load_state('networkidle')

                logger.info(f"Page loaded, closing context to save HAR")

                # Close context to flush HAR
                await context.close()
                await browser.close()

                # Read HAR file
                if har_path.exists():
                    har_bytes = har_path.read_bytes()
                    har_size_kb = len(har_bytes) / 1024
                    logger.info(f"Playwright HAR captured: {har_size_kb:.1f} KB for {run_id}")

                    har_path.unlink()

                    return har_bytes
                else:
                    logger.warning(f"HAR file not found at {har_path} for {run_id}")
                    return None

            finally:
                if browser:
                    await browser.close()

    except ImportError:
        logger.warning("Playwright not installed - HAR capture unavailable")
        return None
    except Exception as e:
        logger.warning(f"Playwright HAR capture failed for {run_id}: {e}", exc_info=True)
        return None
