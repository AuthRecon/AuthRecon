"""Untrusted-page guards for Playwright contexts (see services/target_guard.py).

Every request a page makes, including ones its scripts start, is checked
against the target guard by name and literal IP (no DNS per request) and
aborted if it points at AuthRecon's own services, cloud metadata or loopback.
Contexts are also created with accept_downloads=False.
"""
from __future__ import annotations

from app.services.target_guard import is_allowed


async def harden_playwright_context(context) -> None:
    async def _route(route) -> None:
        url = route.request.url
        if not url.startswith(("http://", "https://")) or is_allowed(url, resolve=False):
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    await context.route("**/*", _route)

    from app.services.automation.remote_browser import finalize_remote_hars, isolation_enabled

    if isolation_enabled():
        # Remote HARs need finishing after the context closes (remote_browser.py).
        original_close = context.close

        async def _close(*args, **kwargs):
            try:
                return await original_close(*args, **kwargs)
            finally:
                finalize_remote_hars()

        context.close = _close


async def launch_chromium(playwright, **launch_kwargs):
    """Launch Chromium for a run: on the isolated browser agent for headless
    sessions when BROWSER_ISOLATION is on, else locally as before."""
    from app.services.automation.remote_browser import connect_playwright, current_display, isolation_enabled

    if isolation_enabled() and (launch_kwargs.get("headless", True) or current_display()):
        return await connect_playwright(playwright, **launch_kwargs)
    return await playwright.chromium.launch(**launch_kwargs)
