"""Client for the browser agent (browser_agent/agent.py).

With BROWSER_ISOLATION=true, browsers run in the authrecon-browser container,
which holds no AuthRecon secrets and has no database access; this process
(worker or API, which do hold the secrets) only drives them over the
WebDriver / Playwright protocols. Headful runs (live view, manual recording)
use a display + VNC the agent starts there (RemoteVncSession); the portal
proxies that VNC stream.
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager, suppress

import requests
from selenium import webdriver
from selenium.webdriver.chromium.remote_connection import ChromiumRemoteConnection

LOGGER = logging.getLogger(__name__)
SHARE_DIR = os.getenv("BROWSER_SHARE_DIR", "/tmp/browser-share")


def isolation_enabled() -> bool:
    return (os.getenv("BROWSER_ISOLATION") or "").strip().lower() in ("1", "true", "yes", "on")


def _agent_url() -> str:
    return os.getenv("BROWSER_AGENT_URL", "http://authrecon-browser:9500").rstrip("/")


def _headers() -> dict[str, str]:
    token = os.getenv("BROWSER_AGENT_TOKEN") or ""
    if len(token) < 32:
        raise RuntimeError("BROWSER_ISOLATION is on but BROWSER_AGENT_TOKEN is not set (see ADMIN_GUIDE.md)")
    return {"X-Browser-Token": token}


# The agent display a run's live view uses (set by vnc_session.live_view);
# browsers started meanwhile render there. Each RQ job is its own process.
_current_display: str | None = None


def current_display() -> str | None:
    return _current_display


def start_session(engine: str) -> dict:
    try:
        resp = requests.post(f"{_agent_url()}/sessions", json={"engine": engine, "display": _current_display},
                             headers=_headers(), timeout=30)
    except requests.RequestException as exc:
        raise RuntimeError(
            "BROWSER_ISOLATION is on but the browser container (authrecon-browser) is not reachable. Start it with "
            "the browser-isolation profile (see ADMIN_GUIDE.md).") from exc
    if resp.status_code != 200:
        raise RuntimeError(f"Browser agent could not start a {engine} session: HTTP {resp.status_code} {resp.text[:200]}")
    return resp.json()


def stop_session(session_id: str | None) -> None:
    if not session_id:
        return
    with suppress(Exception):
        requests.delete(f"{_agent_url()}/sessions/{session_id}", headers=_headers(), timeout=10)


class RemoteChrome(webdriver.Remote):
    """A Chrome driven through the agent's chromedriver; quit() ends the agent session."""

    agent_session_id: str | None = None

    def get_log(self, log_type: str):
        return self.execute("getLog", {"type": log_type})["value"]

    def quit(self) -> None:
        try:
            super().quit()
        finally:
            stop_session(self.agent_session_id)
            self.agent_session_id = None


def create_remote_chrome(options) -> RemoteChrome:
    session = start_session("selenium")
    try:
        conn = ChromiumRemoteConnection(session["webdriver_url"], vendor_prefix="goog", browser_name="chrome",
                                        ignore_proxy=True)
        driver = RemoteChrome(command_executor=conn, options=options)
    except Exception:
        stop_session(session["session_id"])
        raise
    driver.agent_session_id = session["session_id"]
    return driver


async def connect_playwright(playwright, **launch_kwargs):
    """A Chromium on the agent's Playwright server, launched with ``launch_kwargs``.
    Returns the Browser; closing it ends the agent session. Files the browser
    writes (record_har_path) must be under SHARE_DIR, which the worker shares."""
    session = start_session("playwright")
    try:
        browser = await playwright.chromium.connect(
            session["ws_endpoint"],
            headers={"x-playwright-launch-options": json.dumps(launch_kwargs)},
            timeout=30000,
        )
    except Exception:
        stop_session(session["session_id"])
        raise
    def _on_disconnect(*_):
        finalize_remote_hars()
        stop_session(session["session_id"])

    browser.on("disconnected", _on_disconnect)
    return browser


def browser_tmp_dir() -> str:
    """Where browser-written files (Playwright HARs) go: the volume shared with
    authrecon-browser when isolated, else the local temp directory."""
    if isolation_enabled():
        os.makedirs(SHARE_DIR, exist_ok=True)
        return SHARE_DIR
    import tempfile

    return tempfile.gettempdir()


def finalize_remote_hars() -> None:
    """A remote Playwright server leaves each HAR as `<path>.tmp`, a zip holding
    `har.har`, and skips the unzip a local Playwright does. Finish that step so
    the pattern code finds `<path>` as usual."""
    import zipfile
    from pathlib import Path

    for tmp in Path(SHARE_DIR).glob("*.har.tmp"):
        final = tmp.with_suffix("")  # x.har.tmp -> x.har
        try:
            if zipfile.is_zipfile(tmp):
                with zipfile.ZipFile(tmp) as zf:
                    member = next((n for n in zf.namelist() if n.endswith(".har")), None)
                    if member:
                        final.write_bytes(zf.read(member))
            else:
                tmp.replace(final)
                continue
        except Exception:
            LOGGER.warning("Could not finish HAR %s", tmp, exc_info=True)
        with suppress(FileNotFoundError):
            tmp.unlink()


class RemoteVncSession:
    """Same interface as vnc_session.VncSession, but the display, x11vnc and
    websockify run in the browser container (agent POST /displays)."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self._info: dict | None = None

    def start(self):
        try:
            resp = requests.post(f"{_agent_url()}/displays", json={"run_id": self.run_id}, headers=_headers(), timeout=60)
        except requests.RequestException as exc:
            raise RuntimeError("The browser container (authrecon-browser) is not reachable for the live view.") from exc
        if resp.status_code != 200:
            raise RuntimeError(f"Live view did not start in the browser container: {resp.text[:200]}")
        self._info = resp.json()
        return self._info

    @property
    def display(self) -> str:
        return self._info["display"]

    @property
    def novnc_port(self) -> int:
        return int(self._info["novnc_port"])

    def stop(self) -> None:
        if self._info:
            with suppress(Exception):
                requests.delete(f"{_agent_url()}/displays/{self._info['display_id']}", headers=_headers(), timeout=15)
            self._info = None


@contextmanager
def use_display(display: str):
    """Browsers started inside this block render on the agent's ``display``."""
    global _current_display
    previous, _current_display = _current_display, display
    try:
        yield
    finally:
        _current_display = previous
