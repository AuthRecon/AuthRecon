"""Browser isolation plumbing: the agent's token check, and which browsers go remote."""
from __future__ import annotations

import asyncio
import importlib
import os
import subprocess
import sys

import pytest


def test_agent_refuses_to_start_without_a_token():
    env = {k: v for k, v in os.environ.items() if k != "BROWSER_AGENT_TOKEN"}
    proc = subprocess.run([sys.executable, "-c", "import browser_agent.agent"], env=env,
                          cwd=os.path.dirname(os.path.dirname(__file__)), capture_output=True, text=True)
    assert proc.returncode != 0 and "BROWSER_AGENT_TOKEN" in (proc.stderr + proc.stdout)


@pytest.fixture()
def agent(monkeypatch):
    monkeypatch.setenv("BROWSER_AGENT_TOKEN", "t" * 40)
    import browser_agent.agent as mod
    mod = importlib.reload(mod)
    from fastapi.testclient import TestClient
    return TestClient(mod.app)


def test_agent_requires_its_token(agent):
    assert agent.get("/health").status_code == 200
    assert agent.post("/sessions", json={"engine": "selenium"}).status_code == 401
    assert agent.post("/sessions", json={"engine": "selenium"}, headers={"X-Browser-Token": "wrong"}).status_code == 401
    assert agent.post("/sessions", json={"engine": "firefox"}, headers={"X-Browser-Token": "t" * 40}).status_code == 400
    assert agent.delete("/sessions/abc", headers={"X-Browser-Token": "t" * 40}).json() == {"stopped": False}


def test_headless_selenium_goes_remote_only_when_isolated(monkeypatch):
    from app.services.automation import browser, remote_browser

    made = []
    monkeypatch.setattr(remote_browser, "create_remote_chrome", lambda opts: made.append(opts) or _FakeDriver())
    monkeypatch.setattr(browser, "harden_driver", lambda d: None)
    monkeypatch.setattr(browser.webdriver, "Chrome", lambda **kw: "local")
    monkeypatch.delenv("BROWSER_ISOLATION", raising=False)
    assert browser.create_webdriver(browser.create_chrome_options(headless=True)) == "local"
    monkeypatch.setenv("BROWSER_ISOLATION", "true")
    assert isinstance(browser.create_webdriver(browser.create_chrome_options(headless=True)), _FakeDriver)
    assert browser.create_webdriver(browser.create_chrome_options(headless=False)) == "local"  # live view stays local
    assert len(made) == 1


class _FakeDriver:
    pass


def test_playwright_launch_goes_remote_only_for_headless(monkeypatch):
    from app.services.automation import playwright_guard, remote_browser

    calls = []

    async def fake_connect(p, **kw):
        calls.append(("connect", kw))
        return "remote"

    class _Chromium:
        async def launch(self, **kw):
            calls.append(("launch", kw))
            return "local"

    class _P:
        chromium = _Chromium()

    monkeypatch.setattr(remote_browser, "connect_playwright", fake_connect)
    monkeypatch.setenv("BROWSER_ISOLATION", "on")
    assert asyncio.run(playwright_guard.launch_chromium(_P(), headless=True)) == "remote"
    assert asyncio.run(playwright_guard.launch_chromium(_P(), headless=False)) == "local"
    monkeypatch.setenv("BROWSER_ISOLATION", "false")
    assert asyncio.run(playwright_guard.launch_chromium(_P(), headless=True)) == "local"


def test_browser_tmp_dir(monkeypatch, tmp_path):
    from app.services.automation import remote_browser

    monkeypatch.setattr(remote_browser, "SHARE_DIR", str(tmp_path / "share"))
    monkeypatch.setenv("BROWSER_ISOLATION", "true")
    assert remote_browser.browser_tmp_dir() == str(tmp_path / "share")
    monkeypatch.setenv("BROWSER_ISOLATION", "false")
    assert remote_browser.browser_tmp_dir() != str(tmp_path / "share")


def test_missing_agent_token_is_a_clear_error(monkeypatch):
    from app.services.automation import remote_browser

    monkeypatch.delenv("BROWSER_AGENT_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="BROWSER_AGENT_TOKEN"):
        remote_browser.start_session("selenium")


def test_finalize_remote_hars(monkeypatch, tmp_path):
    import io
    import json
    import zipfile

    from app.services.automation import remote_browser

    monkeypatch.setattr(remote_browser, "SHARE_DIR", str(tmp_path))
    har = {"log": {"entries": [{"request": {"url": "https://a.example/"}}]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("har.har", json.dumps(har))
    (tmp_path / "RUN-1-playwright.har.tmp").write_bytes(buf.getvalue())
    (tmp_path / "RUN-2-plain.har.tmp").write_text(json.dumps(har))
    remote_browser.finalize_remote_hars()
    assert json.loads((tmp_path / "RUN-1-playwright.har").read_text()) == har
    assert json.loads((tmp_path / "RUN-2-plain.har").read_text()) == har
    assert not list(tmp_path.glob("*.tmp"))
