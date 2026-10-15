"""Replay check for .side scripts, and the WAS-setup / failure-guidance data
shown on the run page and returned to MCP clients."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.api.deps import get_current_active_profile
from app.db import get_db

from test_ai_and_scan_exports import _Client

SECRET = "Pw-not-in-results!"


class _Element:
    def __init__(self, page):
        self.page = page

    def clear(self):
        pass

    def send_keys(self, value):
        self.page.typed.append(value)

    def click(self):
        self.page.current_url = self.page.after_click

    @property
    def text(self):
        return self.page.body


class _Driver:
    def __init__(self, after_click="https://app.test/home", missing=(), body="Welcome, Test User"):
        self.current_url = "about:blank"
        self.after_click, self.missing, self.body, self.typed = after_click, set(missing), body, []

    def get(self, url):
        self.current_url = url

    def find_element(self, by, value):
        if value in self.missing:
            raise Exception(f"no such element: {value}")
        return _Element(self)


@pytest.fixture(autouse=True)
def _visible(monkeypatch):
    # WebDriverWait/visibility against the fake driver: present unless "missing".
    import selenium.webdriver.support.ui as ui

    class _Wait:
        def __init__(self, driver, timeout):
            self.driver = driver

        def until(self, _cond):
            return True

    monkeypatch.setattr(ui, "WebDriverWait", _Wait)


def _side(verify="https://app.test/home"):
    return {
        "tests": [{"commands": [
            {"command": "open", "target": "https://app.test/login", "value": ""},
            {"command": "type", "target": "css=#user", "value": "alice"},
            {"command": "type", "target": "css=#pass", "value": SECRET},
            {"command": "click", "target": "css=#go", "value": ""},
        ]}],
        "plugins": [{"config": {"pageToVerify": verify}}],
    }


def test_replay_passes_when_it_lands_on_the_verify_page():
    from app.services.side_replay import replay_side

    result = replay_side(_Driver(), _side(), pattern="Welcome, Test User", sleep=lambda _s: None)
    assert result["status"] == "passed" and result["url_matched"] and result["pattern_found"]


def test_replay_reports_the_broken_step_without_credentials():
    from app.services.side_replay import replay_side

    result = replay_side(_Driver(missing={"#pass"}), _side(), sleep=lambda _s: None)
    assert result["status"] == "failed" and result["failed_step"] == 3
    assert result["step"] == "type css=#pass"
    assert SECRET not in str(result)


def test_replay_fails_when_it_ends_on_the_wrong_page():
    from app.services.side_replay import replay_side

    result = replay_side(_Driver(after_click="https://app.test/login?error=1"), _side(), sleep=lambda _s: None)
    assert result["status"] == "failed" and result["url_matched"] is False


# --- endpoint ---------------------------------------------------------------------

@pytest.fixture()
def side_run(db_session, make_run, monkeypatch):
    from app.models import Artifact
    from app.services import queue as queue_module

    enqueued = []

    class _Queue:
        def enqueue(self, *a, **kw):
            enqueued.append(a)

    monkeypatch.setattr(queue_module, "get_queue", lambda *_a, **_kw: _Queue())
    run, owner = make_run()
    db_session.add(Artifact(id=f"{run.id[:8]}-side", run_id=run.id, name="login.side", type="side_file",
                            size_bytes=1, storage_path="x", created_at=datetime.now(timezone.utc)))
    db_session.commit()
    return run, owner, enqueued


def _client(db_session, profile):
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = lambda: profile
    return _Client(app)


def test_owner_can_queue_a_replay_once(db_session, side_run):
    run, owner, enqueued = side_run
    owner.is_admin = False
    client = _client(db_session, owner)
    url = f"/api/v1/runs/{run.id}/artifacts/{run.id[:8]}-side/verify"
    assert client.request("POST", url).json()["status"] == "queued"
    assert client.request("POST", url).json()["status"] == "queued"  # not queued twice
    assert len(enqueued) == 1


def test_other_user_cannot_queue_a_replay(db_session, side_run):
    from app.services.profiles import sync_portal_profile

    run, _owner, enqueued = side_run
    other = sync_portal_profile(db_session, str(uuid.uuid4()))
    other.is_admin = False
    resp = _client(db_session, other).request("POST", f"/api/v1/runs/{run.id}/artifacts/{run.id[:8]}-side/verify")
    assert resp.status_code == 403 and not enqueued


# --- WAS setup / failure guidance -----------------------------------------------------

def test_was_setup_for_a_successful_form_run(db_session, side_run):
    from app.services.side_replay import set_verification
    from app.services.was_setup import build_was_setup

    run, _owner, _ = side_run
    run.auth_type, run.final_url, run.pattern = "form_based", "https://u:p@target.invalid/home", "✅ Welcome, Test User"
    set_verification(run, f"{run.id[:8]}-side", {"status": "passed"})
    setup = build_was_setup(run)
    assert setup["method"] == "selenium"
    assert setup["page_to_verify"] == "https://target.invalid/home"  # no credentials in URLs
    assert setup["pattern_regex"] == "Welcome, Test User"
    assert setup["scripts"][0]["verification"]["status"] == "passed"


def test_basic_auth_points_to_http_auth_settings(db_session, make_run):
    from app.services.was_setup import build_was_setup

    run, _ = make_run()
    run.auth_type = "basic_auth"
    assert build_was_setup(run)["method"] == "http_auth"


@pytest.mark.parametrize("error,category", [
    ("Login failed: invalid credentials", "credentials_rejected"),
    ("Unable to locate a password field on the login page.", "fields_not_found"),
    ("Target appears unreachable - network timeout", "unreachable"),
    ("something odd", "unknown"),
])
def test_failure_guidance_categories(db_session, make_run, error, category):
    from app.services.was_setup import build_failure_guidance

    run, _ = make_run()
    run.status, run.error_message = "failed", error
    guidance = build_failure_guidance(run)
    assert guidance["category"] == category and guidance["next_steps"]


@pytest.mark.parametrize("text,expected", [
    ("You logged into a secure area! ×", "You logged into a secure area!"),
    ("✅ Authenticated - Form Login", "Authenticated - Form Login"),
    ("Total (2) items: $5.00", r"Total \(2\) items: \$5\.00"),
    ("", None),
])
def test_pattern_regex_is_clean_and_literal(text, expected):
    import re

    from app.services.was_setup import pattern_regex

    result = pattern_regex(text)
    assert result == expected
    if result:
        assert re.search(result, text)
