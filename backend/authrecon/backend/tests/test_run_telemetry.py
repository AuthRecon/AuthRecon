"""Run telemetry and playbook accuracy: live timeline timestamps, playbook
counting and learned selectors, API-key attribution, honest discovery notes,
pre-login detection URL, and one name for manual sessions."""
from __future__ import annotations

import time
import uuid

import pytest
from sqlalchemy import select

from app.api.deps import get_current_active_profile
from app.db import get_db

from test_ai_and_scan_exports import _Client


def _timeline(db_session, run_id):
    from app.models import TimelineEvent

    fresh = db_session.factory()  # a separate session sees only committed rows
    try:
        rows = fresh.scalars(
            select(TimelineEvent).where(TimelineEvent.run_id == run_id).order_by(TimelineEvent.id)
        ).all()
        return [(r.occurred_at, r.message) for r in rows]
    finally:
        fresh.close()


# --- 1. live timeline -------------------------------------------------------------


def test_handler_messages_are_written_as_they_happen(db_session, make_run):
    from app.services.live_timeline import event_prefix, live_events, live_timeline, not_yet_written

    run, _ = make_run()
    with live_timeline(run.id, session_factory=db_session.factory), event_prefix("[admin] "):
        events = live_events()
        events.append("Loaded login page")
        assert [m for _, m in _timeline(db_session, run.id)] == ["[admin] Loaded login page"]  # visible already
        time.sleep(0.01)
        events.append("Submitted credentials")

    rows = _timeline(db_session, run.id)
    assert [m for _, m in rows] == ["[admin] Loaded login page", "[admin] Submitted credentials"]
    assert rows[0][0] < rows[1][0]  # real, increasing timestamps
    assert list(events) == ["Loaded login page", "Submitted credentials"]  # handler still sees its messages
    assert not_yet_written(events) == []  # worker won't record them twice


def test_outside_a_run_nothing_is_written(db_session, make_run):
    from app.services.live_timeline import live_events, not_yet_written

    run, _ = make_run()
    events = live_events()
    events.append("x")
    assert _timeline(db_session, run.id) == []
    assert not_yet_written(events) == ["x"]


def test_failures_keep_the_live_list(db_session, make_run):
    from app.services.automation.types import AutomationFailure
    from app.services.live_timeline import live_events, live_timeline, not_yet_written

    run, _ = make_run()
    with live_timeline(run.id, session_factory=db_session.factory):
        events = live_events()
        events.append("Timed out waiting for login to complete")
        failure = AutomationFailure("timeout", events=events)
    assert not_yet_written(failure.events) == []


def test_worker_role_events_are_written_live_and_not_saved_twice(db_session, make_run):
    from app.services.live_timeline import live_timeline
    from app.worker import RoleVariant, _make_role_event, _not_written_live

    run, _ = make_run()
    variant = RoleVariant(index=0, label="admin", username="u", password="p", auth_hint="form_based", tags=[], slug="admin")
    with live_timeline(run.id, session_factory=db_session.factory):
        live = _make_role_event(run.id, variant, "Starting automation", multi_role=True)
    later = _make_role_event(run.id, variant, "Run completed", multi_role=True)
    assert [m for _, m in _timeline(db_session, run.id)] == ["[admin] Starting automation"]
    assert _not_written_live([live, later]) == [later]


def test_navigation_notes_are_written_live(db_session, make_run):
    from app.services.automation.navigation import drain_notes, record_note
    from app.services.live_timeline import live_timeline

    run, _ = make_run()
    drain_notes()
    with live_timeline(run.id, session_factory=db_session.factory):
        record_note("Retrying with HTTP/2 disabled")
    assert [m for _, m in _timeline(db_session, run.id)] == ["Retrying with HTTP/2 disabled"]
    assert drain_notes() == []


# --- 2/3. playbooks ---------------------------------------------------------------


REAL = {"username_selector": "#username", "password_selector": "#password", "submit_selector": "button.radius"}


def _succeeded(run, auth_type="form_based"):
    from app.models.run import RunStatus

    run.status = RunStatus.succeeded
    run.auth_type = auth_type
    return run


def test_learning_keeps_the_selectors_the_login_used(db_session, make_run):
    from app.services.learning import learn_from_successful_run

    run, profile = make_run()
    playbook = learn_from_successful_run(_succeeded(run), db_session, profile.id, selectors=dict(REAL))
    assert playbook.selectors["username_selector"] == "#username"
    assert not playbook.selectors.get("is_generic")


def test_a_success_is_counted_once(db_session, make_run):
    from app.services.learning import learn_from_successful_run, record_playbook_usage

    run, profile = make_run()
    playbook = learn_from_successful_run(_succeeded(run), db_session, profile.id, selectors=dict(REAL))
    assert playbook.success_count == 1
    # Next run: one timed-out attempt, then success with the playbook (worker records both)
    record_playbook_usage(playbook, success=False, db=db_session)
    record_playbook_usage(playbook, success=True, db=db_session)
    run2, _ = make_run(portal_user_id=profile.portal_user_id)
    learn_from_successful_run(_succeeded(run2), db_session, profile.id, selectors=dict(REAL), success_already_recorded=True)
    db_session.refresh(playbook)
    assert (playbook.success_count, playbook.failure_count) == (2, 1)


def test_generic_selectors_never_replace_real_ones(db_session, make_run):
    from app.services.learning import learn_from_successful_run

    run, profile = make_run()
    playbook = learn_from_successful_run(_succeeded(run), db_session, profile.id, selectors=dict(REAL))
    run2, _ = make_run(portal_user_id=profile.portal_user_id)
    learn_from_successful_run(_succeeded(run2), db_session, profile.id, selectors=None)  # falls back to generic
    db_session.refresh(playbook)
    assert playbook.selectors["username_selector"] == "#username"


def test_lookup_matches_auth_type_aliases(db_session, make_run):
    from app.services.learning import canonical_auth_type, learn_from_successful_run, lookup_playbook

    run, profile = make_run()
    learn_from_successful_run(_succeeded(run, "form_auth"), db_session, profile.id, selectors=dict(REAL))
    assert canonical_auth_type("form_post") == "form_based"
    found = lookup_playbook(run.target_url, "form_based", db_session, profile_id=profile.id)
    assert found is not None and found.auth_type == "form_based"


# --- 4/7. attribution and manual naming ---------------------------------------------


@pytest.fixture()
def api(db_session):
    from app.main import create_app
    from app.services.profiles import sync_portal_profile

    profile = sync_portal_profile(db_session, str(uuid.uuid4()))
    profile.display_name = "alice"
    db_session.commit()
    app = create_app()
    current = {"auth_method": "api_key"}

    def _profile():
        profile.is_admin = False
        profile.auth_method = current["auth_method"]
        profile.username = profile.display_name if current["auth_method"] == "api_key" else "alice"
        return profile

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = _profile
    return _Client(app), profile, current


def _start_manual(client, headers=None):
    return client.request("POST", "/api/v1/runs", headers=headers or {},
                          json={"target_url": "https://t.invalid/login", "recording_mode": "manual"})


@pytest.mark.parametrize("header,expected", [
    ({"X-AuthRecon-Client": "mcp"}, "alice (via MCP)"),
    ({}, "alice (via API key)"),
])
def test_api_key_runs_are_attributed_to_the_key_owner(api, db_session, header, expected):
    from app.models import Run

    client, profile, _ = api
    resp = _start_manual(client, header)
    assert resp.status_code == 202, resp.text
    run = db_session.get(Run, resp.json()["id"])
    assert run.operator == "alice"
    assert run.options["submitted_via"] in ("MCP", "API key")
    assert any(expected in m for _, m in _timeline(db_session, run.id))


def test_web_ui_runs_have_no_channel_label(api, db_session):
    from app.models import Run

    client, _, current = api
    current["auth_method"] = "jwt"
    run = db_session.get(Run, _start_manual(client, {"X-AuthRecon-Client": "mcp"}).json()["id"])
    assert "submitted_via" not in run.options
    assert any(m.endswith("by alice") for _, m in _timeline(db_session, run.id))


def test_manual_sessions_use_one_auth_type(api, db_session):
    from app.models import Run

    client, *_ = api
    run = db_session.get(Run, _start_manual(client).json()["id"])
    assert run.auth_type == "manual_recording"


def test_api_key_requests_carry_the_remembered_display_name(db_session):
    from datetime import datetime, timezone

    from app.api.deps import resolve_api_key
    from app.core.security import create_api_key_prefix, generate_api_key, hash_api_key
    from app.models.api_key import APIKey
    from app.services.profiles import sync_portal_profile

    profile = sync_portal_profile(db_session, str(uuid.uuid4()))
    profile.display_name, profile.api_access_enabled = "bob", True
    raw = generate_api_key()
    db_session.add(APIKey(id=str(uuid.uuid4()), profile_id=profile.id, name="k", key_hash=hash_api_key(raw),
                          prefix=create_api_key_prefix(raw), is_revoked=False, created_at=datetime.now(timezone.utc)))
    db_session.commit()
    _key, resolved = resolve_api_key(raw, db_session)
    assert resolved.username == "bob" and resolved.auth_method == "api_key"


# --- 5/6. discovery honesty, pre-login URL ------------------------------------------


def test_discovery_no_longer_claims_unprobed_paths():
    import app.services.automation.pre_run_discovery as discovery

    assert not hasattr(discovery, "_probe_common_endpoints")
    assert "Probed" not in open(discovery.__file__).read()


def test_detection_url_is_labelled_pre_login(api, db_session, make_run):
    client, profile, current = api
    current["auth_method"] = "jwt"
    run, _ = make_run(portal_user_id=profile.portal_user_id)
    run.final_url = "https://t.invalid/secure"
    run.options = {"detected_auth": {"auth_type": "form_based", "final_url": "https://t.invalid/login"}}
    db_session.commit()
    body = client.get(f"/api/v1/runs/{run.id}").json()
    assert body["final_url"] == "https://t.invalid/secure"
    assert body["detected_auth"]["pre_login_url"] == "https://t.invalid/login"
    assert "final_url" not in body["detected_auth"]


def test_ide_locators_become_plain_css():
    from app.services.automation.selectors import plain_css

    assert plain_css("css=input#username") == "input#username"
    assert plain_css("button.radius") == "button.radius"
    assert plain_css("xpath=//input") is None and plain_css("id=user") is None
    assert plain_css("input[name='a=b']") == "input[name='a=b']"
    assert plain_css(None) is None


def test_learning_stores_plain_css(db_session, make_run):
    from app.services.learning import learn_from_successful_run

    run, profile = make_run()
    playbook = learn_from_successful_run(_succeeded(run), db_session, profile.id, selectors={
        "username_selector": "css=input#username", "password_selector": "css=input#password",
        "submit_selector": "css=button.radius", "submit_method": "click"})
    assert playbook.selectors == {"username_selector": "input#username", "password_selector": "input#password",
                                  "submit_selector": "button.radius", "submit_method": "click"}


def test_login_wait_survives_navigation_races(monkeypatch):
    from selenium.common.exceptions import WebDriverException

    import app.services.automation.patterns.form_login as form_login

    calls = iter([
        WebDriverException('unknown error: {"code":-32000,"message":"Node with given id does not belong to the document"}'),
        False,  # form gone: login completed
    ])

    def present(_driver):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(form_login, "_login_form_present", present)
    monkeypatch.setattr(form_login.time, "sleep", lambda _s: None)
    form_login._wait_for_login_completion(object(), timeout_seconds=5)  # no exception


def test_login_wait_still_raises_real_errors(monkeypatch):
    from selenium.common.exceptions import WebDriverException

    import app.services.automation.patterns.form_login as form_login

    def present(_driver):
        raise WebDriverException("chrome not reachable")

    monkeypatch.setattr(form_login, "_login_form_present", present)
    with pytest.raises(WebDriverException):
        form_login._wait_for_login_completion(object(), timeout_seconds=5)


class _El:
    def __init__(self, tag="button", text="", type_="", in_password_form=False, displayed=True):
        self.tag_name, self.text, self._type, self._in_form, self._displayed = tag, text, type_, in_password_form, displayed
        self.clicked = False

    def get_attribute(self, name):
        return {"type": self._type, "aria-label": ""}.get(name)

    def find_elements(self, _by, _xpath):
        return [object()] if self._in_form else []

    def is_displayed(self):
        return self._displayed

    def click(self):
        self.clicked = True


class _Driver:
    def __init__(self, elements, password_visible):
        self.elements, self.password_visible = elements, password_visible

    def find_elements(self, _by, selector):
        if selector == "input[type='password']":
            return [_El(tag="input", displayed=self.password_visible)]
        return self.elements if selector == "button" else []


def test_reveal_never_submits_a_visible_login_form():
    from app.services.automation.pre_run_discovery_click_reveal import _click_reveal_elements

    login_button = _El(text="Login", type_="submit", in_password_form=True)
    _click_reveal_elements(_Driver([login_button], password_visible=True))
    assert not login_button.clicked


def test_reveal_skips_submit_controls_even_when_form_hidden():
    from app.services.automation.pre_run_discovery_click_reveal import _click_reveal_elements

    submit = _El(text="Login", type_="submit")
    reveal = _El(text="Sign in", type_="button")
    _click_reveal_elements(_Driver([submit, reveal], password_visible=False))
    assert not submit.clicked and reveal.clicked
