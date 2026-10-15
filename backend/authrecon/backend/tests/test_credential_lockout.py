"""A login the target explicitly rejects must not be retried: resubmitting the
same credentials is how AD-style lockout policies get tripped. Transient
failures (timeouts, page not ready) still retry."""
from __future__ import annotations

import pytest


def _variant():
    from app.worker import RoleVariant

    return RoleVariant(index=0, label="admin", username="user", password="pw",
                       auth_hint="", tags=[], slug="admin")


@pytest.fixture()
def form_env(monkeypatch):
    import app.services.learning as learning
    import app.worker as worker

    monkeypatch.setattr(learning, "lookup_playbook", lambda **_kw: None)
    monkeypatch.setattr(worker.time, "sleep", lambda _s: None)
    monkeypatch.setattr(worker, "_fetch_pre_auth_html", lambda _url: "")
    return worker


def _run(worker, db_session, make_run, exc):
    calls = []

    def fake_login(*_a, **_kw):
        calls.append(1)
        raise exc

    worker.run_form_login = fake_login
    run, _ = make_run()
    result = worker._run_form_variant(run, _variant(), storage=None, db=db_session, multi_role=False)
    return calls, result


def test_rejected_credentials_are_tried_once(form_env, db_session, make_run, monkeypatch):
    from app.services.automation import CredentialRejected

    monkeypatch.setattr(form_env, "run_form_login", None)
    calls, result = _run(form_env, db_session, make_run, CredentialRejected("Login failed: invalid credentials"))
    assert len(calls) == 1
    assert not result.success
    assert any("not retrying" in e.message for e in result.events)


def test_transient_failures_still_retry(form_env, db_session, make_run, monkeypatch):
    monkeypatch.setattr(form_env, "run_form_login", None)
    calls, result = _run(form_env, db_session, make_run, RuntimeError("Timed out waiting for login to complete."))
    assert len(calls) == 3
    assert not result.success


def test_two_step_rejection_is_tried_once(db_session, make_run, monkeypatch):
    import app.services.automation.patterns.two_step_form as two_step
    import app.worker as worker
    from app.services.automation import CredentialRejected

    calls = []

    def fake_two_step(*_a, **_kw):
        calls.append(1)
        raise CredentialRejected("Authentication failed: Invalid credentials")

    monkeypatch.setattr(two_step, "run_two_step_form_login", fake_two_step)
    monkeypatch.setattr(worker.time, "sleep", lambda _s: None)
    run, _ = make_run()
    result = worker._run_two_step_variant(run, _variant(), storage=None, db=db_session, multi_role=False)
    assert len(calls) == 1
    assert not result.success


@pytest.mark.parametrize("text", [
    "Invalid username or password.",
    "Your password is invalid!",
    "Login failed",
    "Email and password don't match",
    "Incorrect user ID or password",
    "The username or password you entered is incorrect.",
])
def test_rejection_messages_are_recognised(text):
    from app.services.automation.patterns.form_login import is_credential_rejection_text

    assert is_credential_rejection_text(text)


@pytest.mark.parametrize("text", [
    "Password must be 12 characters", "Forgot your password?", "Welcome back",
    "Enter a valid email", "Password is required", "", None,
])
def test_ordinary_page_text_is_not_a_rejection(text):
    from app.services.automation.patterns.form_login import is_credential_rejection_text

    assert not is_credential_rejection_text(text)
