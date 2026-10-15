"""The scanner's "pattern to verify": visible after login, absent from the
login page, never invented."""
from __future__ import annotations

import pytest

from app.services.verify_pattern import choose_verify_pattern, is_placeholder

LOGIN = """<html><head><title>Acme Portal</title></head><body>
<h1>Acme Portal</h1><form><input name="u"><input type="password" name="p">
<button type="submit">Sign in</button></form></body></html>"""

DASH = """<html><head><title>Acme Portal</title><script>var s = "Welcome back";</script></head><body>
<h1>Acme Portal</h1><h2>Welcome back, Jane</h2><nav><a href="/logout">Log out</a></nav></body></html>"""


def test_real_success_text_is_kept():
    assert choose_verify_pattern(["Welcome back, Jane"], DASH, LOGIN) == "Welcome back, Jane"


@pytest.mark.parametrize("placeholder", ["Authenticated page", "Two-step authentication successful", "Authenticated"])
def test_placeholders_are_never_used(placeholder):
    assert is_placeholder(placeholder)
    # Falls through to real page text instead.
    assert choose_verify_pattern([placeholder], DASH, LOGIN) == "Log out"


def test_text_shared_with_the_login_page_is_rejected():
    # The site name is on both pages: a failed login would still "match".
    assert choose_verify_pattern(["Acme Portal"], DASH, LOGIN) == "Log out"


def test_text_only_in_title_or_script_is_not_visible():
    page = "<html><head><title>Dashboard</title></head><body><p>Hi Jane</p></body></html>"
    assert choose_verify_pattern(["Dashboard"], page, LOGIN) is None


def test_heading_used_when_there_is_no_logout_control():
    page = "<html><body><h1>Acme Portal</h1><h2>Your projects</h2></body></html>"
    assert choose_verify_pattern([None], page, LOGIN) == "Your projects"


def test_sign_out_input_button_is_found():
    page = '<html><body><form><input type="submit" value="Sign Out"></form><p>Sign Out of Acme</p></body></html>'
    assert choose_verify_pattern([], page, LOGIN) == "Sign Out"


def test_nothing_qualifies_returns_none():
    assert choose_verify_pattern(["Acme Portal"], LOGIN, LOGIN) is None


def test_without_html_a_real_candidate_is_still_used():
    assert choose_verify_pattern(["Welcome, Jane"], None, None) == "Welcome, Jane"
    assert choose_verify_pattern(["Authenticated page"], None, None) is None


def test_was_setup_flags_a_missing_pattern(db_session, make_run):
    from app.services.was_setup import build_was_setup

    run, _ = make_run()
    run.auth_type, run.final_url, run.pattern = "form_based", "https://target.invalid/home", None
    setup = build_was_setup(run)
    assert setup["pattern_missing"] is True
    assert any("No reliable success text" in n for n in setup["notes"])

    run.pattern = "Welcome, Jane"
    setup = build_was_setup(run)
    assert setup["pattern_missing"] is False
    assert not any("No reliable success text" in n for n in setup["notes"])
