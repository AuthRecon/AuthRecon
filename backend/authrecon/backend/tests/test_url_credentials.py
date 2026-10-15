"""Basic-auth runs load https://user:pass@host/; that URL must never be stored."""
from __future__ import annotations

import pytest

from app.core.urls import strip_userinfo


@pytest.mark.parametrize("url,expected", [
    ("http://user%40x.local:P%40ss%21@loginlab:5500/basic-auth", "http://loginlab:5500/basic-auth"),
    ("https://u:p@example.com/a?b=1#c", "https://example.com/a?b=1#c"),
    ("https://example.com/login", "https://example.com/login"),
    ("https://example.com/path@notuserinfo", "https://example.com/path@notuserinfo"),
    (None, None),
    ("", ""),
])
def test_strip_userinfo(url, expected):
    assert strip_userinfo(url) == expected


# --- page to verify: no single-use sign-in parameters ----------------------------

import pytest  # noqa: E402

from app.core.urls import stable_page_url  # noqa: E402


@pytest.mark.parametrize("url,expected", [
    ("https://app.example.com/home", "https://app.example.com/home"),
    ("https://app.example.com/callback?code=abc&state=xyz", "https://app.example.com/callback"),
    ("https://app.example.com/cb?code=abc&tab=2&session_state=s", "https://app.example.com/cb?tab=2"),
    ("https://app.example.com/#id_token=eyJ&state=1", "https://app.example.com/"),
    ("https://app.example.com/#/dashboard", "https://app.example.com/#/dashboard"),
    ("https://u:p@app.example.com/?ticket=ST-1", "https://app.example.com/"),
    (None, None),
])
def test_stable_page_url(url, expected):
    assert stable_page_url(url) == expected


def test_was_setup_strips_oauth_code_and_says_so(db_session, make_run):
    from app.services.was_setup import build_was_setup

    run, _ = make_run()
    run.auth_type, run.pattern = "oauth", "Welcome, Jane"
    run.final_url = "https://app.example.com/callback?code=one-time&state=abc"
    setup = build_was_setup(run)
    assert setup["page_to_verify"] == "https://app.example.com/callback"
    assert any("one-time sign-in parameters" in n for n in setup["notes"])


def test_side_file_page_to_verify_has_no_oauth_code():
    import json

    from app.services.side_files import build_two_step_side_file

    side = json.loads(build_two_step_side_file(
        start_url="https://app.example.com/login", recorded_actions=[], username="u", password="p",
        final_url="https://app.example.com/cb?code=one-time"))
    assert side["plugins"][0]["config"]["pageToVerify"] == "https://app.example.com/cb"
