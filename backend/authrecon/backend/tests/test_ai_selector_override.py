#!/usr/bin/env python3
"""
Unit tests for _build_ai_selector_override (worker.py) — the function that
converts an AI-recorded selector suggestion (see app/api/ai_assist.py) into
the playbook_selectors shape run_form_login() already knows how to consume.
No browser, no DB, no running services required.
"""
from app.worker import _build_ai_selector_override


class FakeRun:
    def __init__(self, options):
        self.options = options


def test_no_suggestions():
    assert _build_ai_selector_override(FakeRun({})) is None
    assert _build_ai_selector_override(FakeRun({"ai_suggestions": []})) is None


def test_missing_password_selector():
    run = FakeRun({"ai_suggestions": [{"username_selector": "#u", "submit_selector": "#go"}]})
    assert _build_ai_selector_override(run) is None


def test_valid_suggestion_returns_correct_shape():
    run = FakeRun(
        {
            "ai_suggestions": [
                {"username_selector": "#u1", "password_selector": "#p1", "submit_selector": "#go1"},
            ]
        }
    )
    result = _build_ai_selector_override(run)
    assert result == {
        "username_selector": "#u1",
        "password_selector": "#p1",
        "submit_selector": "#go1",
        "is_generic": False,
    }


def test_uses_most_recent_suggestion_when_multiple():
    run = FakeRun(
        {
            "ai_suggestions": [
                {"username_selector": "#old", "password_selector": "#old_p", "submit_selector": "#old_go"},
                {"username_selector": "#new", "password_selector": "#new_p", "submit_selector": "#new_go"},
            ]
        }
    )
    result = _build_ai_selector_override(run)
    assert result["password_selector"] == "#new_p"
    assert result["username_selector"] == "#new"


if __name__ == "__main__":
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:  # noqa: BLE001 — test runner, not app code
            failures += 1
            print(f"FAIL {test.__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    raise SystemExit(1 if failures else 0)
