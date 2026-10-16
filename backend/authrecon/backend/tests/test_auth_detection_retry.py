"""Submit-time detection probe: retry the submitted URL once on a timeout."""
from __future__ import annotations

import pytest
import requests

from app.services import auth_detection as det


class FakeSession:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self.headers = {}
        self.hooks = {"response": []}

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        outcome = self.outcomes.pop(0) if self.outcomes else requests.ReadTimeout("Read timed out.")
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def test_timeout_then_success_returns_response_and_reports_retry():
    ok = object()
    session = FakeSession([requests.ReadTimeout("Read timed out."), ok])
    retried = []
    resp = det._get_with_timeout_retry(
        session, "https://target.invalid/", timeout=10, retries=1, on_retry=lambda: retried.append(1)
    )
    assert resp is ok
    assert len(session.calls) == 2 and retried == [1]
    assert session.calls[0][1] == {"timeout": 10, "allow_redirects": True}


def test_second_timeout_is_raised():
    session = FakeSession([requests.ConnectTimeout("connect timeout"), requests.ReadTimeout("read timeout")])
    with pytest.raises(requests.Timeout):
        det._get_with_timeout_retry(session, "https://target.invalid/", timeout=10, retries=1)
    assert len(session.calls) == 2


def test_non_timeout_errors_are_not_retried():
    session = FakeSession([requests.ConnectionError("Connection refused")])
    with pytest.raises(requests.ConnectionError):
        det._get_with_timeout_retry(session, "https://target.invalid/", timeout=10, retries=1)
    assert len(session.calls) == 1


def test_zero_retries_means_single_attempt():
    session = FakeSession([requests.ReadTimeout("t")])
    with pytest.raises(requests.Timeout):
        det._get_with_timeout_retry(session, "https://target.invalid/login", timeout=5, retries=0)
    assert len(session.calls) == 1


def test_detect_auth_type_retries_submitted_url_once_then_records_error(monkeypatch):
    session = FakeSession([requests.ReadTimeout("Read timed out."), requests.ReadTimeout("Read timed out.")])
    monkeypatch.setattr(det.requests, "Session", lambda: session)

    result = det.detect_auth_type("https://target.invalid/app")

    submitted = [c for c in session.calls if c[0] == "https://target.invalid/app"]
    assert len(submitted) == 2  # one retry, then give up
    assert len(session.calls) == 2  # no guessed paths after the submitted URL failed
    assert result.error and "timed out" in result.error.lower()
    signal_types = [s.get("type") for s in result.signals]
    assert "timeout_retry" in signal_types and "early_termination" in signal_types
