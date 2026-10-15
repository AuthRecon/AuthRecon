"""The workflow tools (detect, credentials, wait, WAS setup, timeline,
artifacts, verify) return only what they document: never usernames,
secrets, cookies or file contents."""
from __future__ import annotations

import httpx
import pytest

import app as mcp_app
from test_auth import FakeApi, _call_tool  # noqa: F401
from test_auth import api, client  # noqa: F401  (fixtures)

CREDS = [
    {"id": "c1", "name": "Staging admin", "description": None, "auth_type": "form", "username": "alice@corp.test",
     "additional_fields": {"secret": "x"}, "last_used_at": None, "is_archived": False},
    {"id": "c2", "name": "Old", "username": "bob", "is_archived": True},
]
SETUP = {"method": "selenium", "login_url": "https://t.invalid/login", "page_to_verify": "https://t.invalid/home",
         "pattern_regex": "Welcome", "scripts": [{"artifact_id": "a1", "name": "login.side", "verification": None}]}
FINISHED = {"id": "r2", "status": "succeeded", "target_url": "https://t.invalid/login", "auth_type": "form_based",
            "warnings": [], "was_setup": SETUP, "failure": None, "session_cookies": [{"name": "sid", "value": "s3cr3t"}],
            "timeline": [{"occurred_at": "2026-10-14T00:00:00Z", "message": f"step {i}"} for i in range(5)]}
ARTIFACTS = [{"id": "a1", "name": "login.side", "type": "side_file", "size_bytes": 10, "download_url": "/x",
              "role_label": None, "description": "script", "created_at": "2026-10-14T00:00:00Z"}]


@pytest.fixture(autouse=True)
def routes(api, monkeypatch):  # noqa: F811
    seen = []
    original = api.handler

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1")
        seen.append((request.method, path))
        if path == "/credentials":
            return httpx.Response(200, json=CREDS)
        if path == "/runs/r2":
            return httpx.Response(200, json=FINISHED)
        if path == "/runs/r2/artifacts":
            return httpx.Response(200, json=ARTIFACTS)
        if path == "/runs/r2/artifacts/a1/verify" and request.method == "POST":
            return httpx.Response(202, json={"status": "queued"})
        if path == "/runs/detect" and request.method == "POST":
            return httpx.Response(200, json={"auth_type": "two_step_form", "scanner_method": "selenium"})
        return original(request)

    monkeypatch.setattr(mcp_app, "_transport", httpx.MockTransport(handler))
    return seen


def _result(value):
    return value.get("result", value) if isinstance(value, dict) else value


def test_list_credentials_hides_usernames_and_archived(client):  # noqa: F811
    creds = _result(_call_tool(client, "list_credentials"))
    assert [c["id"] for c in creds] == ["c1"]
    assert "username" not in creds[0] and "alice" not in str(creds)


def test_wait_and_was_setup_return_only_scan_settings(client):  # noqa: F811
    for tool in ("wait_for_run", "get_was_setup"):
        out = _call_tool(client, tool, {"run_id": "r2"})
        assert out["was_setup"]["page_to_verify"] == "https://t.invalid/home"
        assert "s3cr3t" not in str(out) and "session_cookies" not in out


def test_timeline_is_limited(client):  # noqa: F811
    events = _result(_call_tool(client, "get_run_timeline", {"run_id": "r2", "limit": 2}))
    assert [e["message"] for e in events] == ["step 3", "step 4"]


def test_artifacts_are_listed_without_contents_or_links(client):  # noqa: F811
    rows = _result(_call_tool(client, "list_artifacts", {"run_id": "r2"}))
    assert rows[0]["name"] == "login.side" and "download_url" not in rows[0]


def test_verify_and_detect_call_the_api(client, routes):  # noqa: F811
    assert _call_tool(client, "verify_script", {"run_id": "r2", "artifact_id": "a1"})["status"] == "queued"
    assert _call_tool(client, "detect_auth", {"target_url": "https://t.invalid/login"})["auth_type"] == "two_step_form"
    assert ("POST", "/runs/r2/artifacts/a1/verify") in routes and ("POST", "/runs/detect") in routes
