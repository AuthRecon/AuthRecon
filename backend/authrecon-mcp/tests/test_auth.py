"""MCP client auth: per-user AuthRecon API keys, checked against the API gate.

The server holds no credentials. Every request needs the caller's own API key;
the API decides (via /ai/mcp-gate) whether it's valid and MCP is enabled, and
every tool call is made with that same key.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import app as mcp_app  # noqa: E402

KEY_A = "ak_live_" + "a" * 40
KEY_B = "ak_live_" + "b" * 40
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "pytest", "version": "0"}},
}
EXPORT = {"id": "e1", "filename": "was.zip", "status": "parsed", "created_at": "2026-10-02T00:00:00Z",
          "size_bytes": 10, "sha256": "abc", "storage_path": "scan-export-e1/export.zip",
          "owner_profile_id": "p1", "summary": {"file_count": 2}, "error": None}

COOKIE_VALUE = "BAh7CEkiD3Nlc3Npb25faWQGOgZFVEki"  # what a decrypted rack.session looks like
RUN_DETAIL = {
    "id": "r1", "status": "succeeded", "auth_type": "form_based", "final_url": "https://t.invalid/secure",
    "session_cookies": ["rack.session"],  # not in the allow-list at all
    "security_context": {
        "cookies": {"security_score": 70, "cookies": [{
            "name": "rack.session", "value_encrypted": COOKIE_VALUE, "value_hash": "abc", "domain": "t.invalid",
            "path": "/", "secure": False, "http_only": True, "security_issues": ["Missing Secure flag"],
        }]},
        "headers": {"raw": {"Set-Cookie": f"rack.session={COOKIE_VALUE}; path=/", "Server": "nginx"},
                    "security": {"other": {"Authorization": "Bearer abc.def.ghi"}}},
        "jwt": {"raw_token_encrypted": "eyJhbGciOi.payload.sig", "algorithm": "HS256"},
    },
}


class FakeApi:
    """Stands in for authrecon-api; records which key made each call."""

    def __init__(self):
        self.gate_status = 200
        self.calls: list[tuple[str, str]] = []
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down", request=request)
        path = request.url.path.removeprefix("/api/v1")
        self.calls.append((path, request.headers.get("x-api-key", "")))
        if path == "/ai/mcp-gate":
            if self.gate_status == 200:
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(self.gate_status, json={"detail": "nope"})
        if path == "/scan-exports":
            return httpx.Response(200, json=[EXPORT])
        if path == "/scan-exports/e1":
            return httpx.Response(200, json=EXPORT)
        if path == "/runs/r1":
            return httpx.Response(200, json=RUN_DETAIL)
        return httpx.Response(404, json={"detail": "not found"})


@pytest.fixture()
def api(monkeypatch):
    fake = FakeApi()
    monkeypatch.setattr(mcp_app, "_transport", httpx.MockTransport(fake.handler))
    return fake


@pytest.fixture()
def client(api):
    with TestClient(mcp_app.build_http_app()) as c:
        yield c


def _post(client, body, key=KEY_A):
    headers = dict(MCP_HEADERS)
    if key is not None:
        headers["Authorization"] = f"Bearer {key}"
    return client.post("/mcp", json=body, headers=headers)


def _call_tool(client, name, arguments=None, key=KEY_A):
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
    resp = _post(client, body, key)
    assert resp.status_code == 200, resp.text
    result = resp.json()["result"]
    assert not result.get("isError"), result
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


@pytest.mark.parametrize("key", [None, "", "not-an-authrecon-key", "Basic abc"])
def test_requests_without_an_api_key_are_rejected(client, api, key):
    resp = _post(client, INITIALIZE, key=key)
    assert resp.status_code == 401
    assert api.calls == []  # never even asks the API


@pytest.mark.parametrize("gate_status", [401, 403])
def test_gate_rejections_pass_through(client, api, gate_status):
    api.gate_status = gate_status
    assert _post(client, INITIALIZE).status_code == gate_status


def test_valid_key_reaches_mcp(client, api):
    resp = _post(client, INITIALIZE)
    assert resp.status_code == 200
    assert resp.json()["result"]["serverInfo"]["name"] == "authrecon"
    assert api.calls == [("/ai/mcp-gate", KEY_A)]


def test_tools_act_as_the_calling_user(client, api):
    _call_tool(client, "list_scan_exports", key=KEY_A)
    _call_tool(client, "list_scan_exports", key=KEY_B)
    tool_calls = [c for c in api.calls if c[0] == "/scan-exports"]
    assert tool_calls == [("/scan-exports", KEY_A), ("/scan-exports", KEY_B)]


def test_scan_export_tools_return_metadata_and_summary_only(client, api):
    listed = _call_tool(client, "list_scan_exports")
    listed = listed.get("result", listed)
    assert listed == [{"id": "e1", "filename": "was.zip", "status": "parsed",
                       "created_at": "2026-10-02T00:00:00Z", "size_bytes": 10}]
    detail = _call_tool(client, "get_scan_export_summary", {"export_id": "e1"})
    assert detail["summary"] == {"file_count": 2}
    assert "storage_path" not in detail and "owner_profile_id" not in detail


def test_rate_limit_per_key(client, api, monkeypatch):
    monkeypatch.setattr(mcp_app, "RATE_LIMIT_PER_MINUTE", 3)
    codes = [_post(client, INITIALIZE).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert _post(client, INITIALIZE, key=KEY_B).status_code == 200  # other keys unaffected


def test_gate_result_is_cached_briefly_then_rechecked(api):
    now = [1000.0]
    app = mcp_app.ApiKeyGateMiddleware(mcp_app.build_http_app().app, clock=lambda: now[0])
    with TestClient(app) as c:
        _post(c, INITIALIZE)
        _post(c, INITIALIZE)
        assert [p for p, _ in api.calls].count("/ai/mcp-gate") == 1
        api.gate_status = 403  # admin turned MCP off
        now[0] += mcp_app.GATE_CACHE_SECONDS + 1
        assert _post(c, INITIALIZE).status_code == 403


def test_api_down_returns_503(client, api):
    api.down = True
    assert _post(client, INITIALIZE).status_code == 503


def test_compose_publishes_no_mcp_port_and_needs_no_secrets():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    block = compose.split("\n  authrecon-mcp:\n", 1)[1].split("\n\n", 1)[0]
    assert "ports:" not in block
    assert "profiles:" not in block
    assert "MCP_AUTH_TOKEN" not in compose and "AUTHRECON_API_KEY" not in compose


def test_run_details_never_carry_session_material_to_the_model(client, api):
    detail = _call_tool(client, "get_run_details", {"run_id": "r1"})
    text = json.dumps(detail)
    assert COOKIE_VALUE not in text and "abc.def.ghi" not in text and "eyJhbGciOi" not in text
    cookie = detail["security_context"]["cookies"]["cookies"][0]
    # analysis survives, only the value is gone
    assert cookie["name"] == "rack.session" and cookie["value_encrypted"] == "[REDACTED]"
    assert cookie["security_issues"] == ["Missing Secure flag"] and cookie["value_hash"] == "abc"
    assert detail["security_context"]["headers"]["raw"]["Server"] == "nginx"
    assert "session_cookies" not in detail


def test_redaction_is_recursive_and_case_insensitive():
    out = mcp_app._redact_secrets({"a": [{"SET-COOKIE": "x"}], "Password": "p", "name": "keep", "token_type": "Bearer",
                                   "value": None})
    assert out == {"a": [{"SET-COOKIE": "[REDACTED]"}], "Password": "[REDACTED]", "name": "keep",
                   "token_type": "Bearer", "value": None}
