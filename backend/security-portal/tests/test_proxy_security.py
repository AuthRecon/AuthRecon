"""Proxy hardening: client-sent trust headers are stripped; path traversal is rejected."""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app as portal_app  # noqa: E402
from auth import create_jwt_token  # noqa: E402
from conftest import seed_users  # noqa: E402

ADMIN_TOKEN = secrets.token_hex(32)


@pytest.fixture()
def upstream(monkeypatch):
    """Capture proxied requests instead of sending them."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    real_client = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(portal_app.httpx, "AsyncClient", fake_client)
    return seen


@pytest.fixture()
def client(tmp_path, monkeypatch):
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text("[]\n")
    env = {
        "PORTAL_SECRET_KEY": secrets.token_hex(32),
        "PORTAL_API_SECRET": secrets.token_hex(32),
        "PORTAL_DATABASE_URL": f"sqlite:///{tmp_path / 'portal.db'}",
        "PORTAL_USER_STORE": str(tmp_path / "users.json"),
        "PORTAL_LOG_PATH": str(tmp_path / "portal.log"),
        "PORTAL_ENCRYPTION_KEY_PATH": str(tmp_path / "portal.key"),
        "TOOLS_CONFIG_PATH": str(tools_path),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with TestClient(portal_app.create_app()) as test_client:
        seed_users(("admin", True), ("user", False))
        yield test_client


def _auth(is_admin: bool) -> dict[str, str]:
    name = "admin" if is_admin else "user"
    token = create_jwt_token(name, is_admin=is_admin, user_id=name)
    return {"Authorization": f"Bearer {token}"}


# --- Trust headers ---------------------------------------------------------


def test_client_supplied_trust_headers_are_stripped(client, upstream):
    headers = {**_auth(False), "X-Admin-Token": ADMIN_TOKEN, "X-Portal-Is-Admin": "true",
               "X-Portal-Secret": "forged", "X-Portal-User-Id": "someone-else"}
    response = client.get("/apps/authrecon/api/v1/runs", headers=headers)
    assert response.status_code == 200
    forwarded = upstream[0].headers
    for name in ("x-admin-token", "x-portal-is-admin", "x-portal-secret", "x-portal-user-id"):
        assert name not in forwarded


def test_authrecon_api_proxy_requires_login(client, upstream):
    assert client.get("/apps/authrecon/api/v1/runs").status_code == 401
    assert upstream == []


# --- Item 5: path traversal through proxies ---------------------------------

TRAVERSALS = [
    "%2e%2e/%2e%2e/openapi.json",
    "%2E%2E/%2E%2E/docs",
    "%252e%252e/%252e%252e/openapi.json",
    "..%2f..%2fhealth/ready",
    "vendor/%2e%2e/%2e%2e/%2e%2e/openapi.json",
    "%2e/app/ui.js",
    "%5c..%5copenapi.json",
    "%2fopenapi.json",
]


@pytest.mark.parametrize("path", TRAVERSALS)
def test_novnc_rejects_traversal(client, upstream, path):
    response = client.get(f"/apps/authrecon/novnc/{path}")
    assert response.status_code == 400
    assert upstream == []


@pytest.mark.parametrize("path", TRAVERSALS)
def test_authenticated_proxies_reject_traversal(client, upstream, path):
    response = client.get(f"/apps/authrecon/api/{path}", headers=_auth(True))
    assert response.status_code == 400
    assert upstream == []


def test_novnc_static_assets_still_served(client, upstream):
    response = client.get("/apps/authrecon/novnc/vnc.html")
    assert response.status_code == 200
    assert upstream[0].url.path == "/novnc/vnc.html"

    response = client.get("/apps/authrecon/novnc/core/rfb.js")
    assert response.status_code == 200
    assert upstream[1].url.path == "/novnc/core/rfb.js"


def test_authrecon_api_proxy_still_works(client, upstream):
    response = client.get("/apps/authrecon/api/v1/runs", headers=_auth(False))
    assert response.status_code == 200
    assert upstream[0].url.path == "/api/v1/runs"


# --- MCP endpoint ---------------------------------------------------------------

MCP_KEY = "ak_live_" + "c" * 40


def test_mcp_route_needs_no_portal_login_and_forwards_the_api_key(client, upstream):
    resp = client.post(
        "/apps/authrecon/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": f"Bearer {MCP_KEY}"},
    )
    assert resp.status_code == 200
    (sent,) = upstream
    assert sent.url.host == "authrecon-mcp" and sent.url.path == "/mcp"
    assert sent.headers["authorization"] == f"Bearer {MCP_KEY}"


def test_mcp_route_does_not_forward_portal_trust_headers(client, upstream):
    client.post(
        "/apps/authrecon/mcp",
        json={},
        headers={"Authorization": f"Bearer {MCP_KEY}", "X-Portal-Secret": "forged", "X-Portal-Is-Admin": "true"},
    )
    (sent,) = upstream
    assert "x-portal-secret" not in sent.headers and "x-portal-is-admin" not in sent.headers


@pytest.mark.parametrize("path", ["%2e%2e/api/v1/runs", "..%2f..%2fhealth", "%252e%252e/x"])
def test_mcp_route_rejects_path_traversal(client, upstream, path):
    assert client.post(f"/apps/authrecon/mcp/{path}", json={}).status_code == 400
    assert upstream == []
