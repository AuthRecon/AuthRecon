"""LoginLab enable/disable: a failure is an HTTP error the UI can show, never a
200 whose body carries the error."""
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


def _fake_loginlab(monkeypatch, handler):
    real_client = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(portal_app.httpx, "AsyncClient", fake_client)


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


def _admin() -> dict[str, str]:
    return {"Authorization": f"Bearer {create_jwt_token('admin', is_admin=True, user_id='admin')}"}


def test_enable_when_loginlab_is_down_is_503_with_start_hint(client, monkeypatch):
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)
    _fake_loginlab(monkeypatch, down)
    response = client.post("/api/loginlab/enable?duration_minutes=30", headers=_admin())
    assert response.status_code == 503
    assert "docker compose --profile loginlab up -d loginlab" in response.json()["detail"]


def test_enable_when_loginlab_rejects_is_503(client, monkeypatch):
    _fake_loginlab(monkeypatch, lambda request: httpx.Response(403, json={"detail": "bad token"}))
    response = client.post("/api/loginlab/enable", headers=_admin())
    assert response.status_code == 503
    assert "HTTP 403" in response.json()["detail"]


def test_enable_and_disable_pass_through_on_success(client, monkeypatch):
    _fake_loginlab(monkeypatch, lambda request: httpx.Response(200, json={"active": True, "remaining_seconds": 1800}))
    response = client.post("/api/loginlab/enable", headers=_admin())
    assert response.status_code == 200 and response.json()["active"] is True
    assert client.post("/api/loginlab/disable", headers=_admin()).status_code == 200


def test_status_stays_200_when_loginlab_is_down(client, monkeypatch):
    def down(request):
        raise httpx.ConnectError("connection refused", request=request)
    _fake_loginlab(monkeypatch, down)
    response = client.get("/api/loginlab/status")
    assert response.status_code == 200 and response.json()["active"] is False
