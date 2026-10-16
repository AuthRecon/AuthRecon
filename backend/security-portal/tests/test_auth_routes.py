"""Portal auth: bearer tokens, or the web UI's HttpOnly session cookie (with a CSRF header); SecBot-era routes are gone."""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app as portal_app  # noqa: E402
from auth import create_jwt_token  # noqa: E402
from conftest import seed_users  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text("[]\n")
    for key, value in {
        "PORTAL_SECRET_KEY": secrets.token_hex(32),
        "PORTAL_API_SECRET": secrets.token_hex(32),
        "PORTAL_DATABASE_URL": f"sqlite:///{tmp_path / 'portal.db'}",
        "PORTAL_USER_STORE": str(tmp_path / "users.json"),
        "PORTAL_LOG_PATH": str(tmp_path / "portal.log"),
        "PORTAL_ENCRYPTION_KEY_PATH": str(tmp_path / "portal.key"),
        "TOOLS_CONFIG_PATH": str(tools_path),
    }.items():
        monkeypatch.setenv(key, value)
    with TestClient(portal_app.create_app()) as test_client:
        seed_users(("admin", True), ("user", False))
        yield test_client


def _bearer(is_admin: bool) -> dict[str, str]:
    name = "admin" if is_admin else "user"
    return {"Authorization": f"Bearer {create_jwt_token(name, is_admin=is_admin, user_id=name)}"}


REMOVED = [
    ("GET", "/apps/secbot/status"),
    ("POST", "/apps/secbot/admin/llm/provider"),
    ("GET", "/settings"),
    ("GET", "/settings/report-groups"),
    ("POST", "/settings/report-groups/update"),
    ("GET", "/settings/tenable/tags"),
    ("POST", "/settings/tenable/update"),
    ("POST", "/settings/llm/update"),
    ("GET", "/api/settings/tenable/status"),
    ("GET", "/catalog"),
    ("GET", "/api/service/config"),
]


@pytest.mark.parametrize("method,path", REMOVED)
def test_secbot_era_routes_are_gone(client, method, path):
    assert client.request(method, path, headers=_bearer(True)).status_code in (404, 405)


def test_tools_list_takes_bearer_not_legacy_cookie(client):
    assert client.get("/api/tools", headers=_bearer(False)).status_code == 200
    assert client.get("/api/tools").status_code == 401
    client.cookies.set("secportal_session", "anything")
    assert client.get("/api/tools").status_code == 401


def test_auth_me(client):
    assert client.get("/api/auth/me", headers=_bearer(True)).json() == {"username": "admin", "is_admin": True, "id": "admin"}
    assert client.get("/api/auth/me").status_code == 401


def test_legacy_cookie_session_helpers_are_gone():
    import auth

    for name in ("get_current_user", "login_user", "logout_user"):
        assert not hasattr(auth, name), name


def test_no_secbot_settings_in_config():
    import config

    fields = set(config.PortalConfig.__dataclass_fields__)
    assert not {f for f in fields if "secbot" in f}


# --- tokens follow the live user record ----------------------------------------


def _set_user(name: str, **fields) -> None:
    from database import get_session
    from models import PortalUser

    with get_session() as session:
        user = session.get(PortalUser, name)
        for key, value in fields.items():
            setattr(user, key, value)
        session.commit()


def test_deactivated_user_token_stops_working_immediately(client):
    headers = _bearer(False)
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    _set_user("user", is_active=False)
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_demoted_admin_loses_admin_immediately(client):
    headers = _bearer(True)
    assert client.get("/api/auth/me", headers=headers).json()["is_admin"] is True
    _set_user("admin", is_admin=False)
    assert client.get("/api/auth/me", headers=headers).json()["is_admin"] is False


def test_token_for_deleted_user_is_rejected(client):
    token = create_jwt_token("ghost", is_admin=True, user_id="ghost")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_role_and_status_changes_are_audited(client):
    from database import get_session
    from models.audit_log import AuditLog

    resp = client.patch("/api/users/user", json={"is_admin": True, "is_active": False}, headers=_bearer(True))
    assert resp.status_code == 200, resp.text
    with get_session() as session:
        events = {(e.event_type, e.target_username, e.actor_username) for e in session.query(AuditLog).all()}
    assert ("role_changed", "user", "admin") in events
    assert ("user_deactivated", "user", "admin") in events


# --- HttpOnly session cookie (web UI) -----------------------------------------

CSRF = {"X-Requested-With": "AuthRecon"}
PASSWORD = "Correct-Horse-Battery-9"


def _login(client) -> "object":
    portal_app._login_attempts.clear()  # the per-IP login limit spans tests
    client.app.state.user_store.add_user("alice@example.com", PASSWORD, is_admin=False)
    return client.post("/api/auth/login", json={"username": "alice@example.com", "password": PASSWORD})


def test_login_sets_httponly_strict_session_cookie(client):
    resp = _login(client)
    assert resp.status_code == 200
    cookie = next(h for h in resp.headers.get_list("set-cookie") if h.startswith("ar_session="))
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    assert "Secure" not in cookie  # plain HTTP test server; HTTPS adds it


def test_cookie_session_needs_the_csrf_header(client):
    _login(client)
    assert client.get("/api/auth/me", headers=CSRF).json()["username"] == "alice@example.com"
    # A cross-site form or plain request cannot add the header.
    assert client.get("/api/auth/me").status_code == 403


def test_https_requests_get_secure_cookies(client):
    portal_app._login_attempts.clear()
    client.app.state.user_store.add_user("bob@example.com", PASSWORD, is_admin=False)
    resp = client.post("/api/auth/login", json={"username": "bob@example.com", "password": PASSWORD},
                       headers={"X-Forwarded-Proto": "https"})
    assert "Secure" in next(h for h in resp.headers.get_list("set-cookie") if h.startswith("ar_session="))


def test_logout_revokes_and_clears_the_cookie(client, monkeypatch):
    import app as portal

    revoked = []
    monkeypatch.setattr(portal, "revoke_jti", lambda jti, ttl: revoked.append(jti))
    _login(client)
    resp = client.post("/api/auth/logout", headers=CSRF)
    assert resp.status_code == 200 and revoked
    assert any(h.startswith('ar_session=""') or "Max-Age=0" in h for h in resp.headers.get_list("set-cookie"))


def test_browser_sessions_cannot_mint_service_tokens(client):
    _login(client)
    assert client.post("/api/tools/auth_recon/service-token", headers=CSRF).status_code == 403


def test_authrecon_session_sets_only_an_httponly_cookie(client, monkeypatch):
    import app as portal

    calls = []

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"access_token": "ar-access-token", "expires_at": "2099-01-01T00:00:00+00:00"}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json):
            calls.append((url, json))
            return FakeResponse()

    monkeypatch.setattr(portal.httpx, "AsyncClient", FakeClient)
    _login(client)
    resp = client.post("/api/auth/authrecon-session", headers=CSRF)
    assert resp.status_code == 200
    assert "ar-access-token" not in resp.text  # never in the body
    cookie = next(h for h in resp.headers.get_list("set-cookie") if h.startswith("ar_api="))
    assert "HttpOnly" in cookie and "Path=/apps/authrecon" in cookie
    assert calls[0][0].endswith("/api/v1/auth/portal-login")


def test_proxy_forwards_the_api_cookie_as_bearer_and_drops_cookies(client, monkeypatch):
    import app as portal

    seen = {}

    async def fake_proxy(request, base, path, extra_headers=None):
        seen["extra"] = extra_headers
        seen["forwarded"] = portal._build_proxy_headers(request.headers)
        return portal.Response(status_code=200)

    monkeypatch.setattr(portal, "_proxy_request", fake_proxy)
    _login(client)
    client.cookies.set("ar_api", "ar-access-token", path="/apps/authrecon")
    assert client.get("/apps/authrecon/api/v1/runs", headers=CSRF).status_code == 200
    assert seen["extra"] == {"Authorization": "Bearer ar-access-token"}
    assert not any(k.lower() == "cookie" for k in seen["forwarded"])
