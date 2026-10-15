"""Portal routes take bearer auth (no cookie session); SecBot-era routes are gone."""
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


def test_tools_list_takes_bearer_not_cookie(client):
    assert client.get("/api/tools", headers=_bearer(False)).status_code == 200
    assert client.get("/api/tools").status_code == 401
    client.cookies.set("secportal_session", "anything")
    assert client.get("/api/tools").status_code == 401


def test_auth_me(client):
    assert client.get("/api/auth/me", headers=_bearer(True)).json() == {"username": "admin", "is_admin": True, "id": "admin"}
    assert client.get("/api/auth/me").status_code == 401


def test_cookie_session_helpers_are_gone():
    import auth

    for name in ("get_current_user", "login_user", "logout_user", "SESSION_COOKIE"):
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
