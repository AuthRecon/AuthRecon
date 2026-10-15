"""MCP access control: the admin switch, per-user API access, and the key gate
the MCP server calls on every client request."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api.deps import get_current_active_profile, get_current_admin
from app.core.security import create_api_key_prefix, generate_api_key, hash_api_key
from app.db import get_db

from test_ai_and_scan_exports import _Client


@pytest.fixture()
def api(db_session):
    from app.main import create_app
    from app.services.profiles import sync_portal_profile

    user = sync_portal_profile(db_session, str(uuid.uuid4()))
    app = create_app()
    current = {"profile": user, "admin": False}

    def _profile():
        p = current["profile"]
        p.is_admin = current["admin"]
        return p

    def _admin():
        if not current["admin"]:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        return _profile()

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = _profile
    app.dependency_overrides[get_current_admin] = _admin
    return _Client(app), user, current


def _make_key(db_session, profile, *, revoked=False):
    from app.models.api_key import APIKey

    raw = generate_api_key()
    key = APIKey(id=str(uuid.uuid4()), profile_id=profile.id, name="mcp", key_hash=hash_api_key(raw),
                 prefix=create_api_key_prefix(raw), is_revoked=revoked, created_at=datetime.now(timezone.utc))
    db_session.add(key)
    db_session.commit()
    return raw, key


def _enable_mcp(client, current, enabled=True):
    current["admin"] = True
    assert client.request("PUT", "/api/v1/ai/mcp", json={"enabled": enabled}).status_code == 200
    current["admin"] = False


def _gate(client, raw):
    return client.get("/api/v1/ai/mcp-gate", headers={"X-API-Key": raw} if raw else {})


# --- admin switch ---------------------------------------------------------------


def test_only_admins_can_toggle_mcp(api):
    client, _user, current = api
    assert client.request("PUT", "/api/v1/ai/mcp", json={"enabled": True}).status_code == 403
    current["admin"] = True
    assert client.request("PUT", "/api/v1/ai/mcp", json={"enabled": True}).json() == {"enabled": True}
    assert client.get("/api/v1/ai/status").json()["mcp_enabled"] is True


# --- gate -----------------------------------------------------------------------


def test_gate_refuses_everything_while_mcp_is_disabled(api, db_session):
    client, user, _ = api
    user.api_access_enabled = True
    raw, _ = _make_key(db_session, user)
    assert _gate(client, raw).status_code == 403


def test_gate_accepts_valid_key_and_records_connection(api, db_session):
    client, user, current = api
    user.api_access_enabled = True
    raw, key = _make_key(db_session, user)
    _enable_mcp(client, current)
    assert _gate(client, raw).status_code == 200
    db_session.refresh(key)
    assert key.last_mcp_used_at is not None
    status = client.get("/api/v1/ai/status").json()
    assert status["last_client_activity"] is not None
    assert status["api_keys"][0]["last_mcp_used_at"] is not None


@pytest.mark.parametrize("case", ["missing", "malformed", "unknown", "revoked", "no_access"])
def test_gate_rejects_bad_keys(api, db_session, case):
    client, user, current = api
    _enable_mcp(client, current)
    user.api_access_enabled = case != "no_access"
    db_session.commit()
    raw, _ = _make_key(db_session, user, revoked=case == "revoked")
    raw = {"missing": None, "malformed": "not-a-key", "unknown": generate_api_key()}.get(case, raw)
    assert _gate(client, raw).status_code == 401


# --- per-user API access --------------------------------------------------------


def test_api_access_is_admin_managed(api, db_session):
    client, user, current = api
    assert client.get("/api/v1/ai/api-access").status_code == 403
    assert client.request("PUT", f"/api/v1/ai/api-access/{user.portal_user_id}", json={"enabled": True}).status_code == 403

    current["admin"] = True
    new_user = str(uuid.uuid4())  # never opened AuthRecon yet: profile is created
    r = client.request("PUT", f"/api/v1/ai/api-access/{new_user}", json={"enabled": True})
    assert r.json() == {"portal_user_id": new_user, "api_access_enabled": True}
    listed = {e["portal_user_id"]: e["api_access_enabled"] for e in client.get("/api/v1/ai/api-access").json()}
    assert listed[new_user] is True and listed[user.portal_user_id] is False


def test_revoking_api_access_stops_existing_keys(api, db_session):
    client, user, current = api
    _enable_mcp(client, current)
    user.api_access_enabled = True
    db_session.commit()
    raw, _ = _make_key(db_session, user)
    assert _gate(client, raw).status_code == 200
    current["admin"] = True
    client.request("PUT", f"/api/v1/ai/api-access/{user.portal_user_id}", json={"enabled": False})
    assert _gate(client, raw).status_code == 401


def test_admins_can_create_keys_without_a_separate_grant(api, db_session):
    client, user, current = api
    assert client.request("POST", "/api/v1/api-keys", json={"name": "x"}).status_code == 403
    current["admin"] = True
    r = client.request("POST", "/api/v1/api-keys", json={"name": "Claude Code"})
    assert r.status_code == 201 and r.json()["key"].startswith("ak_live_")
    db_session.refresh(user)
    assert user.api_access_enabled is True  # so the key actually authenticates
