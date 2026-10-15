"""AI & MCP status/preferences and the scan-export scaffold (owner-or-admin, encrypted at rest)."""
from __future__ import annotations

import asyncio
import io
import uuid
import zipfile
from datetime import datetime, timezone

import httpx
import pytest

from app.api.deps import get_current_active_profile
from app.db import get_db


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


EXPORT = _zip({"scan/summary.json": b'{"status":"completed"}', "scan/findings.csv": b"plugin,severity\n1,high\n",
               "scan/config.json": b'{"auth": {"password": "Sup3r-Secret!pw"}}'})


class _Client:
    def __init__(self, app):
        self.app = app

    def request(self, method, url, **kwargs):
        async def go():
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                return await c.request(method, url, **kwargs)
        return asyncio.run(go())

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


@pytest.fixture()
def api(db_session, artifact_storage, monkeypatch):
    from app.main import create_app
    from app.services.profiles import sync_portal_profile
    import app.api.scan_exports as scan_exports_api

    monkeypatch.setattr(scan_exports_api, "get_artifact_storage", lambda: artifact_storage)
    owner = sync_portal_profile(db_session, str(uuid.uuid4()))
    other = sync_portal_profile(db_session, str(uuid.uuid4()))
    app = create_app()
    current = {"profile": owner, "admin": False}

    def _profile():
        p = current["profile"]
        p.is_admin = current["admin"]
        return p

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = _profile
    return _Client(app), owner, other, current


def _upload(client, data=EXPORT, name="was-export.zip"):
    return client.request("POST", "/api/v1/scan-exports", files={"file": (name, data, "application/zip")})


# --- AI & MCP -----------------------------------------------------------------


def test_ai_status_reports_mcp_state_and_keys(api, db_session):
    from app.models.api_key import APIKey

    client, owner, *_ = api
    connected = datetime(2026, 9, 30, tzinfo=timezone.utc)
    db_session.add(APIKey(profile_id=owner.id, name="claude", key_hash="x", prefix="ar_abc",
                          created_at=datetime.now(timezone.utc), last_mcp_used_at=connected))
    db_session.commit()

    data = client.get("/api/v1/ai/status").json()
    assert data["mcp_enabled"] is False  # off until an admin turns it on
    assert data["mcp_path"] == "/apps/authrecon/mcp"
    assert data["use_ai_suggestions"] is False  # new profiles default to off
    assert data["api_access"] is False and data["is_admin"] is False
    assert [k["prefix"] for k in data["api_keys"]] == ["ar_abc"]
    assert data["last_client_activity"].startswith("2026-09-30")
    assert "key_hash" not in str(data)


def test_ai_preference_toggle_is_per_user(api, db_session):
    client, owner, other, current = api
    r = client.request("PUT", "/api/v1/ai/preferences", json={"use_ai_suggestions": True})
    assert r.json() == {"use_ai_suggestions": True}
    db_session.refresh(owner)
    db_session.refresh(other)
    assert owner.llm_enabled is True and other.llm_enabled is False


def test_old_llm_settings_route_is_gone(api):
    client, *_ = api
    assert client.get("/api/v1/settings/llm").status_code == 404


# --- scan exports -------------------------------------------------------------


def test_upload_parses_and_stores_encrypted(api, artifact_storage):
    client, owner, *_ = api
    r = _upload(client)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "parsed" and body["owner_profile_id"] == owner.id
    assert body["summary"]["file_count"] == 3 and body["summary"]["files_by_kind"] == {"json": 2, "csv": 1}
    assert "Sup3r-Secret" not in r.text  # summary carries names only, never contents
    raw = next(artifact_storage.base_path.rglob("export.zip")).read_bytes()
    assert raw.startswith(b"ARENC:p1:") and b"Sup3r" not in raw


@pytest.mark.parametrize("data,msg", [
    (b"not a zip", "must be a .zip"),
    (_zip({"big.txt": b"0" * 5_000_000}), "zip bomb"),
])
def test_bad_uploads_are_rejected(api, data, msg):
    client, *_ = api
    r = _upload(client, data)
    assert r.status_code == 400 and msg in r.json()["detail"]


def test_other_user_cannot_read_or_delete(api):
    client, owner, other, current = api
    export_id = _upload(client).json()["id"]
    current["profile"] = other
    assert client.get(f"/api/v1/scan-exports/{export_id}").status_code == 403
    assert client.request("DELETE", f"/api/v1/scan-exports/{export_id}").status_code == 403
    assert client.get("/api/v1/scan-exports").json() == []


def test_admin_can_read_and_owner_can_delete(api, artifact_storage):
    client, owner, other, current = api
    export_id = _upload(client).json()["id"]
    current.update(profile=other, admin=True)
    assert client.get(f"/api/v1/scan-exports/{export_id}").json()["id"] == export_id
    assert [e["id"] for e in client.get("/api/v1/scan-exports").json()] == [export_id]
    current.update(profile=owner, admin=False)
    assert client.request("DELETE", f"/api/v1/scan-exports/{export_id}").status_code == 204
    assert client.get(f"/api/v1/scan-exports/{export_id}").status_code == 404
    assert not list(artifact_storage.base_path.rglob("export.zip"))


def test_no_route_serves_the_raw_zip(api):
    client, *_ = api
    export_id = _upload(client).json()["id"]
    for suffix in ("/download", "/file", "/raw"):
        assert client.get(f"/api/v1/scan-exports/{export_id}{suffix}").status_code in (404, 405)
