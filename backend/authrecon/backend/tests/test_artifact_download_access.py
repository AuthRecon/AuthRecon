"""Download endpoints decrypt only for the owner or an admin; others get 403."""
from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import datetime, timezone

import asyncio

import httpx
import pytest

from app.api.deps import get_current_active_profile
from app.db import get_db
from app.models import Artifact

SECRET = "Sup3r-Secret!pw"
SIDE = json.dumps({"value": SECRET}).encode()
HAR = json.dumps({"log": {"entries": [{"request": {"url": "https://t.invalid/",
                                                   "postData": {"params": [{"name": "password", "value": SECRET}]}}}]}}).encode()


@pytest.fixture()
def api(db_session, artifact_storage, make_run):
    from app.main import create_app
    from app.services.profiles import sync_portal_profile

    run, owner = make_run()
    side_path = artifact_storage.save_bytes(run.id, "login.side", SIDE)
    har_path = artifact_storage.save_bytes(run.id, "network.har", HAR)
    for name, path, type_ in (("login.side", side_path, "side_file"), ("network.har", har_path, "har")):
        db_session.add(Artifact(id=f"{run.id[:8]}-{type_}", run_id=run.id, name=name, type=type_, size_bytes=0,
                                storage_path=path, created_at=datetime.now(timezone.utc)))
    db_session.commit()
    other = sync_portal_profile(db_session, str(uuid.uuid4()))

    app = create_app()
    current = {"profile": owner}

    def _profile():
        p = current["profile"]
        p.is_admin = current.get("admin", False)
        return p

    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = _profile
    return _Client(app), run, owner, other, current


class _Client:
    """Sync wrapper over httpx.ASGITransport (the pinned Starlette TestClient
    predates httpx 0.28, which requirements.txt pins)."""

    def __init__(self, app):
        self.app = app

    def get(self, url):
        async def _go():
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.get(url)

        return asyncio.run(_go())


def _side_url(run):
    return f"/api/v1/runs/{run.id}/artifacts/{run.id[:8]}-side_file/download"


def test_owner_downloads_decrypted_side_with_credentials(api):
    client, run, *_ = api
    resp = client.get(_side_url(run))
    assert resp.status_code == 200 and resp.content == SIDE


def test_other_user_is_forbidden(api):
    client, run, owner, other, current = api
    current["profile"] = other
    assert client.get(_side_url(run)).status_code == 403
    assert client.get(f"/api/v1/runs/{run.id}/artifacts/download-all").status_code == 403
    assert client.get(f"/api/v1/runs/{run.id}/har").status_code in (403, 404)


def test_admin_can_download(api):
    client, run, owner, other, current = api
    current.update(profile=other, admin=True)
    assert client.get(_side_url(run)).content == SIDE


def test_zip_contains_decrypted_files_and_masked_har(api):
    client, run, *_ = api
    resp = client.get(f"/api/v1/runs/{run.id}/artifacts/download-all")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        files = {n: zf.read(n) for n in zf.namelist()}
    assert files["login.side"] == SIDE
    assert SECRET.encode() not in files["network.har"] and b"[REDACTED]" in files["network.har"]
