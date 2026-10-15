"""Every run-scoped endpoint refuses a user who doesn't own the run (and
isn't an admin), before doing anything: no read, no queueing, no delete."""
from __future__ import annotations

import uuid

import pytest

from app.api.deps import get_current_active_profile
from app.db import get_db

from test_ai_and_scan_exports import _Client

ENDPOINTS = [
    ("GET", "/api/v1/runs/{id}"),
    ("GET", "/api/v1/runs/{id}/events"),
    ("POST", "/api/v1/runs/{id}/cancel"),
    ("POST", "/api/v1/runs/{id}/rerun"),
    ("POST", "/api/v1/runs/{id}/duplicate"),
    ("DELETE", "/api/v1/runs/{id}"),
    ("POST", "/api/v1/runs/{id}/start-manual-session"),
    ("POST", "/api/v1/runs/{id}/end-manual-session"),
    ("GET", "/api/v1/runs/{id}/artifacts"),
    ("GET", "/api/v1/runs/{id}/har"),
    ("GET", "/api/v1/runs/{id}/artifacts/download-all"),
    ("GET", "/api/v1/runs/{id}/artifacts/roles/admin/download"),
]


@pytest.fixture()
def setup(db_session, make_run, monkeypatch):
    from app.main import create_app
    from app.services import queue as queue_module
    from app.services.profiles import sync_portal_profile

    enqueued = []

    class _Queue:
        def enqueue(self, *a, **kw):
            enqueued.append(a)

    monkeypatch.setattr(queue_module, "get_queue", lambda *_a, **_kw: _Queue())
    run, _owner = make_run()
    intruder = sync_portal_profile(db_session, str(uuid.uuid4()))
    intruder.is_admin = False
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = lambda: intruder
    return _Client(app), run, enqueued


@pytest.mark.parametrize("method,path", ENDPOINTS)
def test_other_user_is_refused(setup, db_session, method, path):
    from app.models import Run

    client, run, enqueued = setup
    resp = client.request(method, path.format(id=run.id))
    assert resp.status_code in (403, 404), (method, path, resp.status_code, resp.text[:200])
    assert not enqueued
    db_session.expire_all()
    assert db_session.get(Run, run.id) is not None  # not deleted
