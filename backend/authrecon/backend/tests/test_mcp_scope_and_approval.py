"""Read-only API keys never write; runs an AI client starts can wait for a person."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from test_mcp_access import _make_key, api  # noqa: F401  (fixture)


class _Req:
    def __init__(self, method):
        self.method = method


def test_read_only_key_reads_but_never_writes(db_session):
    from app.api.deps import get_profile_from_api_key
    from app.services.profiles import sync_portal_profile

    profile = sync_portal_profile(db_session, str(uuid.uuid4()))
    profile.api_access_enabled = True
    db_session.commit()
    raw, key = _make_key(db_session, profile)
    key.scope = "read"
    db_session.commit()
    assert get_profile_from_api_key(_Req("GET"), raw, db_session).id == profile.id
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(HTTPException) as exc:
            get_profile_from_api_key(_Req(method), raw, db_session)
        assert exc.value.status_code == 403 and "read-only" in exc.value.detail
    key.scope = "full"
    db_session.commit()
    assert get_profile_from_api_key(_Req("POST"), raw, db_session).id == profile.id


def test_create_read_only_key(api):  # noqa: F811
    client, user, _ = api
    user.api_access_enabled = True
    r = client.request("POST", "/api/v1/api-keys", json={"name": "ai-readonly", "scope": "read"})
    assert r.status_code == 201 and r.json()["scope"] == "read"
    assert client.request("POST", "/api/v1/api-keys", json={"name": "x", "scope": "admin"}).status_code == 422


def _held_run(db_session, owner):
    from app.models import Run
    from app.schemas.run import RunStatus

    run = Run(id=f"RUN-{uuid.uuid4().hex[:8].upper()}", target_url="https://app.example.com/login",
              status=RunStatus.queued, submitted_at=datetime.now(timezone.utc),
              submitted_by_profile_id=owner.id, options={"awaiting_approval": True, "submitted_via": "MCP"})
    db_session.add(run)
    db_session.commit()
    return run


@pytest.fixture()
def queued(monkeypatch):
    import app.api.runs as runs_api

    seen = []

    class Q:
        def enqueue(self, fn, run_id, **kw):
            seen.append(run_id)

    monkeypatch.setattr(runs_api, "get_queue", lambda: Q())
    return seen


def test_approve_queues_the_run(api, db_session, queued):  # noqa: F811
    client, user, _ = api
    run = _held_run(db_session, user)
    summary = client.request("GET", f"/api/v1/runs/{run.id}").json()
    assert summary["awaiting_approval"] is True
    r = client.request("POST", f"/api/v1/runs/{run.id}/approve")
    assert r.status_code == 200 and r.json()["awaiting_approval"] is False
    assert queued == [run.id]
    assert client.request("POST", f"/api/v1/runs/{run.id}/approve").status_code == 409  # not waiting any more


def test_reject_fails_the_run(api, db_session, queued):  # noqa: F811
    client, user, _ = api
    run = _held_run(db_session, user)
    r = client.request("POST", f"/api/v1/runs/{run.id}/reject")
    assert r.status_code == 200 and r.json()["status"] == "failed"
    assert queued == []


def test_an_api_key_cannot_approve(api, db_session, queued):  # noqa: F811
    client, user, _ = api
    run = _held_run(db_session, user)
    user.auth_method = "api_key"
    assert client.request("POST", f"/api/v1/runs/{run.id}/approve").status_code == 403
    assert queued == []


def test_needs_approval_only_for_mcp_when_on(db_session):
    from app.api.runs import _needs_approval
    from app.models.app_setting import MCP_RUNS_NEED_APPROVAL, set_setting

    assert not _needs_approval(db_session, "MCP")
    set_setting(db_session, MCP_RUNS_NEED_APPROVAL, True)
    assert _needs_approval(db_session, "MCP")
    assert not _needs_approval(db_session, None)        # web UI
    assert not _needs_approval(db_session, "API key")   # CLI with a person behind it


def test_only_admins_change_the_approval_setting(api):  # noqa: F811
    client, _, current = api
    assert client.request("PUT", "/api/v1/ai/mcp/approval", json={"enabled": True}).status_code == 403
    current["admin"] = True
    assert client.request("PUT", "/api/v1/ai/mcp/approval", json={"enabled": True}).json() == {"enabled": True}
    assert client.get("/api/v1/ai/status").json()["mcp_runs_need_approval"] is True
