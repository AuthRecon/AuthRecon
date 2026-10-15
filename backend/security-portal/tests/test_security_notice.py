"""Security notice: shown until acknowledged, again after 7 days or when the
notice version changes; acknowledgements are per user and audit-logged."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from test_auth_routes import _bearer, client  # noqa: F401  (fixture)


def test_notice_is_required_until_acknowledged(client):  # noqa: F811
    assert client.get("/api/security-notice", headers=_bearer(False)).json()["required"] is True
    ack = client.post("/api/security-notice/ack", headers=_bearer(False)).json()
    assert ack["required"] is False and ack["acknowledged_at"]
    assert client.get("/api/security-notice", headers=_bearer(False)).json()["required"] is False
    # per user: the admin still has to acknowledge it
    assert client.get("/api/security-notice", headers=_bearer(True)).json()["required"] is True


def test_notice_comes_back_after_seven_days_and_on_new_version(client, monkeypatch):  # noqa: F811
    import security_notice

    client.post("/api/security-notice/ack", headers=_bearer(False))
    later = datetime.now(timezone.utc) + timedelta(days=7, minutes=1)
    assert security_notice.notice_status("user", now=later)["required"] is True
    monkeypatch.setattr(security_notice, "NOTICE_VERSION", security_notice.NOTICE_VERSION + 1)
    assert security_notice.notice_status("user")["required"] is True


def test_acknowledgement_is_audited_and_needs_login(client):  # noqa: F811
    from database import get_session
    from models.audit_log import AuditLog

    assert client.post("/api/security-notice/ack").status_code == 401
    client.post("/api/security-notice/ack", headers=_bearer(False))
    with get_session() as session:
        events = [(e.event_type, e.actor_username) for e in session.query(AuditLog).all()]
    assert ("security_notice_acknowledged", "user") in events
