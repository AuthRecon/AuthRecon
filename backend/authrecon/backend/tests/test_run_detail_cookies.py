"""Run detail decrypts cookie values for the owner's response only; the stored
security_context must stay encrypted."""
from __future__ import annotations

from app.api.deps import get_current_active_profile
from app.db import get_db

from test_ai_and_scan_exports import _Client

COOKIE_VALUE = "BAh7CEkiD3Nlc3Npb25faWQGOgZFVEki"


def test_owner_sees_value_but_stored_context_stays_encrypted(db_session, make_run):
    from app.main import create_app
    from app.services.profiles import get_profile_artifact_cipher

    run, owner = make_run()
    token = get_profile_artifact_cipher(db_session, owner).encrypt(COOKIE_VALUE.encode()).decode()
    run.security_context = {"cookies": {"cookies": [{
        "name": "rack.session", "value_encrypted": token, "value_hash": "h", "domain": "t.invalid", "path": "/",
        "is_session": True, "is_persistent": False, "http_only": True, "secure": False, "size_bytes": 10,
        "entropy_score": 0.5, "captured_at": "2026-10-01T00:00:00Z",
    }], "total_count": 1, "session_count": 1, "persistent_count": 0, "secure_count": 0, "http_only_count": 1,
        "same_site_none_count": 0, "total_size_bytes": 10, "security_score": 50.0},
        "extracted_at": "2026-10-01T00:00:00Z"}
    db_session.commit()

    app = create_app()
    owner.is_admin = False
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = lambda: owner
    resp = _Client(app).get(f"/api/v1/runs/{run.id}")
    assert resp.status_code == 200, resp.text
    cookie = resp.json()["security_context"]["cookies"]["cookies"][0]
    assert cookie["value_encrypted"] == COOKIE_VALUE  # owner's UI still gets it
    # the ORM object (what a later commit would write) is untouched
    assert run.security_context["cookies"]["cookies"][0]["value_encrypted"] == token

    db_session.commit()  # anything pending would be flushed now
    db_session.expire_all()
    stored = db_session.get(type(run), run.id).security_context["cookies"]["cookies"][0]["value_encrypted"]
    assert stored == token and COOKIE_VALUE not in stored


# --- Run.session_cookies_enc --------------------------------------------------

SESSION_COOKIES = [{"name": "sid", "value": COOKIE_VALUE, "domain": "t.invalid", "path": "/"}]


def test_run_cookies_round_trip_for_owned_and_ownerless_runs(db_session, make_run):
    from app.services.artifact_crypto import decrypt_run_cookies, encrypt_run_cookies

    for owned in (True, False):
        run, _ = make_run(owned=owned)
        run.session_cookies_enc = encrypt_run_cookies(db_session, run, SESSION_COOKIES)
        assert COOKIE_VALUE not in run.session_cookies_enc
        assert run.session_cookies_enc.startswith("ARENC:" + ("p1" if owned else "m1") + ":")
        assert decrypt_run_cookies(db_session, run) == SESSION_COOKIES


def test_legacy_profile_token_still_decrypts(db_session, make_run):
    import json

    from app.services.artifact_crypto import decrypt_run_cookies
    from app.services.profiles import get_profile_artifact_cipher

    run, owner = make_run()
    run.session_cookies_enc = get_profile_artifact_cipher(db_session, owner).encrypt(
        json.dumps(SESSION_COOKIES).encode()).decode()
    assert decrypt_run_cookies(db_session, run) == SESSION_COOKIES


def test_run_detail_returns_decrypted_session_cookies_to_owner(db_session, make_run):
    from app.main import create_app
    from app.services.artifact_crypto import encrypt_run_cookies

    run, owner = make_run()
    run.session_cookies_enc = encrypt_run_cookies(db_session, run, SESSION_COOKIES)
    run.session_cookies = []
    db_session.commit()

    app = create_app()
    owner.is_admin = False
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = lambda: owner
    resp = _Client(app).get(f"/api/v1/runs/{run.id}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["session_cookies"][0]["value"] == COOKIE_VALUE


def test_other_user_cannot_read_run_cookies(db_session, make_run):
    from app.main import create_app
    from app.services.artifact_crypto import encrypt_run_cookies

    run, _owner = make_run()
    _, other = make_run()
    run.session_cookies_enc = encrypt_run_cookies(db_session, run, SESSION_COOKIES)
    db_session.commit()

    app = create_app()
    other.is_admin = False
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_active_profile] = lambda: other
    resp = _Client(app).get(f"/api/v1/runs/{run.id}")
    assert resp.status_code in (403, 404)
    assert COOKIE_VALUE not in resp.text
