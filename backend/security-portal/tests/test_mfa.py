"""Two-factor authentication: enrol, two-step login, replay and brute-force
limits, backup codes, disable, admin reset, and the admins-must-enrol policy."""
from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app as portal_app  # noqa: E402
import mfa  # noqa: E402

ADMIN = {"username": "admin@example.com", "password": "SuperSecure1!"}
USER = {"username": "user@example.com", "password": "AlsoSecure2!"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    tools = tmp_path / "tools.yaml"
    tools.write_text("[]\n")
    for key, value in {
        "PORTAL_SECRET_KEY": secrets.token_hex(32), "PORTAL_API_SECRET": secrets.token_hex(32),
        "PORTAL_DATABASE_URL": f"sqlite:///{tmp_path / 'portal.db'}", "PORTAL_USER_STORE": str(tmp_path / "users.json"),
        "PORTAL_LOG_PATH": str(tmp_path / "portal.log"), "PORTAL_ENCRYPTION_KEY_PATH": str(tmp_path / "portal.key"),
        "TOOLS_CONFIG_PATH": str(tools),
    }.items():
        monkeypatch.setenv(key, value)
    portal_app._login_attempts.clear()
    mfa._spent.clear()
    with TestClient(portal_app.create_app()) as c:
        assert c.post("/api/auth/setup", json=ADMIN).status_code == 200
        yield c


def login(client, who=ADMIN):
    portal_app._login_attempts.clear()
    r = client.post("/api/auth/login", json=who)
    assert r.status_code == 200, r.text
    return r.json()


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def enrol(client, token):
    setup = client.post("/api/auth/mfa/setup", headers=auth(token)).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    # No email domain for authenticator apps to match a brand logo against.
    assert "%40" not in setup["otpauth_uri"] and "@" not in setup["otpauth_uri"]
    assert "issuer=AuthRecon" in setup["otpauth_uri"]
    assert setup["qr_data_uri"].startswith("data:image/svg+xml") and "xmlns" in setup["qr_data_uri"]
    totp = pyotp.TOTP(setup["secret"])
    r = client.post("/api/auth/mfa/enable", json={"code": totp.now()}, headers=auth(token))
    assert r.status_code == 200, r.text
    return totp, r.json()["backup_codes"]


def next_code(totp):
    return totp.at(time.time() + 30)  # the next step: never the one just used


def test_enrol_then_login_needs_a_code(client):
    token = login(client)["token"]
    totp, backups = enrol(client, token)
    assert len(backups) == 10
    first = login(client)
    assert first["mfa_required"] is True and first.get("token") is None
    # The half-way token is never a session.
    assert client.get("/api/auth/me", headers=auth(first["mfa_token"])).status_code == 401
    bad = client.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "code": "000000"})
    assert bad.status_code == 401
    good = client.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "code": next_code(totp)})
    assert good.status_code == 200 and good.json()["token"]
    assert client.get("/api/auth/me", headers=auth(good.json()["token"])).status_code == 200
    # Single use: the same pending token cannot be exchanged twice.
    again = client.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "code": next_code(totp)})
    assert again.status_code == 401


def test_a_code_is_not_accepted_twice(client):
    totp, _ = enrol(client, login(client)["token"])
    code = next_code(totp)
    ok = client.post("/api/auth/mfa/verify", json={"mfa_token": login(client)["mfa_token"], "code": code})
    assert ok.status_code == 200
    replay = client.post("/api/auth/mfa/verify", json={"mfa_token": login(client)["mfa_token"], "code": code})
    assert replay.status_code == 401


def test_five_wrong_codes_kill_the_sign_in(client):
    totp, _ = enrol(client, login(client)["token"])
    pending = login(client)["mfa_token"]
    for _ in range(5):
        r = client.post("/api/auth/mfa/verify", json={"mfa_token": pending, "code": "123456"})
    assert "password again" in r.json()["detail"]
    late = client.post("/api/auth/mfa/verify", json={"mfa_token": pending, "code": next_code(totp)})
    assert late.status_code == 401


def test_backup_code_works_once(client):
    _, backups = enrol(client, login(client)["token"])
    ok = client.post("/api/auth/mfa/verify", json={"mfa_token": login(client)["mfa_token"], "code": backups[0]})
    assert ok.status_code == 200
    reused = client.post("/api/auth/mfa/verify", json={"mfa_token": login(client)["mfa_token"], "code": backups[0]})
    assert reused.status_code == 401
    status = client.get("/api/auth/mfa", headers=auth(ok.json()["token"])).json()
    assert status["enabled"] is True and status["backup_codes_left"] == 9


def test_disable_needs_password_and_code(client):
    token = login(client)["token"]
    totp, _ = enrol(client, token)
    assert client.post("/api/auth/mfa/disable", json={"password": "wrong", "code": next_code(totp)},
                       headers=auth(token)).status_code == 400
    assert client.post("/api/auth/mfa/disable", json={"password": ADMIN["password"], "code": "000000"},
                       headers=auth(token)).status_code == 400
    assert client.post("/api/auth/mfa/disable", json={"password": ADMIN["password"], "code": next_code(totp)},
                       headers=auth(token)).status_code == 200
    assert login(client).get("token")  # back to password-only


def test_admin_reset_and_policy(client):
    admin_token = login(client)["token"]
    r = client.post("/api/users", json={**USER, "is_admin": False}, headers=auth(admin_token))
    assert r.status_code == 201, r.text
    user_id = r.json()["id"]
    user_token = login(client, USER)["token"]
    enrol(client, user_token)
    assert login(client, USER)["mfa_required"] is True
    # Only admins reset; then the user signs in with a password again.
    assert client.post(f"/api/auth/mfa/reset/{user_id}", headers=auth(user_token)).status_code == 403
    assert client.post(f"/api/auth/mfa/reset/{user_id}", headers=auth(admin_token)).status_code == 200
    assert login(client, USER).get("token")

    # Policy: an admin cannot require MFA before having it themselves.
    assert client.put("/api/auth/mfa/policy", json={"require_for_admins": True}, headers=auth(admin_token)).status_code == 409


def test_policy_forces_admins_without_mfa_to_enrol(client):
    admin_token = login(client)["token"]
    client.post("/api/users", json={"username": "admin2@example.com", "password": "AlsoSecure2!", "is_admin": True},
                headers=auth(admin_token))
    totp, _ = enrol(client, admin_token)
    full = client.post("/api/auth/mfa/verify", json={"mfa_token": login(client)["mfa_token"], "code": next_code(totp)}).json()["token"]
    assert client.put("/api/auth/mfa/policy", json={"require_for_admins": True}, headers=auth(full)).status_code == 200

    second = login(client, {"username": "admin2@example.com", "password": "AlsoSecure2!"})
    assert second["mfa_enrollment_required"] is True
    limited = second["token"]
    assert client.get("/api/users", headers=auth(limited)).status_code == 403      # everything else is closed
    assert client.get("/api/auth/mfa", headers=auth(limited)).status_code == 200   # but MFA setup is open
    totp2, _ = enrol(client, limited)
    upgraded = client.post("/api/auth/mfa/enable", json={"code": "x"}, headers=auth(limited))  # already on
    assert upgraded.status_code == 409


def test_account_label_drops_the_email_domain():
    from mfa import account_label

    assert account_label("jane.doe@example.org") == "jane.doe"
    assert account_label("admin") == "admin"
