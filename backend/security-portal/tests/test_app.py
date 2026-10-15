"""Basic tests for the Security Portal."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app


def _build_client(tmp_path: Path) -> TestClient:
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(
        """
- id: diagnostics
  name: Diagnostics
  description: Test tool
  url: http://localhost/tools/diagnostics
  enabled: true
"""
    )
    db_path = tmp_path / "portal.db"
    users_path = tmp_path / "users.json"
    log_path = tmp_path / "portal.log"
    key_path = tmp_path / "portal.key"
    overrides = {
        "PORTAL_NAME": "Test Portal",
        "PORTAL_DATABASE_URL": f"sqlite:///{db_path}",
        "PORTAL_USER_STORE": str(users_path),
        "PORTAL_LOG_PATH": str(log_path),
        "PORTAL_ENCRYPTION_KEY_PATH": str(key_path),
        "TOOLS_CONFIG_PATH": str(tools_path),
        "PORTAL_ALLOWED_USERS": "*",
        "PORTAL_ADMIN_USERS": "tester",
    }
    previous: dict[str, str | None] = {}
    for key, value in overrides.items():
        previous[key] = os.environ.get(key)
        os.environ[key] = value
    try:
        application = create_app()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return TestClient(application)


def test_healthz(tmp_path) -> None:
    with _build_client(tmp_path) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.text == "ok"


def test_initial_setup_and_login_flow(tmp_path) -> None:
    """The JWT flow the React app uses: setup, login, then the token works."""
    with _build_client(tmp_path) as client:
        assert client.get("/api/auth/status").json() == {"initialized": False, "needs_setup": True}

        response = client.post(
            "/api/auth/setup",
            json={"username": "admin@example.com", "password": "SuperSecure1!"},
        )
        assert response.status_code == 200, response.text
        assert client.get("/api/auth/status").json()["initialized"] is True

        # Setup only works once.
        again = client.post("/api/auth/setup", json={"username": "x@example.com", "password": "SuperSecure1!"})
        assert again.status_code == 400

        bad = client.post("/api/auth/login", json={"username": "admin@example.com", "password": "wrong-password"})
        assert bad.status_code == 401

        login = client.post("/api/auth/login", json={"username": "admin@example.com", "password": "SuperSecure1!"})
        assert login.status_code == 200, login.text
        token = login.json()["token"]
        me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200 and me.json()["is_admin"] is True

        # The legacy cookie form routes are gone.
        assert client.get("/login", allow_redirects=False).status_code == 410
