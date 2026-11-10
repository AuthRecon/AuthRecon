"""Smoke tests: the practice target starts, renders its pages and issues and
checks its demo JWTs. They exist mainly so dependency updates get exercised."""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.pop("LOGINLAB_SERVICE_TOKEN", None)  # no token gate in these tests

from app import main  # noqa: E402

USER = "testuser@loginlab.local"
PASSWORD = main.TEST_USERS[USER]["password"]


@pytest.fixture()
def client():
    main.enable_loginlab(enabled_by="pytest")
    with TestClient(main.app) as c:
        yield c
    main.disable_loginlab()


def test_disabled_by_default():
    main.disable_loginlab()
    with TestClient(main.app) as c:
        assert c.get("/health").status_code == 200
        assert c.get("/").status_code == 503


def test_pages_render(client):
    for path in ("/", "/form-login"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "<html" in response.text.lower()


def test_form_login_rejects_bad_password(client):
    response = client.post("/form-login", data={"username": USER, "password": "wrong"})
    assert "Invalid username or password" in response.text


def test_api_token_round_trip(client):
    issued = client.post("/api/auth", json={"username": USER, "password": PASSWORD})
    assert issued.status_code == 200
    token = issued.json()["access_token"]

    verified = client.get("/api/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert verified.status_code == 200
    assert verified.json()["username"] == USER


def test_api_rejects_bad_credentials_and_tokens(client):
    assert client.post("/api/auth", json={"username": USER, "password": "wrong"}).status_code == 401

    tampered = client.get("/api/auth/verify", headers={"Authorization": "Bearer not.a.token"})
    assert tampered.status_code == 401

    # A token that claims no signature must not be accepted. Built here so no
    # token-shaped literal sits in the repo for secret scanners to flag.
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    unsigned = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'admin'})}."
    assert client.get("/api/auth/verify", headers={"Authorization": f"Bearer {unsigned}"}).status_code == 401
