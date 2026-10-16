"""SSRF guard for run targets: metadata, loopback and AuthRecon's own services are
refused; internal (private) applications stay scannable unless an admin says otherwise."""
from __future__ import annotations

import ipaddress

import pytest

from app.services import target_guard as tg
from app.services.target_guard import TargetBlocked, check_target, is_allowed

DNS = {
    "intranet.example.org": "10.20.30.40",
    "public.example.com": "93.184.216.34",
    "sneaky.example.com": "169.254.169.254",
    "rebind.example.com": "127.0.0.1",
    "dockerish.example.com": "172.18.0.5",
}


@pytest.fixture(autouse=True)
def fake_network(monkeypatch):
    def resolve(host):
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            return [ipaddress.ip_address(DNS[host])] if host in DNS else []
    monkeypatch.setattr(tg, "_resolve", resolve)
    monkeypatch.setattr(tg, "own_networks", lambda: (ipaddress.ip_network("172.18.0.0/16"),))
    for var in ("TARGET_ALLOW", "TARGET_DENY", "TARGET_BLOCK_PRIVATE"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("url", [
    "https://public.example.com/login",
    "https://intranet.example.org/app",       # internal apps are the main use case
    "http://10.1.2.3:8080/",
    "http://loginlab:5500/form-login",        # practice targets, by name
    "https://unknown.invalid/",               # unresolvable: fails later, not a guard matter
])
def test_allowed(url):
    check_target(url)


@pytest.mark.parametrize("url,why", [
    ("http://169.254.169.254/latest/meta-data/", "metadata"),
    ("https://sneaky.example.com/", "metadata"),             # a public name pointing at metadata
    ("http://rebind.example.com/", "loopback"),
    ("http://127.0.0.1:8001/", "loopback"),
    ("http://[::1]/", "loopback"),
    ("http://postgres:5432/", "AuthRecon"),
    ("http://portal:9000/api/auth/login", "AuthRecon"),
    ("http://host.docker.internal:9000/", "AuthRecon"),
    ("http://172.18.0.7:8000/", "internal Docker network"),
    ("https://dockerish.example.com/", "internal Docker network"),
    ("file:///etc/passwd", "http"),
    ("javascript:alert(1)", "http"),
])
def test_blocked(url, why):
    with pytest.raises(TargetBlocked) as exc:
        check_target(url)
    assert why.lower() in str(exc.value).lower()


def test_admin_allow_and_deny(monkeypatch):
    monkeypatch.setenv("TARGET_ALLOW", "host.docker.internal, 172.18.0.0/16")
    check_target("http://host.docker.internal:8080/")
    check_target("http://172.18.0.7/")
    monkeypatch.setenv("TARGET_DENY", "public.example.com, 10.20.0.0/16")
    assert not is_allowed("https://public.example.com/")
    assert not is_allowed("https://intranet.example.org/")


def test_block_private_switch(monkeypatch):
    monkeypatch.setenv("TARGET_BLOCK_PRIVATE", "true")
    assert not is_allowed("https://intranet.example.org/")
    assert is_allowed("https://public.example.com/")


def test_fast_path_without_dns_checks_names_and_literal_ips():
    assert not is_allowed("http://169.254.169.254/", resolve=False)
    assert not is_allowed("http://redis:6379/", resolve=False)
    assert is_allowed("https://public.example.com/", resolve=False)


def test_detection_refuses_a_redirect_to_metadata():
    import requests

    from app.services.auth_detection import BlockedRedirect, _guard_redirects

    response = requests.Response()
    response.status_code = 302
    response.url = "https://public.example.com/login"
    response.headers["location"] = "http://169.254.169.254/latest/meta-data/"
    with pytest.raises(BlockedRedirect):
        _guard_redirects(response)
    response.headers["location"] = "/dashboard"
    _guard_redirects(response)  # same-site redirect is fine


def test_submit_refuses_a_blocked_target(db_session, monkeypatch):
    """The API answers 422 before any detection or queueing happens."""
    import asyncio

    from fastapi import HTTPException

    from app.api.runs import _guard_target

    with pytest.raises(HTTPException) as exc:
        asyncio.run(_guard_target("http://169.254.169.254/"))
    assert exc.value.status_code == 422 and "not allowed" in exc.value.detail
