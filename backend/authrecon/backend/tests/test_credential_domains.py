"""Stored credentials are bound to the domains they may be used on, and the
worker never types a password on a page outside the run's allowed hosts."""
from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.schemas.credential import CredentialCreate, CredentialUpdate
from app.services.automation import typing_guard
from app.services.automation.typing_guard import TypingBlocked, ensure_safe_to_type
from app.services.credential_domains import (
    CredentialDomainError, check_credential_for_target, host_matches, normalize_domains, registrable_domain,
    typing_allowed_hosts,
)


class Cred:
    def __init__(self, domains=None, name="Test account"):
        self.allowed_domains = domains or []
        self.name = name


def test_normalize_and_validate():
    assert normalize_domains([" App.Example.com. ", "*.Example.org", "", "app.example.com"]) == [
        "app.example.com", "*.example.org"]
    for bad in ("https://app.example.com", "app.example.com/login", "app.example.com:8443", "user@x.com", "*.", "a b"):
        with pytest.raises(ValueError):
            normalize_domains([bad])


def test_schema_rejects_urls_in_domains():
    with pytest.raises(ValidationError):
        CredentialCreate(name="x", username="u", secret="s", allowed_domains=["https://x.example.com"])
    assert CredentialUpdate(allowed_domains=None).allowed_domains is None
    assert CredentialUpdate(allowed_domains=["X.example.com"]).allowed_domains == ["x.example.com"]


def test_matching():
    assert host_matches("app.example.com", ["app.example.com"])
    assert not host_matches("evil-app.example.com", ["app.example.com"])
    assert host_matches("example.com", ["*.example.com"]) and host_matches("a.b.example.com", ["*.example.com"])
    assert not host_matches("example.com.evil.net", ["*.example.com"])
    assert not host_matches("notexample.com", ["*.example.com"])


def test_registrable_domain():
    assert registrable_domain("app.example.com") == "example.com"
    assert registrable_domain("portal.service.gov.uk") == "service.gov.uk"
    assert registrable_domain("app.dept.gc.ca") == "dept.gc.ca"


def test_first_use_binds_then_refuses_other_hosts():
    cred = Cred()
    assert check_credential_for_target(cred, "https://app.example.com/login") is True
    assert cred.allowed_domains == ["app.example.com"]
    assert check_credential_for_target(cred, "https://app.example.com/other") is False
    with pytest.raises(CredentialDomainError) as exc:
        check_credential_for_target(cred, "https://evil.example.net/login")
    assert "only allowed on app.example.com" in str(exc.value)


def test_typing_guard():
    try:
        typing_guard.set_policy(typing_allowed_hosts("https://app.example.com/login", ["partner.example.org"]))
        ensure_safe_to_type("https://app.example.com/login")
        ensure_safe_to_type("https://sts.example.com/adfs/ls")          # same organisation
        ensure_safe_to_type("https://partner.example.org/signin")        # explicitly allowed
        ensure_safe_to_type("https://login.microsoftonline.com/common")  # identity provider
        for bad in ("https://example.com.evil.net/login", "https://evil.example.net/", "about:blank"):
            with pytest.raises(TypingBlocked):
                ensure_safe_to_type(bad)
    finally:
        typing_guard.clear_policy()
    ensure_safe_to_type("https://anything.example/")  # no policy: no check


def test_api_refuses_a_credential_on_the_wrong_site(db_session):
    from app.api.runs import _check_credential_domain
    from app.services.credentials import create_credential
    from app.services.profiles import sync_portal_profile

    owner = sync_portal_profile(db_session, str(uuid.uuid4()))
    owner.is_admin = False  # set from the JWT at request time
    cred = create_credential(db_session, owner=owner, payload=CredentialCreate(
        name="corp test", username="u", secret="s", allowed_domains=["app.example.com"]))
    _check_credential_domain(db_session, owner, cred.id, "https://app.example.com/login")
    with pytest.raises(HTTPException) as exc:
        _check_credential_domain(db_session, owner, cred.id, "https://evil.example.net/login")
    assert exc.value.status_code == 422

    other = sync_portal_profile(db_session, str(uuid.uuid4()))
    other.is_admin = False
    with pytest.raises(HTTPException) as exc:  # still owner-only
        _check_credential_domain(db_session, other, cred.id, "https://app.example.com/login")
    assert exc.value.status_code == 403
