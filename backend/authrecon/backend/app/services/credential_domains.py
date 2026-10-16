"""Bind stored credentials to the sites they belong to.

A stored credential lists the domains it may be used on (allowed_domains).
Runs against any other host refuse to use it, so a mistake, or an AI client
steered by text on a hostile page, cannot send a real account's password to
the wrong site. A credential with no domains yet is bound to the host of the
first run that uses it (trust on first use); the owner can edit the list.

Entries are hostnames ("app.example.com") or wildcards ("*.example.com",
which also matches example.com itself). No schemes, paths or ports.
"""
from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlsplit

MAX_DOMAINS = 20
_ENTRY = re.compile(r"^(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")

# Identity providers a login legitimately passes through on its way back to the
# app. Typing a credential there is expected (it is often that IdP's account).
IDP_SUFFIXES = (
    "login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "login.live.com",
    "b2clogin.com", "okta.com", "oktapreview.com", "okta-emea.com", "auth0.com",
    "accounts.google.com", "onelogin.com", "pingidentity.com", "pingone.com", "duosecurity.com",
    "jumpcloud.com", "cyberark.cloud",
)
# Two-label public suffixes, so "registrable domain" is not "co.uk" (small list:
# the fallback is stricter, never looser).
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "gov.au", "co.nz", "govt.nz",
    "co.jp", "co.za", "com.br", "com.mx", "gc.ca", "qc.ca", "on.ca", "ns.ca", "bc.ca", "ab.ca",
}


class CredentialDomainError(ValueError):
    """A credential was used on (or configured for) a host it is not bound to."""


def normalize_domains(entries: Iterable[str]) -> list[str]:
    """Validate and normalise an allowed-domains list (raises ValueError)."""
    out: list[str] = []
    for raw in entries or []:
        entry = (raw or "").strip().lower().rstrip(".")
        if not entry:
            continue
        if "://" in entry or "/" in entry or ":" in entry or "@" in entry:
            raise ValueError(f"'{raw}': use a host name like app.example.com or *.example.com (no scheme, path or port)")
        if not _ENTRY.match(entry):
            raise ValueError(f"'{raw}' is not a valid host name")
        if entry not in out:
            out.append(entry)
    if len(out) > MAX_DOMAINS:
        raise ValueError(f"At most {MAX_DOMAINS} allowed domains")
    return out


def host_of(url: str | None) -> str:
    return (urlsplit(url or "").hostname or "").lower().rstrip(".")


def host_matches(host: str, entries: Iterable[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    for entry in entries or []:
        if entry.startswith("*."):
            base = entry[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == entry:
            return True
    return False


def registrable_domain(host: str) -> str:
    labels = (host or "").lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_idp_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) for s in IDP_SUFFIXES)


def check_credential_for_target(credential, target_url: str) -> bool:
    """Raise CredentialDomainError if ``credential`` may not be used against
    ``target_url``. Binds an unbound credential to the target's host and
    returns True when it did (the caller commits)."""
    host = host_of(target_url)
    if not host:
        raise CredentialDomainError("The target URL has no host.")
    domains = list(getattr(credential, "allowed_domains", None) or [])
    if not domains:
        credential.allowed_domains = [host]
        return True
    if not host_matches(host, domains):
        raise CredentialDomainError(
            f"Stored credential “{credential.name}” is only allowed on {', '.join(domains)}, not {host}. "
            "If this site should use it, add the domain: New Run › Saved credential › Edit domains.")
    return False


def typing_allowed_hosts(target_url: str, credential_domains: Iterable[str] | None) -> list[str]:
    """Where the worker may type a password during a run: the target's host and its
    registrable domain (e.g. sts.example.com for app.example.com), the credential's
    allowed domains, and known identity providers (checked separately)."""
    host = host_of(target_url)
    allowed = [host, f"*.{registrable_domain(host)}"] if host else []
    for entry in credential_domains or []:
        if entry not in allowed:
            allowed.append(entry)
    return allowed
