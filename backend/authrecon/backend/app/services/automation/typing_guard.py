"""Refuse to type a password on a page outside the run's allowed hosts.

The worker sets the policy once per run (each RQ job runs in its own forked
process, one run at a time). Every place that types a password calls
ensure_safe_to_type() with the page it is about to type into first, so a login
that redirects to an unexpected site (an open redirect, a lookalike domain, a
page steering an AI-started run) stops instead of handing the password over.
With no policy set (unit tests, direct calls) nothing is checked.
"""
from __future__ import annotations

from app.services.automation.types import AutomationFailure
from app.services.credential_domains import host_matches, host_of, is_idp_host

_allowed: list[str] | None = None


class TypingBlocked(AutomationFailure):
    """The login form is on a host this run's credentials are not allowed on."""


def set_policy(allowed_hosts: list[str] | None) -> None:
    global _allowed
    _allowed = list(allowed_hosts) if allowed_hosts is not None else None


def clear_policy() -> None:
    set_policy(None)


def ensure_safe_to_type(current_url: str | None) -> None:
    if _allowed is None:
        return
    host = host_of(current_url)
    if host and (host_matches(host, _allowed) or is_idp_host(host)):
        return
    raise TypingBlocked(
        f"Stopped before entering the password: the login form is on {host or 'an unknown page'}, which is not "
        f"an allowed domain for this run ({', '.join(_allowed)}). If this site is legitimate, add it to the "
        "stored credential's allowed domains (New Run › Saved credential › Edit domains).")
