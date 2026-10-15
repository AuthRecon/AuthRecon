"""URL helpers."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def strip_userinfo(url: str | None) -> str | None:
    """Drop ``user:password@`` from a URL.

    Basic-auth automation loads ``https://user:pass@host/`` so the browser can
    answer the challenge; the browser then reports that URL back as the
    current URL. It must never be stored or shown with the credentials in it.
    """
    if not url:
        return url
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


# Single-use or secret sign-in parameters (OAuth/OIDC, SAML, CAS). A URL that
# carries them works once: a scanner that loads it later gets an error page.
ONE_TIME_PARAMS = frozenset({
    "code", "state", "session_state", "id_token", "access_token", "refresh_token", "token_type",
    "expires_in", "iss", "client_info", "nonce", "ticket", "samlresponse", "samlart", "relaystate",
    "oauth_token", "oauth_verifier",
})


def _without_one_time(part: str) -> str:
    from urllib.parse import parse_qsl, urlencode

    pairs = parse_qsl(part, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if k.lower() not in ONE_TIME_PARAMS]
    return part if len(kept) == len(pairs) else urlencode(kept)


def stable_page_url(url: str | None) -> str | None:
    """A URL safe to give a scanner as the page to verify: no credentials and
    no single-use sign-in parameters (in the query or the fragment)."""
    url = strip_userinfo(url)
    if not url:
        return url
    parts = urlsplit(url)
    query = _without_one_time(parts.query)
    fragment = _without_one_time(parts.fragment) if "=" in parts.fragment else parts.fragment
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, fragment))
