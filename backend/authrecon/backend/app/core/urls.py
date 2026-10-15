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
