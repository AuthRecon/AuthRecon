from __future__ import annotations

import logging
from html.parser import HTMLParser
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse

import requests
from requests import Response

logger = logging.getLogger(__name__)

_FRAMEWORK_SIGNATURES: dict[str, Sequence[str]] = {
    "React": ("react", "react-dom", "next", "gatsby"),
    "Angular": ("angular", "@angular", "ng-"),
    "Vue.js": ("vue", "nuxt"),
    "Svelte": ("svelte", "vite\\/"),
    "Ember.js": ("ember", "ember-cli"),
    "jQuery": ("jquery",),
    "Alpine.js": ("alpinejs", "alpine.js"),
}

_LIBRARY_SIGNATURES: dict[str, Sequence[str]] = {
    "Bootstrap": ("bootstrap",),
    "Tailwind": ("tailwind",),
    "Moment.js": ("moment",),
    "Lodash": ("lodash", "underscore"),
    "Datadog RUM": ("datadog", "dd-rum"),
    "Adobe Launch": ("adobe", "launch-"),
}

_CMS_HINTS: dict[str, Sequence[str]] = {
    "WordPress": ("wp-content", "wp-includes", "wordpress"),
    "Drupal": ("drupal",),
    "Sitecore": ("sitecore",),
    "SharePoint": ("sharepoint",),
    "Adobe Experience Manager": ("aem", "adobeaemcloud"),
}

_AUTH_COOKIE_KEYWORDS: tuple[str, ...] = (
    "auth",
    "session",
    "sess",
    "token",
    "jwt",
    "sso",
    "login",
    "azure",
    "aad",
)

_SECURITY_HEADERS: tuple[str, ...] = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
)


class _HtmlFingerprintParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.script_sources: list[str] = []
        self.meta_entries: list[tuple[str | None, str]] = []
        self.link_hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # pragma: no cover - best effort parsing
        if not attrs:
            return
        lowered = tag.lower()
        attr_map = {name.lower(): (value or "") for name, value in attrs if name}

        if lowered == "script":
            src = attr_map.get("src")
            if src:
                self.script_sources.append(src.strip())
            return

        if lowered == "meta":
            name = attr_map.get("name") or attr_map.get("property")
            content = attr_map.get("content") or ""
            self.meta_entries.append((name.lower() if name else None, content))
            return

        if lowered == "link":
            href = attr_map.get("href")
            if href:
                self.link_hrefs.append(href.strip())


def analyze_tech_fingerprint(
    target_url: str,
    *,
    html_samples: Iterable[str | None] = (),
    cookies: Sequence[str] | None = None,
    timeout: float = 6.0,
) -> dict[str, Any] | None:
    """
    Collect lightweight technology fingerprinting information for a target.

    Returns a dictionary suitable for JSON storage. All fields are optional and the function
    will never raise; errors are logged and result in None.
    """
    parser = _HtmlFingerprintParser()
    raw_html_chunks: list[str] = []

    for sample in html_samples or []:
        if not sample:
            continue
        try:
            parser.feed(sample)
            raw_html_chunks.append(sample)
        except Exception:  # pragma: no cover - defensive around malformed HTML
            logger.debug("Failed to parse HTML sample during fingerprinting", exc_info=True)
            continue

    combined_html = " ".join(raw_html_chunks).lower()

    headers = {}
    server = None
    powered_by = None
    try:
        response = _safe_fetch_headers(target_url, timeout=timeout)
        if response is not None:
            for key, value in response.headers.items():
                lowered = key.lower()
                if lowered == "set-cookie":
                    continue
                headers[key] = value
            server = response.headers.get("Server")
            powered_by = response.headers.get("X-Powered-By")
    except Exception:  # pragma: no cover - defensive logging
        logger.debug("Header fetch failed during tech fingerprint collection", exc_info=True)

    js_frameworks = _detect_signatures(parser.script_sources, combined_html, _FRAMEWORK_SIGNATURES)
    js_frameworks.extend(_detect_inline_signatures(combined_html))
    js_frameworks = sorted(set(js_frameworks))
    js_libraries = _detect_signatures(parser.script_sources, combined_html, _LIBRARY_SIGNATURES)
    cms_hints = _detect_signatures(parser.script_sources + parser.link_hrefs, combined_html, _CMS_HINTS)

    meta_generators = []
    for name, content in parser.meta_entries:
        if name == "generator" and content:
            meta_generators.append(content.strip())
        elif name and "framework" in name and content:
            meta_generators.append(content.strip())

    cookie_list = _dedupe_sequence(cookies or ())
    auth_cookie_names = [
        name
        for name in cookie_list
        if any(keyword in name.lower() for keyword in _AUTH_COOKIE_KEYWORDS)
    ]

    security_headers = [
        header_name
        for header_name in headers
        if header_name.lower() in _SECURITY_HEADERS
    ]

    observations: list[str] = []
    if server:
        observations.append(f"Server header reports {server}.")
    if powered_by:
        observations.append(f"X-Powered-By header indicates {powered_by}.")
    if js_frameworks:
        observations.append(f"Detected JavaScript frameworks: {', '.join(js_frameworks)}.")
    if js_libraries:
        observations.append(f"Detected JavaScript libraries: {', '.join(js_libraries)}.")
    if cms_hints:
        observations.append(f"CMS or platform hints: {', '.join(cms_hints)}.")
    if security_headers:
        observations.append(f"Security headers present: {', '.join(security_headers)}.")
    if auth_cookie_names:
        observations.append(f"Authentication-related cookies: {', '.join(auth_cookie_names)}.")
    if not observations:
        observations.append("No technology fingerprints were identified automatically.")

    return {
        "server": server,
        "powered_by": powered_by,
        "headers": headers,
        "js_frameworks": js_frameworks,
        "js_libraries": js_libraries,
        "cms": cms_hints,
        "meta_generators": meta_generators,
        "security_headers": security_headers,
        "cookies": cookie_list,
        "auth_cookies": auth_cookie_names,
        "observations": observations,
    }


def _detect_signatures(
    script_sources: Sequence[str],
    combined_html: str,
    signatures: dict[str, Sequence[str]],
) -> list[str]:
    detected: set[str] = set()

    for label, patterns in signatures.items():
        if any(pattern in combined_html for pattern in patterns):
            detected.add(label)
            continue
        for source in script_sources:
            src_lower = source.lower()
            if any(pattern in src_lower for pattern in patterns):
                detected.add(label)
                break

    return sorted(detected)


def _detect_inline_signatures(combined_html: str) -> list[str]:
    inline_map: dict[str, Sequence[str]] = {
        "Next.js": ("__next_data__",),
        "Nuxt.js": ("__nuxt__",),
        "Angular": ("ng-version",),
        "Laravel": ("csrf-token", "laravel"),
        "Django": ("csrftoken", "djangosettings"),
    }
    detected: set[str] = set()
    for label, hints in inline_map.items():
        if any(hint in combined_html for hint in hints):
            detected.add(label)
    return sorted(detected)


def _dedupe_sequence(items: Iterable[str]) -> list[str]:
    seen = set()
    ordered = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _safe_fetch_headers(target_url: str, *, timeout: float) -> Response | None:
    # allow_redirects=False prevents SSRF via redirect: a target that redirects to
    # 169.254.169.254 (cloud metadata) or internal IPs would otherwise be followed.
    # Playwright already resolved the real final URL during capture, so we don't
    # need redirect-following here — we capture headers of the initial response
    # (including Location: if a redirect occurs, which is itself useful intel).
    # Scheme check prevents requests from attempting file://, ftp://, etc.
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            logger.debug("Skipping header fetch for non-HTTP/S URL: %s", target_url)
            return None
        return requests.get(target_url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        logger.debug("Primary header fetch failed for %s", target_url, exc_info=True)
        return None
