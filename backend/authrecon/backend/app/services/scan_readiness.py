"""Scan readiness: will this login make a good Tenable WAS scan, and what
settings should the scan start with?

Deterministic rules over what a run already captured: session cookies and
their lifetimes, the post-login replay HAR (the landing page re-loaded with
only the captured cookies), the post-login page's links, the detection
redirect chain and the tech fingerprint. No AI.

The result is a starting point, not a final configuration: one login cannot
show what a multi-hour scan will hit. The scan-export analyzer refines it.
Output holds no secrets: cookie and header *names*, hosts and URL paths only.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit

from app.core.urls import stable_page_url

VERSION = 1

_LOGOUT_WORDS = re.compile(r"log[\s_-]?out|sign[\s_-]?out|log[\s_-]?off|sign[\s_-]?off|end[\s_-]?session", re.I)
_DESTRUCTIVE_WORDS = re.compile(
    r"\b(delete|remove|deactivate|disable|destroy|terminate|unsubscribe|close[\s_-]?account|reset)\b", re.I)
_LOGIN_PATH = re.compile(r"log[\s_-]?in|sign[\s_-]?in|auth|sso|saml|oauth|adfs", re.I)
_IDP_HOSTS = re.compile(
    r"(^|\.)(login\.microsoftonline\.com|login\.windows\.net|okta\.com|oktapreview\.com|auth0\.com|"
    r"accounts\.google\.com|onelogin\.com|pingidentity\.com|duosecurity\.com|b2clogin\.com)$", re.I)
# Third-party CDNs, analytics, monitoring and consent services: never the app's
# own API, so not worth suggesting as an additional scan target.
_STATIC_HOSTS = re.compile(
    r"(^|\.)(googleapis\.com|gstatic\.com|cloudflare\.com|cdnjs\.cloudflare\.com|jsdelivr\.net|unpkg\.com|"
    r"fontawesome\.com|bootstrapcdn\.com|jquery\.com|typekit\.net|"
    r"google-analytics\.com|googletagmanager\.com|doubleclick\.net|googlesyndication\.com|googleadservices\.com|"
    r"hotjar\.com|clarity\.ms|optimizely\.com|mixpanel\.com|amplitude\.com|fullstory\.com|heapanalytics\.com|"
    r"quantserve\.com|adobedtm\.com|omtrdc\.net|demdex\.net|connect\.facebook\.net|"
    r"newrelic\.com|nr-data\.net|sentry\.io|segment\.(com|io)|datadoghq\.(com|eu)|browser-intake-datadoghq\.(com|eu)|"
    r"cookielaw\.org|onetrust\.com|cookiebot\.com|trustarc\.com)$", re.I)
_WAF_HEADERS = {
    "cf-ray": "Cloudflare", "x-sucuri-id": "Sucuri", "x-iinfo": "Imperva", "x-cdn": "Imperva",
    "x-akamai-transformed": "Akamai", "akamai-grn": "Akamai", "x-amzn-waf-action": "AWS WAF",
    "x-azure-ref": "Azure Front Door",
}
_WAF_COOKIES = {
    "__cf_bm": "Cloudflare", "cf_clearance": "Cloudflare", "incap_ses": "Imperva", "visid_incap": "Imperva",
    "ak_bmsc": "Akamai", "_abck": "Akamai", "bm_sz": "Akamai", "aws-waf-token": "AWS WAF",
}
_SPA_FRAMEWORKS = ("react", "angular", "vue", "svelte", "ember", "next.js", "nuxt")
SLOW_MS = 5000


# --- inputs -----------------------------------------------------------------------

def har_signals(har_bytes: bytes | None, landing_url: str | None) -> dict[str, Any] | None:
    """Summarise a post-login replay HAR: counts, hosts and flags only."""
    if not har_bytes:
        return None
    try:
        entries = json.loads(har_bytes).get("log", {}).get("entries", [])
    except (ValueError, AttributeError):
        return None
    if not isinstance(entries, list) or not entries:
        return None

    landing_host = (urlsplit(landing_url or "").hostname or "").lower()
    hosts: dict[str, int] = {}
    statuses: dict[str, int] = {}
    bearer = slow = 0
    max_ms = 0
    retry_after = False
    waf: set[str] = set()
    first_redirect_to_login = False

    for i, entry in enumerate(entries):
        req, resp = entry.get("request") or {}, entry.get("response") or {}
        url = req.get("url") or ""
        host = (urlsplit(url).hostname or "").lower()
        if host and host != landing_host:
            hosts[host] = hosts.get(host, 0) + 1
        status = resp.get("status")
        if isinstance(status, int) and status >= 400:
            statuses[str(status)] = statuses.get(str(status), 0) + 1
        for h in req.get("headers") or []:
            if (h.get("name") or "").lower() == "authorization" and (h.get("value") or "").lower().startswith("bearer"):
                bearer += 1
                break
        for h in resp.get("headers") or []:
            name = (h.get("name") or "").lower()
            if name in _WAF_HEADERS:
                waf.add(_WAF_HEADERS[name])
            if name == "retry-after":
                retry_after = True
            if name == "server" and re.search(r"cloudflare|akamai|imperva|sucuri", h.get("value") or "", re.I):
                waf.add(re.search(r"cloudflare|akamai|imperva|sucuri", h["value"], re.I).group(0).title())
            if name == "set-cookie":
                cookie_name = (h.get("value") or "").split("=", 1)[0].strip().lower()
                for prefix, vendor in _WAF_COOKIES.items():
                    if cookie_name.startswith(prefix):
                        waf.add(vendor)
        elapsed = entry.get("time")
        if isinstance(elapsed, (int, float)):
            max_ms = max(max_ms, int(elapsed))
            if elapsed > SLOW_MS:
                slow += 1
        if i == 0 and isinstance(status, int) and 300 <= status < 400:
            target = urljoin(url, resp.get("redirectURL") or "")
            first_redirect_to_login = bool(_LOGIN_PATH.search(urlsplit(target).path))

    return {
        "requests": len(entries),
        "other_hosts": dict(sorted(hosts.items(), key=lambda kv: -kv[1])[:20]),
        "error_statuses": statuses,
        "bearer_requests": bearer,
        "slow_requests": slow,
        "max_ms": max_ms,
        "retry_after": retry_after,
        "waf": sorted(waf),
        "landing_redirected_to_login": first_redirect_to_login,
    }


class _Links(HTMLParser):
    """Links and buttons on the post-login page: (text, href)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str]] = []
        self._open: list[tuple[str, str, list[str]]] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "button"):
            self._open.append((tag, a.get("href") or a.get("formaction") or "", []))
        elif tag == "form":
            self.items.append(("", a.get("action") or ""))
        elif tag == "input" and (a.get("type") or "").lower() in ("submit", "button"):
            self.items.append((a.get("value") or "", a.get("formaction") or ""))

    def handle_endtag(self, tag):
        if self._open and self._open[-1][0] == tag:
            _, href, parts = self._open.pop()
            self.items.append((" ".join(" ".join(parts).split()), href))

    def handle_data(self, data):
        for _, _, parts in self._open:
            parts.append(data)


def _links(html: str | None) -> list[tuple[str, str]]:
    parser = _Links()
    if html:
        try:
            parser.feed(html)
            parser.close()
        except Exception:
            pass
    return parser.items


def _path(base: str, href: str) -> str | None:
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None
    absolute = urljoin(base, href)
    parts = urlsplit(absolute)
    if parts.scheme not in ("http", "https"):
        return None
    if (parts.hostname or "").lower() != (urlsplit(base).hostname or "").lower():
        return None
    return parts.path or "/"


def _exclusion_regex(path: str) -> str:
    """A WAS exclusion line (case-sensitive regex, matched anywhere in the URL)."""
    return re.escape(path).replace("\\/", "/")


# --- assessment -----------------------------------------------------------------------

def assess(
    *,
    auth_type: str | None,
    target_url: str,
    final_url: str | None,
    pattern: str | None,
    post_auth_html: str | None,
    security_context: dict | None,
    tech_fingerprint: dict | None,
    detected_auth: dict | None,
    har: dict | None,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    scope_exclude: list[dict[str, str]] = []
    scope_include: list[str] = []
    other_targets: list[dict[str, Any]] = []
    performance: list[dict[str, str]] = []
    selenium: list[dict[str, str]] = []
    session: dict[str, str | None] = {"cookie": None, "header": None}

    def check(status: str, title: str, detail: str, check_id: str) -> None:
        checks.append({"id": check_id, "status": status, "title": title, "detail": detail})

    auth_type = (auth_type or "").lower()
    landing = final_url or target_url
    target_host = (urlsplit(target_url).hostname or "").lower()

    # Authentication method
    if auth_type in ("basic_auth", "digest_auth", "windows_integrated"):
        check("ok", "HTTP authentication",
              "The scanner logs in with its HTTP authentication settings; there is no form or session to lose.",
              "auth_http")
    elif not pattern:
        check("bad", "No success text to verify the login",
              "Nothing on the post-login page is absent from the login page, so the scanner cannot tell "
              "whether it is still logged in. Pick text that only appears when logged in before scanning.",
              "pattern_missing")
    else:
        check("ok", "Login can be verified", f"The scanner checks for “{pattern[:80]}” after logging in.",
              "pattern_ok")

    # Session cookies
    cookies = ((security_context or {}).get("cookies") or {}).get("cookies") or []
    auth_names = [c for c in (tech_fingerprint or {}).get("auth_cookies") or [] if isinstance(c, str)]
    by_name = {c.get("name"): c for c in cookies if isinstance(c, dict) and c.get("name")}
    auth_cookies = [by_name[n] for n in auth_names if n in by_name] or [
        c for c in by_name.values() if c.get("http_only") and (c.get("entropy_score") or 0) >= 0.6]
    if auth_type not in ("basic_auth", "digest_auth", "windows_integrated"):
        if auth_cookies:
            session["cookie"] = _likeliest_session_cookie(auth_cookies)["name"]
        elif not by_name and not (har or {}).get("bearer_requests"):
            check("bad", "No session cookie or token seen",
                  "After logging in the site set no cookies and no API calls carried a token, so the scanner "
                  "has nothing to keep its session with. Check the run's timeline and HAR.", "session_none")
        ttls = [c.get("ttl_seconds") for c in auth_cookies if isinstance(c.get("ttl_seconds"), int)]
        shortest = min(ttls) if ttls else None
        if shortest is not None and shortest < 300:
            check("bad", f"Session cookie expires in {shortest // 60 or 1} min",
                  "Scans run for hours. The scanner re-logs in when it notices, but expect many re-logins "
                  "(plugin 98043) or an aborted scan (98044). Ask for a longer session timeout for the scan account.",
                  "session_short")
        elif shortest is not None and shortest < 1800:
            check("warn", f"Session cookie expires in {shortest // 60} min",
                  "The scanner will have to re-log in during the scan; keep the success text reliable.",
                  "session_short")

    # Post-login replay: does the session survive on cookies alone?
    if har:
        if not (har.get("landing_redirected_to_login") or har.get("error_statuses", {}).get("401")):
            check("ok", "The session survives on cookies alone",
                  "Re-loading the landing page with only the captured cookies stayed logged in, so the scanner's "
                  "HTTP plugins will audit it authenticated.", "session_portable")
        if har.get("landing_redirected_to_login") or har.get("error_statuses", {}).get("401"):
            check("bad", "The session does not survive on cookies alone",
                  "Re-loading the landing page with only the captured cookies "
                  + ("was sent back to the login page" if har.get("landing_redirected_to_login")
                     else f"got {har['error_statuses']['401']} × 401")
                  + ". The scanner's HTTP plugins carry cookies, so they would audit this app logged out. "
                  "The session is probably tied to a token in browser storage, the client IP or a one-time value.",
                  "session_not_portable")
        if har.get("bearer_requests"):
            session["header"] = "Authorization"
            check("warn", "API calls use a bearer token",
                  f"{har['bearer_requests']} request(s) after login sent an Authorization header. Set the "
                  "scan's session header to Authorization so the scanner tracks it.", "bearer")
        if har.get("waf"):
            vendors = ", ".join(har["waf"])
            check("warn", f"A WAF or bot protection is in front ({vendors})",
                  "It may block or slow the scan. Ask for the scanner's IP to be allowed, and turn on the "
                  "Scan ID header so the traffic can be identified.", "waf")
            performance.append({"setting": "Add Scan ID HTTP Header", "value": "Enabled",
                                "why": f"{vendors} detected: lets the site's team allow-list or spot scan traffic."})
            performance.append({"setting": "Max Number of HTTP Requests Per Second", "value": "10",
                                "why": "Lower than the default 25 to avoid tripping rate rules."})
        if har.get("error_statuses", {}).get("429") or har.get("retry_after"):
            check("warn", "The site rate-limits", "It answered 429 / Retry-After during one page load.",
                  "rate_limited")
            performance.append({"setting": "Max Number of HTTP Requests Per Second", "value": "5",
                                "why": "The site rate-limits (429)."})
            performance.append({"setting": "Slow down the scan when network congestion is detected",
                                "value": "Enabled", "why": "The site rate-limits."})
        if har.get("slow_requests"):
            seconds = har["max_ms"] // 1000
            check("warn", "Slow responses",
                  f"{har['slow_requests']} request(s) took over {SLOW_MS // 1000} s (slowest {seconds} s).",
                  "slow")
            performance.append({"setting": "Network Timeout (In Seconds)", "value": str(max(60, seconds * 2)),
                                "why": f"Responses take up to {seconds} s; the default is 30."})
            selenium.append({"setting": "Page Rendering Delay", "value": str(max(30000, har["max_ms"] * 2)),
                             "why": "Slow pages need longer to render after login."})
        for host, count in (har.get("other_hosts") or {}).items():
            if _IDP_HOSTS.search(host) or _STATIC_HOSTS.search(host):
                continue
            other_targets.append({"host": host, "requests": count})
        if other_targets:
            names = ", ".join(t["host"] for t in other_targets[:3])
            check("warn", "The app calls other hosts",
                  f"After login the page called {names}. The scanner skips other domains (not_in_domain): "
                  "if that is the app's API, scan it as an additional target.", "other_hosts")

    # Identity provider on another domain
    chain_hosts = {(urlsplit(u).hostname or "").lower() for u in (detected_auth or {}).get("redirect_chain") or []
                   if isinstance(u, str)}
    idp = sorted(h for h in chain_hosts if h and h != target_host)
    if idp:
        check("info", "Login goes through another domain",
              f"Sign-in redirects through {', '.join(idp[:3])}. The scanner keeps to the target's domain, so "
              "the identity provider is not scanned; the .side script still logs in through it.", "idp")

    # Post-login page: logout and destructive links
    logout_paths: set[str] = set()
    destructive: set[str] = set()
    for text, href in _links(post_auth_html):
        path = _path(landing, href)
        if not path:
            continue
        if _LOGOUT_WORDS.search(text) or _LOGOUT_WORDS.search(path):
            logout_paths.add(path)
        elif _DESTRUCTIVE_WORDS.search(text) or _DESTRUCTIVE_WORDS.search(path):
            destructive.add(path)
    for path in sorted(logout_paths):
        if "logout" in path:
            continue  # the scan's default exclusion "logout" already matches (case-sensitive)
        scope_exclude.append({"regex": _exclusion_regex(path), "why": "Logout link on the post-login page"})
    for path in sorted(destructive)[:10]:
        scope_exclude.append({"regex": _exclusion_regex(path),
                              "why": "Looks destructive (delete/reset/deactivate); review before excluding"})
    if logout_paths:
        covered = all("logout" in p for p in logout_paths)
        check("ok", "Logout link found",
              "The scan's default \u201clogout\u201d exclusion already covers it." if covered else
              "Excluding it (below) keeps the scanner from logging itself out (plugin 98043/98044).", "logout_found")
    elif auth_type not in ("basic_auth", "digest_auth", "windows_integrated"):
        check("info", "No logout link found on the landing page",
              "Keep the default “logout” exclusion; add the app's logout URL if it uses another word.",
              "logout_missing")

    # Seed the crawl with the landing page when it differs from the login URL
    stable_landing = stable_page_url(landing)
    if stable_landing and urlsplit(stable_landing).path not in ("", "/", urlsplit(target_url).path):
        scope_include.append(stable_landing)

    # Single-page apps
    frameworks = [f for f in (tech_fingerprint or {}).get("js_frameworks") or [] if isinstance(f, str)]
    if any(any(s in f.lower() for s in _SPA_FRAMEWORKS) for f in frameworks):
        selenium.append({"setting": "Script Completion Delay", "value": "8000",
                         "why": f"Single-page app ({', '.join(frameworks[:2])}): give rendered content time to appear."})
        check("info", "Single-page app",
              "If the app has an OpenAPI/Swagger definition, add it to the scan's scope: the crawler finds "
              "API endpoints far better from a spec.", "spa")

    statuses = [c["status"] for c in checks]
    grade = "poor" if "bad" in statuses else "caution" if "warn" in statuses else "good"
    summary = {
        "good": "Start with the settings below.",
        "caution": "Review the warnings before scanning.",
        "poor": "Fix the problems marked below before scanning.",
    }[grade]
    return {
        "version": VERSION,
        "grade": grade,
        "summary": summary,
        "checks": checks,
        "settings": {
            "scope": {"include_urls": scope_include, "exclude_regex": scope_exclude,
                      "additional_targets": other_targets[:5]},
            "session": session,
            "performance": _dedupe(performance),
            "selenium": _dedupe(selenium),
        },
    }


_SESSION_NAME = re.compile(r"sess|sid", re.I)
_SESSIONISH = re.compile(r"auth|token|jwt|login", re.I)


def _likeliest_session_cookie(cookies: list[dict]) -> dict:
    """Of several auth cookies, the one most likely to carry the session:
    session-like name, HttpOnly, no expiry (a browser-session cookie), high entropy."""
    def score(c: dict) -> tuple:
        name = c.get("name") or ""
        return (bool(_SESSION_NAME.search(name)), bool(_SESSIONISH.search(name)), bool(c.get("http_only")),
                c.get("expires") is None and c.get("ttl_seconds") is None, c.get("entropy_score") or 0)
    return max(cookies, key=score)


def _dedupe(items: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    """Keep the first (strongest) suggestion per setting; rules run strictest-first is not
    guaranteed, so for request rates keep the lowest value."""
    out: dict[str, dict[str, str]] = {}
    for item in items:
        prev = out.get(item["setting"])
        if prev is None:
            out[item["setting"]] = item
        elif prev["value"].isdigit() and item["value"].isdigit() and "Per Second" in item["setting"]:
            if int(item["value"]) < int(prev["value"]):
                out[item["setting"]] = item
    return list(out.values())
