"""Scan readiness: deterministic grade + starting WAS settings from a run."""
from __future__ import annotations

import json

from app.services.scan_readiness import assess, har_signals

LANDING = "https://app.example.com/dashboard"


def _har(*entries):
    return json.dumps({"log": {"entries": list(entries)}}).encode()


def _entry(url, status=200, time=100, req_headers=(), resp_headers=(), redirect=""):
    return {"request": {"url": url, "headers": [{"name": k, "value": v} for k, v in req_headers]},
            "response": {"status": status, "redirectURL": redirect,
                         "headers": [{"name": k, "value": v} for k, v in resp_headers]},
            "time": time}


def _assess(**kw):
    base = dict(auth_type="form_based", target_url="https://app.example.com/login", final_url=LANDING,
                pattern="Welcome, Jane", post_auth_html="", security_context=None, tech_fingerprint=None,
                detected_auth=None, har=None)
    base.update(kw)
    return assess(**base)


def _ids(result, status=None):
    return {c["id"] for c in result["checks"] if status is None or c["status"] == status}


def _cookie(name, ttl=None, http_only=True, entropy=0.9):
    return {"name": name, "ttl_seconds": ttl, "http_only": http_only, "entropy_score": entropy}


def test_clean_login_is_a_good_candidate():
    ctx = {"cookies": {"cookies": [_cookie("SESSIONID", ttl=7200)]}}
    har = har_signals(_har(_entry(LANDING)), LANDING)
    r = _assess(security_context=ctx, tech_fingerprint={"auth_cookies": ["SESSIONID"]}, har=har)
    assert r["grade"] == "good"
    assert r["settings"]["session"]["cookie"] == "SESSIONID"
    assert r["settings"]["scope"]["include_urls"] == [LANDING]


def test_session_not_portable_when_cookie_replay_lands_on_login():
    har = har_signals(_har(_entry(LANDING, status=302, redirect="/login?next=/dashboard")), LANDING)
    assert har["landing_redirected_to_login"] is True
    r = _assess(har=har, security_context={"cookies": {"cookies": [_cookie("sid")]}})
    assert r["grade"] == "poor"
    assert "session_not_portable" in _ids(r, "bad")


def test_401s_on_replay_also_mean_not_portable():
    har = har_signals(_har(_entry(LANDING), _entry("https://app.example.com/api/me", status=401)), LANDING)
    assert "session_not_portable" in _ids(_assess(har=har), "bad")


def test_short_session_is_flagged():
    ctx = {"cookies": {"cookies": [_cookie("sid", ttl=240)]}}
    r = _assess(security_context=ctx, tech_fingerprint={"auth_cookies": ["sid"]})
    assert "session_short" in _ids(r, "bad")
    ctx = {"cookies": {"cookies": [_cookie("sid", ttl=900)]}}
    assert "session_short" in _ids(_assess(security_context=ctx, tech_fingerprint={"auth_cookies": ["sid"]}), "warn")


def test_bearer_waf_rate_limit_and_slow_responses():
    har = har_signals(_har(
        _entry(LANDING, resp_headers=[("cf-ray", "x"), ("set-cookie", "__cf_bm=abc; path=/")]),
        _entry("https://app.example.com/api/items", req_headers=[("Authorization", "Bearer eyJ...")]),
        _entry("https://app.example.com/api/slow", status=429, time=9000, resp_headers=[("Retry-After", "5")]),
    ), LANDING)
    assert har["waf"] == ["Cloudflare"] and har["bearer_requests"] == 1 and har["slow_requests"] == 1
    r = _assess(har=har)
    assert {"bearer", "waf", "rate_limited", "slow"} <= _ids(r, "warn")
    assert r["settings"]["session"]["header"] == "Authorization"
    perf = {p["setting"]: p["value"] for p in r["settings"]["performance"]}
    assert perf["Max Number of HTTP Requests Per Second"] == "5"  # the strictest rule wins
    assert perf["Network Timeout (In Seconds)"] == "60"
    assert "eyJ" not in json.dumps(r)  # never the token itself


def test_logout_and_destructive_links_become_exclusions():
    html = """<nav><a href="/account/signout">Sign out</a><a href="/logout">Log out</a>
    <a href="/users/42/delete">Delete user</a><a href="https://other.example.org/x">x</a></nav>"""
    r = _assess(post_auth_html=html)
    regexes = [e["regex"] for e in r["settings"]["scope"]["exclude_regex"]]
    assert "/account/signout" in regexes
    assert "/logout" not in regexes  # already covered by the scan's default "logout"
    assert "/users/42/delete" in regexes
    assert "logout_found" in _ids(r, "ok")


def test_other_hosts_but_not_idp_or_cdn():
    har = har_signals(_har(_entry(LANDING), _entry("https://api.example.com/v1/x"),
                           _entry("https://fonts.googleapis.com/css"), _entry("https://login.microsoftonline.com/x")),
                      LANDING)
    r = _assess(har=har)
    assert [t["host"] for t in r["settings"]["scope"]["additional_targets"]] == ["api.example.com"]


def test_analytics_and_consent_hosts_are_not_scan_targets():
    # Seen live: an Optimizely beacon made a clean login look like it needed an extra target.
    har = har_signals(_har(_entry(LANDING), _entry("https://298279967.log.optimizely.com/event"),
                           _entry("https://cdn.cookielaw.org/x.js"), _entry("https://browser-intake-datadoghq.com/r")),
                      LANDING)
    r = _assess(har=har)
    assert r["settings"]["scope"]["additional_targets"] == []
    assert "other_hosts" not in _ids(r)


def test_http_auth_needs_no_session_or_pattern():
    r = _assess(auth_type="basic_auth", pattern=None)
    assert r["grade"] == "good" and "auth_http" in _ids(r, "ok")


def test_missing_pattern_is_poor():
    assert _assess(pattern=None)["grade"] == "poor"


def test_bad_har_is_ignored():
    assert har_signals(b"not json", LANDING) is None
    assert har_signals(None, LANDING) is None


def test_likeliest_session_cookie_among_several():
    ctx = {"cookies": {"cookies": [_cookie("app_persistent", ttl=86400, http_only=False),
                                   _cookie("app_session"), _cookie("prefs", http_only=False, entropy=0.2)]}}
    r = _assess(security_context=ctx, tech_fingerprint={"auth_cookies": ["app_persistent", "app_session"]})
    assert r["settings"]["session"]["cookie"] == "app_session"


def test_portable_session_is_reported_when_replay_ran():
    har = har_signals(_har(_entry(LANDING)), LANDING)
    assert "session_portable" in _ids(_assess(har=har), "ok")
    assert "session_portable" not in _ids(_assess(har=None))


def test_session_named_cookie_beats_other_login_named_cookies():
    ctx = {"cookies": {"cookies": [_cookie("loginlab_persistent", ttl=86400), _cookie("loginlab_session")]}}
    r = _assess(security_context=ctx, tech_fingerprint={"auth_cookies": ["loginlab_persistent", "loginlab_session"]})
    assert r["settings"]["session"]["cookie"] == "loginlab_session"
