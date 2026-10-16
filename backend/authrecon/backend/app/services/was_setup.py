"""What an operator needs to configure an authenticated Tenable WAS scan from a
run, and what to do next when the run failed.

Shared by the run-detail API (the "Tenable WAS setup" card) and the MCP
``get_was_setup`` tool. Never includes credentials: the .side file (which
holds them, by design, for the scanner) is referenced by artifact id only.
"""
from __future__ import annotations

import re
from typing import Any

from app.core.urls import stable_page_url, strip_userinfo

# Auth types a .side (Selenium) script can drive.
_SELENIUM_TYPES = {"form_based", "two_step_form", "azure_ad", "okta", "ldap", "saml", "oauth", "manual_recording"}
_HTTP_CHALLENGE = {
    "basic_auth": ("HTTP Basic", "Use the scan's HTTP authentication settings (Basic) with these credentials."),
    "windows_integrated": ("Windows Integrated (Kerberos/NTLM)",
                           "Use the scan's HTTP authentication settings for NTLM/Kerberos, if your scanner supports it."),
    "digest_auth": ("HTTP Digest", "Use the scan's HTTP authentication settings for Digest, if your scanner supports it."),
}


def _options(run) -> dict:
    return run.options if isinstance(run.options, dict) else {}


def side_verifications(run) -> dict[str, dict]:
    value = _options(run).get("side_verification")
    return value if isinstance(value, dict) else {}


def _side_artifacts(run) -> list:
    return [a for a in (run.artifacts or []) if a.type == "side_file"]


def _role_labels(run) -> dict[str, str]:
    roles = (_options(run).get("scope") or {}).get("roles") or []
    return {r.get("slug"): r.get("label") for r in roles if isinstance(r, dict) and r.get("slug")}


_REGEX_SPECIALS = re.compile(r"([.^$*+?{}\[\]\\|()])")


def pattern_regex(pattern: str | None) -> str | None:
    """The success text as a regex a scanner can match literally.

    Trims page furniture captured with the text (a leading "✅", a trailing
    "×" close button) and escapes only regex metacharacters, so the result
    is readable and pastes cleanly into the scanner.
    """
    if not pattern:
        return None
    text = re.sub(r"^[^\w]+", "", pattern.strip())
    text = re.sub(r"[^\w.!?)\]\"']+$", "", text).strip()
    return _REGEX_SPECIALS.sub(r"\\\1", text) if text else None


def build_was_setup(run) -> dict[str, Any] | None:
    """WAS configuration summary for a succeeded run (None otherwise)."""
    if str(getattr(run.status, "value", run.status)) != "succeeded":
        return None
    auth_type = run.auth_type or ""
    verifications = side_verifications(run)
    labels = _role_labels(run)
    scripts = [
        {
            "artifact_id": a.id,
            "name": a.name,
            "role_slug": a.role_slug,
            "role_label": labels.get(a.role_slug) if a.role_slug else None,
            "verification": verifications.get(a.id),
        }
        for a in sorted(_side_artifacts(run), key=lambda a: a.name)
    ]
    if auth_type in _HTTP_CHALLENGE:
        method, label = "http_auth", _HTTP_CHALLENGE[auth_type][0]
    elif scripts:
        method, label = "selenium", "Selenium script (.side)"
    elif auth_type in _SELENIUM_TYPES:
        method, label = "selenium", "Selenium script (.side) — no script was generated for this run"
    else:
        method, label = "unknown", auth_type or "unknown"

    notes = []
    if method == "http_auth":
        notes.append(_HTTP_CHALLENGE[auth_type][1])
    if method == "selenium" and not pattern_regex(run.pattern):
        notes.append("No reliable success text was found (nothing on the post-login page that is absent from "
                     "the login page). Before scanning, pick text that only appears when logged in, such as "
                     "your username or a 'Log out' link, from the post-login screenshot.")
    if stable_page_url(run.final_url) != strip_userinfo(run.final_url):
        notes.append("The login landed on a URL with one-time sign-in parameters (such as an OAuth code); "
                     "they were removed from the page to verify. If that page shows an error without them, "
                     "use the application's home page instead.")
    if method == "selenium":
        notes.append("Upload the .side file as the scan's Selenium authentication script.")
        notes.append("The .side file contains the login credentials in plain text (the scanner needs them): "
                     "store and share it like a password.")
    return {
        "method": method,
        "method_label": label,
        "login_url": strip_userinfo(run.target_url),
        "page_to_verify": stable_page_url(run.final_url),
        "pattern_to_verify": run.pattern,
        "pattern_regex": pattern_regex(run.pattern),
        "pattern_missing": method == "selenium" and not pattern_regex(run.pattern),
        "scripts": scripts,
        "notes": notes,
        # Grade and starting scan settings (services/scan_readiness.py); None for older runs.
        "readiness": _options(run).get("scan_readiness"),
    }


# --- failure guidance -----------------------------------------------------------

_FAILURES = [
    ("credentials_rejected",
     ("rejected these credentials", "invalid credentials", "login failed:", "authentication failed: invalid"),
     "The site rejected the username or password.",
     ["Check the credentials (and any required domain prefix) and re-run.",
      "AuthRecon did not retry, to avoid locking the account."]),
    ("unreachable",
     ("unreachable", "timed out connecting", "name or service not known", "connection refused", "err_name_not_resolved"),
     "AuthRecon could not reach the target.",
     ["Confirm the URL opens from the AuthRecon server (firewall, VPN, DNS).",
      "Network Tools in the sidebar can test connectivity from the server."]),
    ("fields_not_found",
     ("unable to locate", "could not find", "no login form", "unable to find a submit"),
     "AuthRecon could not find the login fields on the page.",
     ["Try Manual recording: log in yourself in the live browser and AuthRecon builds the script.",
      "If AI suggestions are enabled, an MCP client can propose selectors for a re-run.",
      "If the login sits behind a button or a specific link, set a login hint and re-run."]),
    ("needs_human",
     ("mfa", "captcha", "verification code", "one-time", "authenticator"),
     "The login needs a human step (MFA or CAPTCHA).",
     ["Use a test account without MFA for scanning, or use the scanner's OAuth support where available."]),
    ("unsupported",
     ("not yet supported", "http-level challenge", "unable to determine authentication type"),
     "This login type can't be scripted automatically.",
     ["Follow the guidance in the error message, or try Manual recording."]),
    ("timeout",
     ("timed out", "timeout"),
     "The login didn't finish in time.",
     ["Re-run: slow first page loads are common. If it repeats, try Manual recording."]),
]


def build_failure_guidance(run) -> dict[str, Any] | None:
    """Plain-language category + next steps for a failed run (None otherwise)."""
    if str(getattr(run.status, "value", run.status)) != "failed":
        return None
    text = " ".join(filter(None, [run.error_message or "", " ".join(
        (e.message or "") for e in (run.timeline_events or [])[-15:]
    )])).lower()
    for category, needles, title, steps in _FAILURES:
        if any(n in text for n in needles):
            return {"category": category, "title": title, "next_steps": steps, "error": run.error_message}
    return {"category": "unknown", "title": "The run failed.",
            "next_steps": ["Check the Timeline tab for the last step that ran, then re-run or try Manual recording."],
            "error": run.error_message}


def run_warnings(run) -> list[str]:
    """Warnings on an otherwise successful run (e.g. some roles failed)."""
    roles = (_options(run).get("scope") or {}).get("roles") or []
    failed = [r.get("label") or r.get("username") or "?" for r in roles
              if isinstance(r, dict) and r.get("status") == "failed"]
    if failed and str(getattr(run.status, "value", run.status)) == "succeeded":
        return [f"Login failed for {', '.join(failed)}. Artifacts are available for the other roles."]
    return []
