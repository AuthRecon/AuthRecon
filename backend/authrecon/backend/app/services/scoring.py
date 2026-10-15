"""
Weighted Scoring System for Authentication Detection

Part of Signal Fusion Pipeline Phase 3

Replaces hardcoded if/else classification with evidence-based scoring.
Each auth type accumulates points from multiple signals, and the highest
score wins. Confidence is calculated as (score / max_possible_score) * 100.

NO MAGIC NUMBERS: All scores are based on signal strength and evidence.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import logging
from dataclasses import dataclass, field
from typing import Any

LOGGER = logging.getLogger(__name__)


@dataclass
class Signal:
    """A single detection signal with weight and evidence."""

    signal_type: str  # e.g., "header", "url_redirect", "html_content", "tech_fingerprint"
    auth_type: str  # e.g., "azure_ad", "okta", "form_based"
    weight: int  # Points contributed (0-100)
    evidence: str  # Human-readable explanation
    source: str | None = None  # Optional: which function/module detected this


@dataclass
class AuthTypeScore:
    """Accumulated score for a specific auth type."""

    auth_type: str
    total_score: int = 0
    signals: list[Signal] = field(default_factory=list)

    def add_signal(self, signal: Signal) -> None:
        """Add a signal and accumulate its weight."""
        self.signals.append(signal)
        self.total_score += signal.weight

    def get_confidence(self, max_possible: int) -> int:
        """Calculate confidence as percentage of maximum possible score."""
        if max_possible == 0:
            return 0
        # Ensure confidence doesn't exceed 100
        return min(int((self.total_score / max_possible) * 100), 100)


class ScoringMatrix:
    """
    Accumulates signals and scores for all auth types.

    Usage:
        matrix = ScoringMatrix()
        matrix.add_signal(Signal("header", "basic_auth", 100, "WWW-Authenticate: Basic"))
        result = matrix.get_best_match()
    """

    def __init__(self):
        self.scores: dict[str, AuthTypeScore] = {}
        self.max_possible_score = 100  # Maximum theoretical score (definitive signal)

    def add_signal(self, signal: Signal) -> None:
        """Add a signal to the matrix."""
        if signal.auth_type not in self.scores:
            self.scores[signal.auth_type] = AuthTypeScore(auth_type=signal.auth_type)

        self.scores[signal.auth_type].add_signal(signal)
        LOGGER.debug(
            f"Signal added: {signal.signal_type} → {signal.auth_type} "
            f"(+{signal.weight} points, total={self.scores[signal.auth_type].total_score})"
        )

    def get_best_match(self, threshold: int = 30) -> tuple[str, int, list[Signal]] | None:
        """
        Get the auth type with the highest score.

        Args:
            threshold: Minimum score required to avoid "generic" fallback

        Returns:
            Tuple of (auth_type, confidence, signals) or None if no scores above threshold
        """
        if not self.scores:
            return None

        # Find highest scoring auth type
        best = max(self.scores.values(), key=lambda s: s.total_score)

        if best.total_score < threshold:
            LOGGER.info(
                f"Best match '{best.auth_type}' scored {best.total_score} "
                f"(below threshold {threshold}), falling back to generic"
            )
            return None

        confidence = best.get_confidence(self.max_possible_score)

        LOGGER.info(
            f"Best match: {best.auth_type} "
            f"(score={best.total_score}, confidence={confidence}%, signals={len(best.signals)})"
        )

        return best.auth_type, confidence, best.signals

    def get_all_scores(self) -> dict[str, int]:
        """Get all auth type scores for debugging."""
        return {auth_type: score.total_score for auth_type, score in self.scores.items()}


# Signal weight definitions (evidence-based, not arbitrary)
# These weights represent the strength of evidence for each signal

# DEFINITIVE signals (100 points) - Immediate, unambiguous classification
WEIGHT_DEFINITIVE = 100

# STRONG signals (30-40 points) - Very reliable indicators
WEIGHT_STRONG_HIGH = 40
WEIGHT_STRONG_MED = 35
WEIGHT_STRONG_LOW = 30

# MODERATE signals (15-25 points) - Reliable when combined with other signals
WEIGHT_MODERATE_HIGH = 25
WEIGHT_MODERATE_MED = 20
WEIGHT_MODERATE_LOW = 15

# WEAK signals (5-10 points) - Hints that need corroboration
WEIGHT_WEAK_HIGH = 10
WEIGHT_WEAK_MED = 7
WEIGHT_WEAK_LOW = 5


def _lower_keys(headers: dict[str, str]) -> dict[str, str]:
    """
    HTTP header names are case-insensitive per RFC 7230 — a server is just as
    entitled to send "Www-Authenticate" as "WWW-Authenticate". `requests`
    preserves whatever casing the server sends once a response's headers are
    converted to a plain dict (its own `CaseInsensitiveDict` is only
    case-insensitive as long as it stays a CaseInsensitiveDict). Every lookup
    in this module must go through this normalizer first — a single real
    target (Heroku, in the first case this caught) sending `Www-Authenticate`
    instead of `WWW-Authenticate` silently voided the WWW-Authenticate check
    below, causing a confident basic_auth signal to be missed entirely.
    """
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def analyze_headers_for_signals(
    response_headers: dict[str, str],
    history_headers: list[dict[str, str]] | None = None
) -> list[Signal]:
    """
    Extract authentication signals from HTTP response headers.

    Args:
        response_headers: Final response headers
        history_headers: Headers from redirect chain (optional)

    Returns:
        List of Signal objects
    """
    signals = []

    # Combine all headers (history + final response), normalizing casing once
    # here rather than trusting every call site to hand us consistently-cased
    # keys — see _lower_keys().
    all_headers = []
    if history_headers:
        all_headers.extend(_lower_keys(h) for h in history_headers)
    all_headers.append(_lower_keys(response_headers))

    # Check for WWW-Authenticate header (DEFINITIVE)
    for headers in all_headers:
        www_auth = headers.get("www-authenticate", "")
        if www_auth:
            www_auth_lower = www_auth.lower()
            if "digest" in www_auth_lower:
                # Digest and Basic share the WWW-Authenticate challenge
                # mechanism but need completely different automation (Digest
                # requires nonce/response hashing; Basic is a static
                # base64 header) — they must never share an auth_type, or
                # whichever handler the shared type dispatches to will fail
                # confusingly instead of honestly reporting "not supported".
                signals.append(Signal(
                    signal_type="header",
                    auth_type="digest_auth",
                    weight=WEIGHT_DEFINITIVE,
                    evidence=f"WWW-Authenticate indicates Digest auth: {www_auth[:50]}",
                    source="analyze_headers_for_signals"
                ))
            elif "basic" in www_auth_lower:
                signals.append(Signal(
                    signal_type="header",
                    auth_type="basic_auth",
                    weight=WEIGHT_DEFINITIVE,
                    evidence=f"WWW-Authenticate header: {www_auth[:50]}",
                    source="analyze_headers_for_signals"
                ))
            elif "negotiate" in www_auth_lower or "ntlm" in www_auth_lower:
                # Windows Integrated Auth (Kerberos/NTLM). Checked after Basic:
                # servers often offer "Negotiate, NTLM, Basic", and Basic is
                # the one we can automate. A browser script can't answer this
                # challenge, so it gets its own type and an honest "configure
                # it in the scanner" result instead of a failed form login.
                signals.append(Signal(
                    signal_type="header",
                    auth_type="windows_integrated",
                    weight=WEIGHT_DEFINITIVE,
                    evidence=f"WWW-Authenticate indicates Windows Integrated Auth: {www_auth[:50]}",
                    source="analyze_headers_for_signals"
                ))
            elif "bearer" in www_auth_lower or "oauth" in www_auth_lower:
                signals.append(Signal(
                    signal_type="header",
                    auth_type="oauth",
                    weight=WEIGHT_STRONG_MED,
                    evidence=f"WWW-Authenticate indicates OAuth/Bearer: {www_auth[:50]}",
                    source="analyze_headers_for_signals"
                ))

    # Check Set-Cookie headers for auth indicators.
    # Deliberately weak and generic (never auth-type-specific on its own):
    # a session cookie gets set on almost any response — including a bare
    # 401 Basic Auth challenge, which sets one before any login has even
    # been attempted (confirmed against a real target). A cookie proves a
    # session exists; it says nothing about *how* you'd authenticate. This
    # must never be strong enough, alone, to push a classification over the
    # confidence threshold — it exists only to corroborate another signal.
    auth_cookie_count = 0
    session_cookie_names = []

    for headers in all_headers:
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            set_cookie_lower = set_cookie.lower()
            # Extract cookie name (before '=')
            cookie_name = set_cookie.split("=")[0].strip()

            # Check for auth-related keywords
            auth_keywords = ["auth", "session", "sess", "token", "jwt", "sso", "login", "azure", "aad"]
            if any(keyword in set_cookie_lower for keyword in auth_keywords):
                auth_cookie_count += 1
                session_cookie_names.append(cookie_name)

    if auth_cookie_count > 0:
        weight = min(WEIGHT_WEAK_LOW + auth_cookie_count, WEIGHT_WEAK_HIGH)
        signals.append(Signal(
            signal_type="header",
            auth_type="form_based",  # weak hint only — see comment above
            weight=weight,
            evidence=f"Set-Cookie headers with auth keywords: {', '.join(session_cookie_names[:3])}",
            source="analyze_headers_for_signals"
        ))

    # Check Location header for redirect patterns
    for headers in all_headers:
        location = headers.get("location", "")
        if location:
            location_lower = location.lower()

            # Microsoft/Azure AD redirect
            if any(domain in location_lower for domain in [
                "login.microsoftonline.com",
                "microsoftonline.com",
                "login.live.com",
                "account.live.com"
            ]):
                signals.append(Signal(
                    signal_type="header",
                    auth_type="azure_ad",
                    weight=WEIGHT_STRONG_HIGH,
                    evidence=f"Location header redirects to Microsoft endpoint: {location[:80]}",
                    source="analyze_headers_for_signals"
                ))

            # Okta redirect
            elif any(domain in location_lower for domain in ["okta.com", "okta-emea.com", "oktacdn.com"]):
                signals.append(Signal(
                    signal_type="header",
                    auth_type="okta",
                    weight=WEIGHT_STRONG_HIGH,
                    evidence=f"Location header redirects to Okta: {location[:80]}",
                    source="analyze_headers_for_signals"
                ))

            # OAuth endpoints
            elif any(pattern in location_lower for pattern in ["/oauth/authorize", "/authorize", "client_id="]):
                signals.append(Signal(
                    signal_type="header",
                    auth_type="oauth",
                    weight=WEIGHT_STRONG_MED,
                    evidence=f"Location header redirects to OAuth endpoint: {location[:80]}",
                    source="analyze_headers_for_signals"
                ))

            # SAML endpoints
            elif any(pattern in location_lower for pattern in ["/saml/", "/saml2/", "samlrequest=", "samlresponse="]):
                signals.append(Signal(
                    signal_type="header",
                    auth_type="saml",
                    weight=WEIGHT_STRONG_HIGH,
                    evidence=f"Location header redirects to SAML endpoint: {location[:80]}",
                    source="analyze_headers_for_signals"
                ))

    # Check Content-Security-Policy for hints (final response only, matching
    # prior behavior — but through the same case-insensitive lookup)
    csp = _lower_keys(response_headers).get("content-security-policy", "")
    if csp:
        csp_lower = csp.lower()

        # Azure AD CSP patterns
        if "login.microsoftonline.com" in csp_lower:
            signals.append(Signal(
                signal_type="header",
                auth_type="azure_ad",
                weight=WEIGHT_MODERATE_LOW,
                evidence="CSP references login.microsoftonline.com",
                source="analyze_headers_for_signals"
            ))

        # Okta CSP patterns
        elif "okta.com" in csp_lower or "oktacdn.com" in csp_lower:
            signals.append(Signal(
                signal_type="header",
                auth_type="okta",
                weight=WEIGHT_MODERATE_LOW,
                evidence="CSP references Okta domains",
                source="analyze_headers_for_signals"
            ))

    return signals


def analyze_url_for_signals(url: str, redirect_chain: list[str] | None = None) -> list[Signal]:
    """
    Extract authentication signals from URL patterns and redirect chains.

    Args:
        url: Final URL after redirects
        redirect_chain: List of URLs from redirect history

    Returns:
        List of Signal objects
    """
    signals = []

    # Check all URLs in chain
    # Each distinct URL counts once: the final URL is usually also the last
    # hop of the redirect chain, and counting it twice skews the scores.
    urls_to_check = list(dict.fromkeys([url, *(redirect_chain or [])]))

    for check_url in urls_to_check:
        url_lower = check_url.lower()
        # Path + fragment only, for path-style checks: matching "/login"
        # against the whole URL also hits hostnames ("https://login.example.com",
        # "http://loginlab:5500"), which says nothing about the page itself.
        _parts = urlsplit(url_lower)
        path_lower = _parts.path + ("#" + _parts.fragment if _parts.fragment else "")

        # Microsoft/Azure AD URL patterns
        # NOTE: Microsoft uses OAuth internally, but we want the specialized Azure handler
        # so we detect Microsoft first and skip generic OAuth detection for these URLs
        is_microsoft_url = any(domain in url_lower for domain in [
            "login.microsoftonline.com",
            "microsoftonline.com",
            "login.live.com",
            "account.live.com"
        ])
        if is_microsoft_url:
            signals.append(Signal(
                signal_type="url_redirect",
                auth_type="azure_ad",
                weight=WEIGHT_STRONG_HIGH,
                evidence=f"URL redirected to Microsoft domain: {check_url[:80]}",
                source="analyze_url_for_signals"
            ))

        # Okta URL patterns
        is_okta_url = any(domain in url_lower for domain in ["okta.com", "okta-emea.com", "oktacdn.com"])
        if is_okta_url:
            signals.append(Signal(
                signal_type="url_redirect",
                auth_type="okta",
                weight=WEIGHT_STRONG_HIGH,
                evidence=f"URL redirected to Okta domain: {check_url[:80]}",
                source="analyze_url_for_signals"
            ))

        # SPA-style login routes (hash-based) and common sign-in paths
        if any(fragment in path_lower for fragment in [
            "#/login", "#/sign", "#/signin", "#/auth",
            "/users/sign_in", "/login", "/signin"
        ]):
            signals.append(Signal(
                signal_type="url_pattern",
                auth_type="form_based",
                weight=WEIGHT_MODERATE_MED,
                evidence=f"Login path detected in URL: {check_url[:80]}",
                source="analyze_url_for_signals"
            ))

        # SAML URL patterns
        if any(pattern in url_lower for pattern in [
            "/saml/", "/saml2/", "/sso/saml", "/auth/saml",
            "samlrequest=", "samlresponse=", "relaystate=",
            "/idp/profile/saml", "shibboleth"
        ]):
            # Different weights based on specificity
            if "samlrequest=" in url_lower or "samlresponse=" in url_lower:
                weight = WEIGHT_STRONG_HIGH
                evidence = f"SAML parameters in URL: {check_url[:80]}"
            elif "shibboleth" in url_lower:
                weight = WEIGHT_STRONG_MED
                evidence = f"Shibboleth IdP detected in URL: {check_url[:80]}"
            else:
                weight = WEIGHT_STRONG_MED
                evidence = f"SAML path detected in URL: {check_url[:80]}"

            signals.append(Signal(
                signal_type="url_pattern",
                auth_type="saml",
                weight=weight,
                evidence=evidence,
                source="analyze_url_for_signals"
            ))

        # OAuth URL patterns
        # Skip generic OAuth detection for Microsoft/Okta - they use OAuth internally
        # but we want to use their specialized handlers with correct selectors
        if not is_microsoft_url and not is_okta_url:
            if any(pattern in url_lower for pattern in [
                "oauth/authorize", "/authorize", "oauth2/authorize"
            ]):
                signals.append(Signal(
                    signal_type="url_pattern",
                    auth_type="oauth",
                    weight=WEIGHT_STRONG_MED,
                    evidence=f"OAuth authorization endpoint in URL: {check_url[:80]}",
                    source="analyze_url_for_signals"
                ))

            # OAuth parameters
            if "client_id=" in url_lower and ("redirect_uri=" in url_lower or "response_type=" in url_lower):
                signals.append(Signal(
                    signal_type="url_pattern",
                    auth_type="oauth",
                    weight=WEIGHT_STRONG_HIGH,
                    evidence=f"OAuth parameters detected in URL: {check_url[:80]}",
                    source="analyze_url_for_signals"
                ))

            # Known OAuth providers
            if any(provider in url_lower for provider in [
                "accounts.google.com", "github.com/login/oauth",
                "auth0.com", "cognito", "identityserver"
            ]):
                signals.append(Signal(
                    signal_type="url_pattern",
                    auth_type="oauth",
                    weight=WEIGHT_STRONG_HIGH,
                    evidence=f"Known OAuth provider detected: {check_url[:80]}",
                    source="analyze_url_for_signals"
                ))

        # ADFS/LDAP URL patterns
        if "adfs" in url_lower:
            signals.append(Signal(
                signal_type="url_pattern",
                auth_type="ldap",
                weight=WEIGHT_MODERATE_HIGH,
                evidence=f"ADFS detected in URL: {check_url[:80]}",
                source="analyze_url_for_signals"
            ))

    return signals


def analyze_html_for_signals(html: str, url: str) -> list[Signal]:
    """
    Extract authentication signals from HTML content.

    Args:
        html: HTML content
        url: URL of the page (for context)

    Returns:
        List of Signal objects
    """
    import re

    signals = []
    html_lower = html.lower()

    # Detect form fields
    has_password = bool(re.search(r'<input[^>]+type=["\']?password', html_lower))
    has_username = bool(re.search(
        r'<input[^>]+(?:name|id)=["\'][^"\']*(email|user|login|username)',
        html_lower
    ))
    has_submit = bool(re.search(
        r'(<button[^>]*(sign[ -]?in|log[ -]?in|submit)|<input[^>]+type=["\']?submit)',
        html_lower
    ))

    # Azure AD / Microsoft branding
    if any(keyword in html_lower for keyword in [
        "microsoftonline.com", "azuread", "enter code", "login.live.com", "msa"
    ]):
        signals.append(Signal(
            signal_type="html_content",
            auth_type="azure_ad",
            weight=WEIGHT_STRONG_LOW,
            evidence="HTML contains Azure AD/Microsoft branding",
            source="analyze_html_for_signals"
        ))

    # Okta branding
    if any(keyword in html_lower for keyword in [
        "okta-sign-in", 'data-se="o-form"', "okta-login-container"
    ]):
        signals.append(Signal(
            signal_type="html_content",
            auth_type="okta",
            weight=WEIGHT_STRONG_MED,
            evidence="HTML contains Okta sign-in widget",
            source="analyze_html_for_signals"
        ))

    # LDAP/ADFS branding with form
    if any(keyword in html_lower for keyword in ["ldap", "active directory", "adfs"]) and "<form" in html_lower:
        signals.append(Signal(
            signal_type="html_content",
            auth_type="ldap",
            weight=WEIGHT_MODERATE_MED,
            evidence="HTML references LDAP/ADFS branding and contains a form",
            source="analyze_html_for_signals"
        ))

    # Form-based authentication detection
    if has_password:
        if has_username and has_submit:
            # Complete login form (strong signal)
            signals.append(Signal(
                signal_type="html_content",
                auth_type="form_based",
                weight=WEIGHT_STRONG_MED,
                evidence="Complete login form detected (username + password + submit)",
                source="analyze_html_for_signals"
            ))
        elif has_username or has_submit:
            # Partial form (moderate signal)
            signals.append(Signal(
                signal_type="html_content",
                auth_type="form_based",
                weight=WEIGHT_MODERATE_HIGH,
                evidence="Login form detected (password + username or submit)",
                source="analyze_html_for_signals"
            ))
        else:
            # Just password field (weak signal - could be two-step)
            signals.append(Signal(
                signal_type="html_content",
                auth_type="form_based",
                weight=WEIGHT_WEAK_HIGH,
                evidence="Password field detected (may be form-based or two-step)",
                source="analyze_html_for_signals"
            ))

    # Two-step form detection
    if has_username and not has_password:
        signals.append(Signal(
            signal_type="html_content",
            auth_type="two_step_form",
            weight=WEIGHT_MODERATE_HIGH,
            evidence="Username field without password (likely two-step authentication)",
            source="analyze_html_for_signals"
        ))

    return signals


def analyze_tech_fingerprint_for_signals(tech_data: dict[str, Any]) -> list[Signal]:
    """
    Extract authentication signals from technology fingerprinting data.

    Args:
        tech_data: Technology fingerprint dictionary from analyze_tech_fingerprint()

    Returns:
        List of Signal objects
    """
    signals = []

    if not tech_data:
        return signals

    # Extract data
    frameworks = tech_data.get("js_frameworks", [])
    cms = tech_data.get("cms", [])
    auth_cookies = tech_data.get("auth_cookies", [])

    # SPA framework detection
    spa_frameworks = {"React", "Angular", "Vue.js", "Svelte", "Ember.js"}
    detected_spa = [f for f in frameworks if f in spa_frameworks]

    if detected_spa:
        # SPA suggests client-side routing, likely needs browser detection
        signals.append(Signal(
            signal_type="tech_fingerprint",
            auth_type="form_based",  # SPAs typically have forms, but rendered by JS
            weight=WEIGHT_WEAK_MED,
            evidence=f"SPA framework detected: {', '.join(detected_spa)} (may need browser detection)",
            source="analyze_tech_fingerprint_for_signals"
        ))

    # WordPress/CMS detection
    if "WordPress" in cms:
        signals.append(Signal(
            signal_type="tech_fingerprint",
            auth_type="form_based",
            weight=WEIGHT_MODERATE_MED,
            evidence="WordPress CMS detected (typically uses form-based authentication)",
            source="analyze_tech_fingerprint_for_signals"
        ))

    if "Drupal" in cms:
        signals.append(Signal(
            signal_type="tech_fingerprint",
            auth_type="form_based",
            weight=WEIGHT_MODERATE_MED,
            evidence="Drupal CMS detected (typically uses form-based authentication)",
            source="analyze_tech_fingerprint_for_signals"
        ))

    if "SharePoint" in cms:
        signals.append(Signal(
            signal_type="tech_fingerprint",
            auth_type="azure_ad",
            weight=WEIGHT_MODERATE_LOW,
            evidence="SharePoint detected (often uses Azure AD authentication)",
            source="analyze_tech_fingerprint_for_signals"
        ))

    # Auth cookie detection
    if auth_cookies:
        # More cookies = stronger signal
        weight = min(WEIGHT_WEAK_HIGH + len(auth_cookies), WEIGHT_MODERATE_LOW)
        signals.append(Signal(
            signal_type="tech_fingerprint",
            auth_type="form_based",  # Cookies suggest session-based auth
            weight=weight,
            evidence=f"Auth-related cookies detected: {', '.join(auth_cookies[:5])}",
            source="analyze_tech_fingerprint_for_signals"
        ))

    return signals


def analyze_har_insights_for_signals(har_insights: dict[str, Any]) -> list[Signal]:
    """
    Extract authentication signals from HAR analysis insights.

    Args:
        har_insights: HAR insights dictionary from analyze_har()

    Returns:
        List of Signal objects
    """
    signals = []

    if not har_insights:
        return signals

    # Extract data
    login_endpoints = har_insights.get("login_endpoints", [])
    api_endpoints = har_insights.get("api_endpoints", [])
    has_api_auth = har_insights.get("has_api_auth", False)
    has_multi_step = har_insights.get("has_multi_step", False)
    successful_posts = har_insights.get("successful_posts", [])

    # API-first flow detection
    if has_api_auth and not login_endpoints:
        signals.append(Signal(
            signal_type="har_analysis",
            auth_type="form_based",  # Still form-based, but API-driven
            weight=WEIGHT_MODERATE_MED,
            evidence=f"API-first authentication detected ({len(api_endpoints)} API endpoints)",
            source="analyze_har_insights_for_signals"
        ))

    # Multi-step authentication
    if has_multi_step:
        signals.append(Signal(
            signal_type="har_analysis",
            auth_type="two_step_form",
            weight=WEIGHT_MODERATE_HIGH,
            evidence=f"Multi-step authentication detected ({len(successful_posts)} POST requests)",
            source="analyze_har_insights_for_signals"
        ))

    # Login endpoint detection boosts confidence
    if login_endpoints:
        weight = min(WEIGHT_WEAK_HIGH + (len(login_endpoints) * 3), WEIGHT_MODERATE_LOW)
        signals.append(Signal(
            signal_type="har_analysis",
            auth_type="form_based",
            weight=weight,
            evidence=f"Login endpoints detected in HAR: {len(login_endpoints)} endpoints",
            source="analyze_har_insights_for_signals"
        ))

    return signals
