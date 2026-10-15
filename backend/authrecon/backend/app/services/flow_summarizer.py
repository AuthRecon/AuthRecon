"""
Authentication Flow Summarizer

Generates human-readable narrative summaries of authentication flows
based on Run data, HAR analysis, detection results, and execution context.

This makes AuthRecon's intelligence immediately understandable without
requiring manual HAR forensics or timeline analysis.
"""

import logging
from typing import Any
from urllib.parse import urlparse

from app.services.har_analyzer import HARAuthInsight, analyze_har, get_primary_auth_endpoint
from app.services.cookie_analyzer import analyze_cookies_from_har

LOGGER = logging.getLogger(__name__)


def generate_flow_summary(
    run_data: dict[str, Any],
    har_bytes: bytes | None = None,
    har_insight: HARAuthInsight | None = None,
) -> str:
    """
    Generate a structured, multi-section summary of the authentication flow.

    Args:
        run_data: Run model data (dict with auth_type, final_url, tech_fingerprint, etc.)
        har_bytes: Optional raw HAR file bytes (will be analyzed if har_insight not provided)
        har_insight: Optional pre-analyzed HAR insights

    Returns:
        Structured multi-line summary with sections for target, auth type, HTTP flow,
        session management, security observations, and execution context
    """
    sections = []

    # Analyze HAR if needed and bytes provided
    if not har_insight and har_bytes:
        har_insight = analyze_har(har_bytes)

    # 1. Target Domain (from final_url)
    target_domain = _extract_target_domain(run_data)
    if target_domain:
        sections.append(f"Target: {target_domain}")

    # 2. Authentication Type & Form Details
    auth_summary = _summarize_auth_type_detailed(run_data, har_insight)
    if auth_summary:
        sections.append(f"\n{auth_summary}")

    # 3. HTTP Flow (endpoints, methods, redirects)
    http_flow = _summarize_http_flow_detailed(run_data, har_insight)
    if http_flow:
        sections.append(f"\n{http_flow}")

    # 4. Session Management (primary cookie + others)
    session_mgmt = _summarize_session_management_detailed(run_data, har_insight)
    if session_mgmt:
        sections.append(f"\nSession Management:\n{session_mgmt}")

    # 5. Security Observations
    security_obs = _summarize_security_observations(run_data, har_insight)
    if security_obs:
        sections.append(f"\nSecurity Observations:\n{security_obs}")

    # 6. Technology & Execution Context
    context = _summarize_execution_context(run_data)
    if context:
        sections.append(f"\n{context}")

    if not sections:
        return "No authentication flow information available for this run."

    return "\n".join(sections)


def _summarize_auth_type(run_data: dict[str, Any], har_insight: HARAuthInsight | None) -> str:
    """Summarize the authentication type and step count."""
    auth_type = run_data.get("auth_type", "UNKNOWN").upper()

    # Determine step count from HAR insights
    step_count = None
    if har_insight:
        if har_insight.has_multi_step:
            # Count successful POST requests as step indicators
            step_count = len([p for p in har_insight.successful_posts
                            if p.get('status') in (200, 201, 302, 303)])

    # Build auth type description
    if auth_type == "FORM_BASED":
        if step_count and step_count >= 2:
            return f"This is a {step_count}-step form-based authentication (username then password)."
        else:
            return "This is a single-page form-based authentication."

    elif auth_type == "API_BASED":
        return "This is an API-based authentication (JSON/REST)."

    elif auth_type == "SSO":
        # Check for specific SSO provider in tech fingerprint or options
        tech_fp = run_data.get("tech_fingerprint", {})
        sso_provider = tech_fp.get("sso_provider") or tech_fp.get("auth_provider")

        if sso_provider:
            return f"This uses {sso_provider} single sign-on (SSO) for authentication."
        return "This uses single sign-on (SSO) for authentication."

    elif auth_type == "OAUTH":
        return "This uses OAuth-based authentication."

    elif auth_type == "SAML":
        return "This uses SAML-based authentication."

    elif auth_type == "BASIC_AUTH":
        return "This uses HTTP Basic Authentication."

    elif auth_type == "NTLM":
        return "This uses NTLM authentication (Windows integrated)."

    elif auth_type == "LDAP":
        return "This uses LDAP-based authentication."

    else:
        return f"Authentication type: {auth_type.replace('_', ' ').title()}."


def _summarize_http_flow(run_data: dict[str, Any], har_insight: HARAuthInsight | None) -> str:
    """Summarize HTTP endpoints, methods, and redirects."""
    parts = []

    # Primary auth endpoint (from HAR if available)
    if har_insight:
        primary_endpoint = get_primary_auth_endpoint(har_insight)
        if primary_endpoint:
            parsed = urlparse(primary_endpoint)
            endpoint_path = parsed.path or "/"

            # Determine method (assume POST for login endpoints)
            method = "POST"
            parts.append(f"The login request is a {method} to `{endpoint_path}`.")

        # Redirects (from HAR)
        redirect_count = len(har_insight.redirects)
        final_url = run_data.get("final_url")

        if redirect_count > 0 and final_url:
            final_parsed = urlparse(final_url)
            final_path = final_parsed.path or "/"

            if redirect_count == 1:
                parts.append(
                    f"After authentication, the application performs 1 redirect "
                    f"before landing on `{final_path}`."
                )
            else:
                parts.append(
                    f"After authentication, the application performs {redirect_count} redirects "
                    f"before landing on `{final_path}`."
                )

    # Fallback: Use final_url from run data even without HAR
    if not parts:
        final_url = run_data.get("final_url")
        if final_url:
            final_parsed = urlparse(final_url)
            final_path = final_parsed.path or "/"
            parts.append(f"After successful authentication, the user is redirected to `{final_path}`.")

    return " ".join(parts)


def _summarize_session_mechanism(run_data: dict[str, Any], har_insight: HARAuthInsight | None) -> str:
    """Summarize how session is maintained (cookies, tokens)."""
    parts = []

    # Check for cookies from HAR first
    if har_insight and har_insight.cookies_set:
        # Extract cookie names
        cookie_names = [c.get("name") for c in har_insight.cookies_set if c.get("name")]

        # Limit to most relevant cookies (session-related)
        session_cookies = [
            name for name in cookie_names
            if any(keyword in name.lower() for keyword in
                   ["session", "sid", "sess", "auth", "token", "csrf", "xsrf"])
        ]

        if session_cookies:
            if len(session_cookies) == 1:
                parts.append(f"Session is maintained via cookie: {session_cookies[0]}.")
            elif len(session_cookies) <= 3:
                cookie_list = ", ".join(session_cookies)
                parts.append(f"Session is maintained via cookies: {cookie_list}.")
            else:
                # Too many cookies, generalize
                parts.append(f"Session is maintained via {len(session_cookies)} cookies.")

    # Check for Bearer tokens in auth headers (HAR only)
    if har_insight:
        has_bearer = any(
            h.get("header_type") == "authorization" and "bearer" in h.get("value", "").lower()
            for h in har_insight.auth_headers
        )

        if has_bearer:
            parts.append("Session is maintained via Bearer token in Authorization header.")

        # Check for API key headers
        has_api_key = any(
            h.get("header_type") in ("x-api-key", "x-auth-token")
            for h in har_insight.auth_headers
        )

        if has_api_key:
            parts.append("Session is maintained via API key header.")

    # Fallback: Use session_cookies from run data if HAR didn't provide insights
    if not parts:
        session_cookies_data = run_data.get("session_cookies", [])

        if session_cookies_data:
            # Extract cookie names from run.session_cookies (can be strings or dicts)
            cookie_names = []
            for cookie in session_cookies_data:
                if isinstance(cookie, dict):
                    name = cookie.get("name")
                    if name:
                        cookie_names.append(name)
                elif isinstance(cookie, str):
                    cookie_names.append(cookie)

            if cookie_names:
                if len(cookie_names) == 1:
                    parts.append(f"Session is maintained via cookie: {cookie_names[0]}.")
                elif len(cookie_names) <= 3:
                    cookie_list = ", ".join(cookie_names)
                    parts.append(f"Session is maintained via cookies: {cookie_list}.")
                else:
                    # Too many cookies, generalize
                    parts.append(f"Session is maintained via {len(cookie_names)} cookies.")

    return " ".join(parts)


def _summarize_technology(run_data: dict[str, Any]) -> str:
    """Summarize detected technology/framework."""
    tech_fp = run_data.get("tech_fingerprint")

    if not tech_fp:
        return ""

    # Extract framework/platform
    framework = tech_fp.get("framework") or tech_fp.get("platform")
    auth_library = tech_fp.get("auth_library")

    parts = []

    if framework:
        parts.append(f"Application appears to use {framework}.")

    if auth_library and auth_library != framework:
        parts.append(f"Authentication library: {auth_library}.")

    return " ".join(parts)


def _summarize_execution_mode(run_data: dict[str, Any]) -> str:
    """Summarize how authentication was executed (browser vs HTTP)."""
    options = run_data.get("options", {})
    engine = options.get("engine") or "UNKNOWN"

    if engine == "PLAYWRIGHT":
        return "Authentication was executed using browser automation (Playwright)."
    elif engine == "SELENIUM":
        return "Authentication was executed using browser automation (Selenium)."
    elif engine == "HTTPX":
        return "Authentication was executed using direct HTTP requests (no browser required)."
    elif engine == "MULTI_ENGINE":
        return "Authentication was executed using multi-engine detection (automatic engine selection)."
    else:
        return ""


def _summarize_playbook_context(run_data: dict[str, Any]) -> str:
    """Summarize playbook usage (deterministic vs heuristic)."""
    pattern = run_data.get("pattern")

    # Check if a playbook/pattern was used
    if pattern:
        return "This domain has a learned playbook from previous runs (deterministic mode)."
    else:
        # First-time run using heuristic detection
        return "This was a first-time authentication using heuristic detection."

# ===== New Detailed Summarization Functions =====

def _extract_target_domain(run_data: dict[str, Any]) -> str | None:
    """Extract target domain from final_url."""
    final_url = run_data.get("final_url")
    if not final_url:
        return None

    try:
        parsed = urlparse(final_url)
        return parsed.hostname
    except Exception:
        return None


def _summarize_auth_type_detailed(run_data: dict[str, Any], har_insight: HARAuthInsight | None) -> str:
    """Enhanced auth type summary with form/API details."""
    auth_type = run_data.get("auth_type", "UNKNOWN").upper()

    # Determine step count from HAR insights
    step_info = ""
    if har_insight and har_insight.has_multi_step:
        step_count = len([p for p in har_insight.successful_posts
                        if p.get('status') in (200, 201, 302, 303)])
        if step_count >= 2:
            step_info = f" ({step_count}-step flow)"

    # Build auth type description
    if auth_type == "FORM_BASED":
        form_detail = "with username and password fields"
        return f"Authentication Type: Form-based login{step_info} {form_detail}."

    elif auth_type == "API_BASED":
        return f"Authentication Type: API-based (JSON/REST){step_info}."

    elif auth_type == "SSO":
        tech_fp = run_data.get("tech_fingerprint", {})
        provider = tech_fp.get("sso_provider") or tech_fp.get("auth_provider")
        if provider:
            return f"Authentication Type: {provider} SSO."
        return "Authentication Type: Single Sign-On (SSO)."

    elif auth_type == "OAUTH":
        return "Authentication Type: OAuth flow."

    elif auth_type == "SAML":
        return "Authentication Type: SAML-based."

    elif auth_type == "BASIC_AUTH":
        return "Authentication Type: HTTP Basic Authentication."

    else:
        return f"Authentication Type: {auth_type.replace('_', ' ').title()}."


def _summarize_http_flow_detailed(run_data: dict[str, Any], har_insight: HARAuthInsight | None) -> str:
    """Enhanced HTTP flow summary with endpoints and redirects."""
    parts = []

    # Primary auth endpoint (from HAR if available)
    if har_insight:
        primary_endpoint = get_primary_auth_endpoint(har_insight)
        if primary_endpoint:
            parsed = urlparse(primary_endpoint)
            endpoint_path = parsed.path or "/"
            parts.append(f"Login endpoint: POST {endpoint_path}")

    # Final landing page
    final_url = run_data.get("final_url")
    if final_url:
        final_parsed = urlparse(final_url)
        final_path = final_parsed.path or "/"

        # Redirect count from HAR
        redirect_count = len(har_insight.redirects) if har_insight else 0

        if redirect_count > 0:
            parts.append(f"After authentication: {redirect_count} redirect(s) → lands on `{final_path}`")
        else:
            parts.append(f"After successful authentication: redirects to `{final_path}`")

    return "\n".join(parts) if parts else ""


def _summarize_session_management_detailed(run_data: dict[str, Any], har_insight: HARAuthInsight | None) -> str:
    """Detailed session management with primary cookie identification."""
    lines = []

    # Get cookies from HAR or run data
    cookies_to_analyze = []

    if har_insight and har_insight.cookies_set:
        cookies_to_analyze = har_insight.cookies_set
    else:
        # Fallback to run.session_cookies
        session_cookies_data = run_data.get("session_cookies", [])
        for cookie in session_cookies_data:
            if isinstance(cookie, dict):
                cookies_to_analyze.append(cookie)
            elif isinstance(cookie, str):
                cookies_to_analyze.append({"name": cookie})

    if not cookies_to_analyze:
        return ""

    # Identify primary session cookie vs tracking cookies
    session_cookies = []
    tracking_cookies = []

    session_keywords = ["session", "sid", "sess", "auth", "token", "csrf", "xsrf"]
    tracking_patterns = ["optimizely", "google", "analytics", "_ga", "_gid", "mixpanel", "segment"]

    for cookie in cookies_to_analyze:
        name = cookie.get("name", "")
        if not name:
            continue

        name_lower = name.lower()

        # Check if it's a tracking cookie
        if any(pattern in name_lower for pattern in tracking_patterns):
            tracking_cookies.append(cookie)
        # Check if it's a session cookie
        elif any(keyword in name_lower for keyword in session_keywords):
            session_cookies.append(cookie)
        else:
            # Unknown type, assume session for safety
            session_cookies.append(cookie)

    # Analyze cookies with decoder
    analyzed_session_cookies = []
    if session_cookies:
        try:
            analyzed_session_cookies = analyze_cookies_from_har(session_cookies)
        except Exception as e:
            LOGGER.debug(f"Failed to analyze cookies: {e}")
            analyzed_session_cookies = []

    # Primary session cookie (first session cookie found)
    if analyzed_session_cookies:
        primary_analysis = analyzed_session_cookies[0]
        name = primary_analysis.name

        # Build flags string
        flags = []
        if primary_analysis.is_httponly:
            flags.append("httpOnly")
        if primary_analysis.is_secure:
            flags.append("Secure")
        if primary_analysis.same_site:
            flags.append(f"SameSite={primary_analysis.same_site}")

        flag_str = f" ({', '.join(flags)})" if flags else " (no security flags)"

        # Add cookie type indicator
        type_indicator = {
            "jwt": "JWT Token",
            "base64_json": "Base64 JSON",
            "base64": "Base64 Encoded",
            "flask_session": "Flask Session",
            "encrypted": "Encrypted",
            "plain": "Plain Text"
        }.get(primary_analysis.cookie_type, primary_analysis.cookie_type)

        lines.append(f"- Primary session cookie: {name}{flag_str}")
        lines.append(f"  Type: {type_indicator} (entropy: {primary_analysis.entropy:.1f})")

        # Show decoded JWT claims if available
        if primary_analysis.claims:
            claims_summary = []
            if "user_id" in primary_analysis.claims:
                claims_summary.append(f"user_id={primary_analysis.claims['user_id']}")
            if "username" in primary_analysis.claims:
                claims_summary.append(f"username={primary_analysis.claims['username']}")
            if "roles" in primary_analysis.claims:
                claims_summary.append(f"roles={primary_analysis.claims['roles']}")
            if "is_admin" in primary_analysis.claims and primary_analysis.claims["is_admin"]:
                claims_summary.append("admin=true")
            if "exp" in primary_analysis.claims:
                claims_summary.append(f"exp={primary_analysis.claims['exp']}")

            if claims_summary:
                lines.append(f"  Claims: {', '.join(claims_summary)}")

        # Show security notes
        for note in primary_analysis.security_notes:
            if "⚠️" in note or "⏰" in note:  # Only show warnings and important info
                lines.append(f"  {note}")

        # Additional session cookies
        if len(analyzed_session_cookies) > 1:
            other_names = [c.name for c in analyzed_session_cookies[1:]]
            if other_names:
                lines.append(f"- Additional auth cookies: {', '.join(other_names)}")

    # Tracking cookies (mention count, not names)
    if tracking_cookies:
        lines.append(f"- Tracking cookies: {len(tracking_cookies)} ({', '.join([c.get('name') for c in tracking_cookies[:2]])}{'...' if len(tracking_cookies) > 2 else ''})")

    return "\n".join(lines) if lines else ""


def _summarize_security_observations(run_data: dict[str, Any], har_insight: HARAuthInsight | None) -> str:
    """Security-relevant observations about the auth flow."""
    observations = []

    # Get session cookies for analysis
    cookies_to_check = []

    if har_insight and har_insight.cookies_set:
        cookies_to_check = har_insight.cookies_set
    else:
        # Fallback to run.session_cookies
        session_cookies_data = run_data.get("session_cookies", [])
        for cookie in session_cookies_data:
            if isinstance(cookie, dict):
                cookies_to_check.append(cookie)

    # Check primary session cookie for security flags
    session_keywords = ["session", "sid", "sess", "auth", "token"]
    primary_session = None

    for cookie in cookies_to_check:
        name = cookie.get("name", "")
        if any(keyword in name.lower() for keyword in session_keywords):
            primary_session = cookie
            break

    if primary_session:
        http_only = primary_session.get("httpOnly", False)
        secure = primary_session.get("secure", False)
        same_site = primary_session.get("sameSite", "")

        # Positive observations
        if http_only:
            observations.append("✓ Session cookie has httpOnly flag (protects against XSS)")

        # Security concerns
        if not secure:
            observations.append("⚠ Session cookie is NOT marked Secure (can be sent over HTTP)")

        if not same_site or same_site.lower() == "none":
            observations.append("⚠ Session cookie has no SameSite protection (CSRF risk)")

    return "\n".join(observations) if observations else ""


def _summarize_execution_context(run_data: dict[str, Any]) -> str:
    """Technology, execution mode, and playbook context."""
    parts = []

    # Technology
    tech_fp = run_data.get("tech_fingerprint")
    if tech_fp:
        framework = tech_fp.get("framework") or tech_fp.get("platform")
        if framework:
            parts.append(f"Technology: {framework}")

    # Execution mode
    options = run_data.get("options", {})
    engine = options.get("engine", "UNKNOWN")

    engine_desc = {
        "PLAYWRIGHT": "browser automation (Playwright)",
        "SELENIUM": "browser automation (Selenium)",
        "HTTPX": "direct HTTP requests (no browser)",
        "MULTI_ENGINE": "multi-engine detection (automatic)"
    }.get(engine.upper(), "")

    if engine_desc:
        parts.append(f"Execution: {engine_desc}")

    # Playbook context
    # Only show deterministic mode if pattern is actual JSON playbook data, not just a success message
    pattern = run_data.get("pattern")
    is_playbook = False
    if pattern:
        try:
            import json
            if isinstance(pattern, str) and pattern.startswith("{"):
                pattern_data = json.loads(pattern)
                # Check if it has playbook selector keys
                if isinstance(pattern_data, dict) and any(k in pattern_data for k in ["username_selector", "password_selector", "submit_selector"]):
                    is_playbook = True
        except (json.JSONDecodeError, TypeError):
            pass

    if is_playbook:
        parts.append("Mode: Deterministic (using learned playbook from previous runs)")
    else:
        parts.append("Mode: Heuristic (first-time authentication)")

    return "\n".join(parts) if parts else ""
