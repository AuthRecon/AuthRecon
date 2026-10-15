"""
Security Context Extractor

Extracts comprehensive security metadata from Selenium WebDriver sessions
for AuthRecon runs. This includes cookies, headers, TLS info, tokens, etc.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from selenium.webdriver.remote.webdriver import WebDriver

from app.schemas.security_context import (
    SecurityContext,
    CookieAnalysis,
    CookieMetadata,
    SameSitePolicy,
    SecurityHeaders,
    ResponseHeaders,
    HSTSConfig,
    CSPConfig,
    CSPDirective,
    CORSConfig,
)


def extract_security_context(driver: WebDriver, target_url: str) -> SecurityContext:
    """
    Extract complete security context from a Selenium WebDriver session.

    Phase 1 (current): Cookie analysis only
    Future phases: Headers, TLS, tokens, storage, etc.
    """
    # Extract cookies
    cookies_data = extract_cookie_analysis(driver)

    # Extract security headers (Phase 2)
    headers_data = extract_security_headers(driver, target_url)

    # Calculate overall security score (weighted average)
    cookie_score = cookies_data.security_score if cookies_data else 0.0
    header_score = headers_data.security.security_score if headers_data else 0.0
    overall_score = (cookie_score * 0.4) + (header_score * 0.6)  # Headers weighted higher

    return SecurityContext(
        cookies=cookies_data,
        security_headers=headers_data,
        # Phase 3+: TLS, tokens, etc. will be added here
        authentication_tokens=None,
        tls_info=None,
        server_fingerprint=None,
        redirect_chain=None,
        browser_storage=None,
        form_metadata=None,
        api_discovery=None,
        error_disclosure=None,
        # Overall scoring
        overall_security_score=overall_score,
        critical_issues=[],
        warnings=[],
        extracted_at=datetime.now(timezone.utc),
        extraction_version="1.1.0",  # Incremented for Phase 2
    )


def extract_cookie_analysis(driver: WebDriver) -> CookieAnalysis:
    """Extract comprehensive cookie metadata and security analysis."""
    raw_cookies = driver.get_cookies()

    if not raw_cookies:
        return CookieAnalysis(
            cookies=[],
            total_count=0,
            session_count=0,
            persistent_count=0,
            secure_count=0,
            http_only_count=0,
            same_site_none_count=0,
            total_size_bytes=0,
            security_score=100.0,  # No cookies = perfect score
            issues=[],
        )

    # Convert Selenium cookies to CookieMetadata
    cookies = []
    for raw_cookie in raw_cookies:
        cookie_meta = extract_cookie_metadata(raw_cookie)
        cookies.append(cookie_meta)

    # Calculate aggregates
    total_count = len(cookies)
    session_count = sum(1 for c in cookies if c.is_session)
    persistent_count = sum(1 for c in cookies if c.is_persistent)
    secure_count = sum(1 for c in cookies if c.secure)
    http_only_count = sum(1 for c in cookies if c.http_only)
    same_site_none_count = sum(
        1 for c in cookies
        if c.same_site == SameSitePolicy.NONE
    )
    total_size_bytes = sum(c.size_bytes for c in cookies)

    # Calculate security score and issues
    security_score, issues = analyze_cookie_security(cookies)

    return CookieAnalysis(
        cookies=cookies,
        total_count=total_count,
        session_count=session_count,
        persistent_count=persistent_count,
        secure_count=secure_count,
        http_only_count=http_only_count,
        same_site_none_count=same_site_none_count,
        total_size_bytes=total_size_bytes,
        security_score=security_score,
        issues=issues,
    )


def extract_cookie_metadata(raw_cookie: dict[str, Any]) -> CookieMetadata:
    """Convert Selenium cookie dict to CookieMetadata with security analysis."""
    name = raw_cookie.get("name", "")
    value = raw_cookie.get("value", "")
    domain = raw_cookie.get("domain", "")
    path = raw_cookie.get("path", "/")
    expires = raw_cookie.get("expiry")  # Unix timestamp or None
    http_only = raw_cookie.get("httpOnly", False)
    secure = raw_cookie.get("secure", False)
    same_site_raw = raw_cookie.get("sameSite")

    # Parse SameSite
    same_site = None
    if same_site_raw:
        same_site_upper = same_site_raw.upper()
        if same_site_upper == "STRICT":
            same_site = SameSitePolicy.STRICT
        elif same_site_upper == "LAX":
            same_site = SameSitePolicy.LAX
        elif same_site_upper == "NONE":
            same_site = SameSitePolicy.NONE

    # Calculate TTL
    ttl_seconds = None
    if expires:
        now = datetime.now(timezone.utc).timestamp()
        ttl_seconds = int(expires - now)
        if ttl_seconds < 0:
            ttl_seconds = 0

    # Determine session vs persistent
    is_session = expires is None
    is_persistent = expires is not None

    # Calculate size
    size_bytes = len(name.encode('utf-8')) + len(value.encode('utf-8'))

    # Calculate entropy (randomness score 0.0-1.0)
    entropy_score = calculate_entropy(value)

    # Hash the value for comparison
    value_hash = hashlib.sha256(value.encode('utf-8')).hexdigest()

    value_plaintext = value

    # Analyze security issues for this specific cookie
    cookie_issues = []

    # Check for missing Secure flag on non-localhost
    if is_session and not secure and "localhost" not in domain:
        cookie_issues.append("Missing Secure flag on session cookie")

    # Check for missing HttpOnly flag on session cookies
    if is_session and not http_only:
        cookie_issues.append("Missing HttpOnly flag (XSS vulnerable)")

    # Check SameSite=None without Secure
    if same_site == SameSitePolicy.NONE and not secure:
        cookie_issues.append("SameSite=None requires Secure flag")

    # Check for low entropy session tokens
    if "session" in name.lower() or "token" in name.lower():
        if entropy_score < 0.7:  # Less than ~128 bits of randomness
            cookie_issues.append(f"Low entropy ({entropy_score:.2f}) for session token")

    # Check for oversized cookies
    if size_bytes > 4096:  # 4KB limit
        cookie_issues.append(f"Cookie exceeds size limit ({size_bytes} bytes)")

    # Check for long-lived session cookies (>24 hours)
    if is_persistent and ttl_seconds and ttl_seconds > 86400:  # 24 hours
        hours = ttl_seconds / 3600
        cookie_issues.append(f"Long-lived session token ({hours:.1f} hours)")

    # Check for overly broad domain scope
    if domain.startswith(".") and domain.count(".") <= 2:
        # e.g., ".com" or ".co.uk" - too broad
        cookie_issues.append(f"Overly broad domain scope: {domain}")

    return CookieMetadata(
        name=name,
        value_encrypted=value_plaintext,  # Plaintext temporarily - will be encrypted in worker
        value_hash=value_hash,
        domain=domain,
        path=path,
        expires=expires,
        ttl_seconds=ttl_seconds,
        http_only=http_only,
        secure=secure,
        same_site=same_site,
        size_bytes=size_bytes,
        is_session=is_session,
        is_persistent=is_persistent,
        entropy_score=entropy_score,
        captured_at=datetime.now(timezone.utc),
        security_issues=cookie_issues,
    )


def calculate_entropy(value: str) -> float:
    """
    Calculate Shannon entropy of a string, normalized to 0.0-1.0.

    1.0 = maximum randomness (all characters unique)
    0.0 = minimum randomness (all same character)
    """
    if not value:
        return 0.0

    # Count character frequencies
    counter = Counter(value)
    length = len(value)

    # Calculate Shannon entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    # Normalize to 0.0-1.0 based on theoretical max for this length
    # Max entropy = log2(length) when all chars unique
    max_entropy = math.log2(length) if length > 1 else 1.0
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0

    return min(1.0, max(0.0, normalized))


def analyze_cookie_security(cookies: list[CookieMetadata]) -> tuple[float, list[str]]:
    """
    Calculate overall cookie security score (0-100) and aggregate issues.

    Returns:
        (score, issues) where score is 0.0-100.0 and issues is list of strings
    """
    if not cookies:
        return 100.0, []

    score = 100.0
    issues = []

    # Count security issues
    total_cookies = len(cookies)
    session_cookies = [c for c in cookies if c.is_session]

    # Deduct points for missing Secure flags
    insecure_count = sum(1 for c in cookies if not c.secure)
    if insecure_count > 0:
        score -= min(20, insecure_count * 5)
        issues.append(f"{insecure_count}/{total_cookies} cookies missing Secure flag")

    # Deduct points for missing HttpOnly on session cookies
    session_no_httponly = sum(1 for c in session_cookies if not c.http_only)
    if session_no_httponly > 0:
        score -= min(20, session_no_httponly * 10)
        issues.append(f"{session_no_httponly} session cookies missing HttpOnly flag")

    # Deduct points for SameSite=None without Secure
    samesite_none_insecure = sum(
        1 for c in cookies
        if c.same_site == SameSitePolicy.NONE and not c.secure
    )
    if samesite_none_insecure > 0:
        score -= min(15, samesite_none_insecure * 10)
        issues.append(f"{samesite_none_insecure} cookies with SameSite=None missing Secure")

    # Deduct points for low entropy session tokens
    low_entropy = [
        c for c in cookies
        if ("session" in c.name.lower() or "token" in c.name.lower())
        and c.entropy_score < 0.7
    ]
    if low_entropy:
        score -= min(15, len(low_entropy) * 10)
        issues.append(f"{len(low_entropy)} session tokens with low entropy")

    # Deduct points for oversized cookies
    oversized = [c for c in cookies if c.size_bytes > 4096]
    if oversized:
        score -= min(10, len(oversized) * 5)
        issues.append(f"{len(oversized)} cookies exceed size limit")

    # Deduct points for missing SameSite on session cookies
    session_no_samesite = sum(1 for c in session_cookies if c.same_site is None)
    if session_no_samesite > 0:
        score -= min(10, session_no_samesite * 5)
        issues.append(f"{session_no_samesite} session cookies missing SameSite attribute")

    return max(0.0, score), issues


def extract_security_headers(driver: WebDriver, target_url: str) -> ResponseHeaders:
    """
    Extract security headers from HTTP response.

    Note: Selenium doesn't easily expose response headers. We use JavaScript
    and Chrome DevTools Protocol where available.
    """
    headers = {}
    
    try:
        # Try to use Chrome DevTools Protocol to get response headers
        # This works with ChromeDriver
        logs = driver.get_log('performance')
        
        for entry in logs:
            import json
            log_entry = json.loads(entry['message'])
            message = log_entry.get('message', {})
            method = message.get('method', '')
            
            # Look for Network.responseReceived events
            if method == 'Network.responseReceived':
                params = message.get('params', {})
                response = params.get('response', {})
                url = response.get('url', '')
                
                # Match the target URL or current page
                if target_url in url or driver.current_url in url:
                    headers_dict = response.get('headers', {})
                    # Merge headers (case-insensitive)
                    for key, value in headers_dict.items():
                        headers[key.lower()] = value
                        
    except Exception:
        # If Performance logging is not available, fall back to JavaScript approach
        pass
    
    # If we couldn't get headers via CDP, try JavaScript Performance API
    if not headers:
        try:
            # Get headers from Performance API (limited data)
            perf_data = driver.execute_script("""
                const entries = performance.getEntriesByType('navigation');
                if (entries && entries.length > 0) {
                    return {
                        'server_timing': entries[0].serverTiming || []
                    };
                }
                return {};
            """)
        except Exception:
            perf_data = {}
    
    # Parse security headers
    hsts_config = _parse_hsts(headers.get('strict-transport-security'))
    csp_config = _parse_csp(headers.get('content-security-policy'))
    cors_config = _parse_cors(headers)
    
    # Check for missing critical headers
    missing_headers = []
    if not headers.get('strict-transport-security') and target_url.startswith('https'):
        missing_headers.append('Strict-Transport-Security')
    if not headers.get('content-security-policy') and not headers.get('content-security-policy-report-only'):
        missing_headers.append('Content-Security-Policy')
    if not headers.get('x-frame-options'):
        missing_headers.append('X-Frame-Options')
    if not headers.get('x-content-type-options'):
        missing_headers.append('X-Content-Type-Options')
    if not headers.get('referrer-policy'):
        missing_headers.append('Referrer-Policy')
    
    # Parse other security headers
    x_frame_options = headers.get('x-frame-options')
    x_content_type_options = headers.get('x-content-type-options')
    x_xss_protection = headers.get('x-xss-protection')
    referrer_policy = headers.get('referrer-policy')
    
    # Parse Permissions-Policy
    permissions_policy = {}
    perm_header = headers.get('permissions-policy') or headers.get('feature-policy')
    if perm_header:
        permissions_policy = _parse_permissions_policy(perm_header)
    
    # Calculate security score and issues
    score, issues = _analyze_headers_security(
        hsts_config, csp_config, cors_config, x_frame_options,
        x_content_type_options, referrer_policy, missing_headers
    )
    
    # Collect other security-relevant headers
    other_headers = {}
    for key, value in headers.items():
        if key not in ['strict-transport-security', 'content-security-policy',
                       'x-frame-options', 'x-content-type-options', 'x-xss-protection',
                       'referrer-policy', 'permissions-policy', 'feature-policy'] and \
           not key.startswith('access-control-'):
            other_headers[key] = value

    # Extract server identification
    server = headers.get('server')
    x_powered_by = headers.get('x-powered-by')

    # Detect framework hints from various headers
    framework_hints = []
    if x_powered_by:
        framework_hints.append(x_powered_by)
    if 'x-aspnet-version' in headers:
        framework_hints.append(f"ASP.NET {headers['x-aspnet-version']}")
    if 'x-aspnetmvc-version' in headers:
        framework_hints.append(f"ASP.NET MVC {headers['x-aspnetmvc-version']}")
    if 'x-runtime' in headers:
        framework_hints.append(headers['x-runtime'])

    # Build SecurityHeaders object
    security_headers = SecurityHeaders(
        hsts=hsts_config,
        csp=csp_config,
        x_frame_options=x_frame_options,
        x_content_type_options=x_content_type_options,
        x_xss_protection=x_xss_protection,
        referrer_policy=referrer_policy,
        permissions_policy=permissions_policy,
        cors=cors_config,
        other=other_headers,
        missing_headers=missing_headers,
        security_score=score,
        issues=issues,
    )

    # Wrap in ResponseHeaders
    return ResponseHeaders(
        security=security_headers,
        server=server,
        x_powered_by=x_powered_by,
        framework_hints=framework_hints,
        raw=headers,
    )


def _parse_hsts(hsts_header: str | None) -> HSTSConfig | None:
    """Parse Strict-Transport-Security header."""
    if not hsts_header:
        return None
    
    max_age = 0
    include_subdomains = False
    preload = False
    
    parts = [p.strip() for p in hsts_header.split(';')]
    for part in parts:
        if part.startswith('max-age='):
            try:
                max_age = int(part.split('=')[1])
            except (ValueError, IndexError):
                pass
        elif part.lower() == 'includesubdomains':
            include_subdomains = True
        elif part.lower() == 'preload':
            preload = True
    
    return HSTSConfig(
        max_age=max_age,
        include_subdomains=include_subdomains,
        preload=preload,
        raw_value=hsts_header,
    )


def _parse_csp(csp_header: str | None) -> CSPConfig | None:
    """Parse Content-Security-Policy header."""
    if not csp_header:
        return None
    
    directives = []
    report_uri = None
    allows_unsafe_inline = False
    allows_unsafe_eval = False
    allows_wildcard = False
    issues = []
    
    # Split by semicolon to get directives
    parts = [p.strip() for p in csp_header.split(';') if p.strip()]
    
    for part in parts:
        tokens = part.split()
        if not tokens:
            continue
        
        directive_name = tokens[0]
        values = tokens[1:] if len(tokens) > 1 else []
        
        directives.append(CSPDirective(name=directive_name, values=values))
        
        # Check for report-uri
        if directive_name == 'report-uri' and values:
            report_uri = values[0]
        
        # Security checks
        if "'unsafe-inline'" in values:
            allows_unsafe_inline = True
        if "'unsafe-eval'" in values:
            allows_unsafe_eval = True
        if '*' in values:
            allows_wildcard = True
    
    # Generate issues
    if allows_unsafe_inline:
        issues.append("CSP allows 'unsafe-inline' (XSS risk)")
    if allows_unsafe_eval:
        issues.append("CSP allows 'unsafe-eval' (code injection risk)")
    if allows_wildcard:
        issues.append("CSP uses wildcard '*' (too permissive)")
    if not any(d.name in ['default-src', 'script-src'] for d in directives):
        issues.append("CSP missing critical directives (default-src or script-src)")
    
    return CSPConfig(
        directives=directives,
        report_uri=report_uri,
        report_only=False,  # Would need to check CSP-Report-Only header separately
        raw_value=csp_header,
        allows_unsafe_inline=allows_unsafe_inline,
        allows_unsafe_eval=allows_unsafe_eval,
        allows_wildcard=allows_wildcard,
        issues=issues,
    )


def _parse_cors(headers: dict[str, str]) -> CORSConfig | None:
    """Parse CORS headers."""
    allow_origin = headers.get('access-control-allow-origin')
    if not allow_origin:
        return None
    
    allow_credentials = headers.get('access-control-allow-credentials', '').lower() == 'true'
    allow_methods = headers.get('access-control-allow-methods', '').split(',')
    allow_methods = [m.strip() for m in allow_methods if m.strip()]
    
    allow_headers = headers.get('access-control-allow-headers', '').split(',')
    allow_headers = [h.strip() for h in allow_headers if h.strip()]
    
    expose_headers = headers.get('access-control-expose-headers', '').split(',')
    expose_headers = [h.strip() for h in expose_headers if h.strip()]
    
    max_age = None
    max_age_str = headers.get('access-control-max-age')
    if max_age_str:
        try:
            max_age = int(max_age_str)
        except ValueError:
            pass
    
    # Security analysis
    is_overly_permissive = (allow_origin == '*' and allow_credentials)
    issues = []
    
    if is_overly_permissive:
        issues.append("CORS allows all origins (*) with credentials (security risk)")
    if allow_origin == '*':
        issues.append("CORS allows all origins (*)") 
    if 'DELETE' in allow_methods or 'PUT' in allow_methods:
        issues.append(f"CORS allows destructive methods: {', '.join([m for m in allow_methods if m in ['DELETE', 'PUT']])}")
    
    return CORSConfig(
        allow_origin=allow_origin,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        expose_headers=expose_headers,
        max_age=max_age,
        is_overly_permissive=is_overly_permissive,
        issues=issues,
    )


def _parse_permissions_policy(policy_header: str) -> dict[str, list[str]]:
    """Parse Permissions-Policy or Feature-Policy header."""
    policy_dict = {}
    
    # Format: feature=(origin1 origin2), feature2=*
    parts = [p.strip() for p in policy_header.split(',')]
    
    for part in parts:
        if '=' in part:
            feature, origins_str = part.split('=', 1)
            feature = feature.strip()
            origins_str = origins_str.strip()
            
            # Remove parentheses
            if origins_str.startswith('(') and origins_str.endswith(')'):
                origins_str = origins_str[1:-1]
            
            origins = [o.strip() for o in origins_str.split() if o.strip()]
            policy_dict[feature] = origins
    
    return policy_dict


def _analyze_headers_security(
    hsts: HSTSConfig | None,
    csp: CSPConfig | None,
    cors: CORSConfig | None,
    x_frame_options: str | None,
    x_content_type_options: str | None,
    referrer_policy: str | None,
    missing_headers: list[str],
) -> tuple[float, list[str]]:
    """
    Calculate security score for headers (0-100) and aggregate issues.
    
    Returns:
        (score, issues)
    """
    score = 100.0
    issues = []
    
    # Deduct for missing HSTS (critical for HTTPS)
    if not hsts:
        score -= 20
        issues.append("Missing HSTS header (HTTPS sites should use Strict-Transport-Security)")
    elif hsts.max_age < 31536000:  # Less than 1 year
        score -= 5
        issues.append(f"HSTS max-age too short ({hsts.max_age} seconds, recommend 31536000)")
    
    # Deduct for missing or weak CSP
    if not csp:
        score -= 20
        issues.append("Missing Content-Security-Policy header (XSS protection)")
    else:
        # CSP has its own issues
        issues.extend(csp.issues)
        if csp.allows_unsafe_inline or csp.allows_unsafe_eval:
            score -= 10
        if csp.allows_wildcard:
            score -= 5
    
    # Deduct for missing X-Frame-Options
    if not x_frame_options:
        score -= 15
        issues.append("Missing X-Frame-Options (clickjacking risk)")
    
    # Deduct for missing X-Content-Type-Options
    if not x_content_type_options:
        score -= 10
        issues.append("Missing X-Content-Type-Options (MIME sniffing risk)")
    elif x_content_type_options.lower() != 'nosniff':
        score -= 5
        issues.append(f"X-Content-Type-Options should be 'nosniff', got '{x_content_type_options}'")
    
    # Deduct for missing Referrer-Policy
    if not referrer_policy:
        score -= 10
        issues.append("Missing Referrer-Policy (information leakage risk)")
    
    # CORS issues
    if cors:
        issues.extend(cors.issues)
        if cors.is_overly_permissive:
            score -= 15
        elif cors.allow_origin == '*':
            score -= 5
    
    # Additional penalty for too many missing headers
    if len(missing_headers) >= 4:
        score -= 10
        issues.append(f"{len(missing_headers)} critical security headers missing")
    
    return max(0.0, score), issues
