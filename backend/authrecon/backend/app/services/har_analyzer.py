"""
HAR (HTTP Archive) Analysis for Authentication Intelligence

Parses Playwright HAR captures to extract:
- POST/GET endpoints related to authentication
- Response codes and redirect chains
- Auth-related headers (WWW-Authenticate, Set-Cookie, Authorization)
- API-first authentication flows

Part of Signal Fusion Pipeline Phase 2
"""

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)


@dataclass
class HARAuthInsight:
    """Authentication intelligence extracted from HAR data."""

    # Detected auth endpoints
    login_endpoints: list[str]
    logout_endpoints: list[str]
    api_endpoints: list[str]

    # Response patterns
    successful_posts: list[dict[str, Any]]  # {url, status, headers}
    redirects: list[dict[str, Any]]  # {from, to, status}

    # Header intelligence
    auth_headers: list[dict[str, Any]]  # {url, header_type, value}
    cookies_set: list[dict[str, Any]]  # {name, domain, secure, httpOnly}

    # Flow indicators
    has_api_auth: bool  # True if found API endpoints without form submission
    has_session_refresh: bool  # True if found token/session refresh
    has_multi_step: bool  # True if multiple POST requests in sequence

    # Metadata
    total_requests: int
    auth_related_requests: int


def analyze_har(har_bytes: bytes | None) -> HARAuthInsight | None:
    """
    Parse HAR file and extract authentication-related intelligence.

    Args:
        har_bytes: Raw HAR file bytes from Playwright capture

    Returns:
        HARAuthInsight with extracted intelligence, or None if parsing fails
    """
    if not har_bytes:
        return None

    try:
        har_data = json.loads(har_bytes.decode('utf-8'))
        entries = har_data.get('log', {}).get('entries', [])

        if not entries:
            LOGGER.debug("HAR file contains no entries")
            return None

        # Initialize collectors
        login_endpoints = []
        logout_endpoints = []
        api_endpoints = []
        successful_posts = []
        redirects = []
        auth_headers = []
        cookies_set = []

        # Flow indicators
        post_count = 0
        api_auth_detected = False
        session_refresh_detected = False

        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})

            method = request.get('method', '').upper()
            url = request.get('url', '')
            status = response.get('status', 0)

            if not url:
                continue

            parsed_url = urlparse(url)
            path = parsed_url.path.lower()

            # Extract auth-related endpoints
            if _is_login_endpoint(path, method):
                login_endpoints.append(url)
                if method == 'POST':
                    post_count += 1

            if _is_logout_endpoint(path):
                logout_endpoints.append(url)

            if _is_api_endpoint(path, url):
                api_endpoints.append(url)
                if method == 'POST' and status in (200, 201):
                    api_auth_detected = True

            # Track successful POSTs
            if method == 'POST' and status in (200, 201, 302, 303):
                successful_posts.append({
                    'url': url,
                    'status': status,
                    'content_type': response.get('content', {}).get('mimeType', '')
                })

            # Track redirects
            if status in (301, 302, 303, 307, 308):
                location = _extract_location_header(response)
                if location:
                    redirects.append({
                        'from': url,
                        'to': location,
                        'status': status
                    })

            # Extract authentication headers
            auth_header_data = _extract_auth_headers(url, request, response)
            if auth_header_data:
                auth_headers.extend(auth_header_data)

            # Extract cookies
            cookie_data = _extract_cookies(response)
            if cookie_data:
                cookies_set.extend(cookie_data)

            # Detect session refresh patterns
            if _is_session_refresh(path, method, request):
                session_refresh_detected = True

        # Determine multi-step flow
        has_multi_step = post_count >= 2

        # Calculate metrics
        total_requests = len(entries)
        auth_related = len(login_endpoints) + len(logout_endpoints) + len(api_endpoints)

        insight = HARAuthInsight(
            login_endpoints=login_endpoints,
            logout_endpoints=logout_endpoints,
            api_endpoints=api_endpoints,
            successful_posts=successful_posts,
            redirects=redirects,
            auth_headers=auth_headers,
            cookies_set=cookies_set,
            has_api_auth=api_auth_detected,
            has_session_refresh=session_refresh_detected,
            has_multi_step=has_multi_step,
            total_requests=total_requests,
            auth_related_requests=auth_related
        )

        LOGGER.debug(
            f"HAR analysis: {total_requests} total requests, "
            f"{auth_related} auth-related, {len(successful_posts)} successful POSTs"
        )

        return insight

    except json.JSONDecodeError as e:
        LOGGER.warning(f"Failed to parse HAR JSON: {e}")
        return None
    except Exception as e:
        LOGGER.warning(f"HAR analysis failed: {e}", exc_info=True)
        return None


def _is_login_endpoint(path: str, method: str) -> bool:
    """Check if path/method indicates a login endpoint."""
    login_patterns = [
        '/login', '/signin', '/authenticate', '/auth',
        '/session', '/token', '/oauth', '/sso',
        '/api/login', '/api/auth', '/api/session',
        '/v1/login', '/v2/login', '/accounts/login',
        '/_login', '/_auth', '/user/login'
    ]

    # Check exact matches and startswith patterns
    for pattern in login_patterns:
        if pattern in path:
            return True

    # Additional heuristics for POST requests
    if method == 'POST' and any(keyword in path for keyword in ['user', 'account', 'credential']):
        return True

    return False


def _is_logout_endpoint(path: str) -> bool:
    """Check if path indicates a logout endpoint."""
    logout_patterns = [
        '/logout', '/signout', '/sign-out', '/exit',
        '/api/logout', '/session/end', '/auth/logout'
    ]
    return any(pattern in path for pattern in logout_patterns)


def _is_api_endpoint(path: str, url: str) -> bool:
    """Check if this is an API endpoint (not static resources)."""
    # Exclude static resources
    static_extensions = [
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map'
    ]

    if any(path.endswith(ext) for ext in static_extensions):
        return False

    # API indicators
    api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/']
    return any(pattern in path for pattern in api_patterns)


def _is_session_refresh(path: str, method: str, request: dict[str, Any]) -> bool:
    """Detect session refresh or token renewal requests."""
    refresh_patterns = ['/refresh', '/renew', '/token/refresh', '/auth/refresh']

    if any(pattern in path for pattern in refresh_patterns):
        return True

    # Check for refresh token in request body
    if method == 'POST':
        post_data = request.get('postData', {}).get('text', '')
        if 'refresh_token' in post_data.lower():
            return True

    return False


def _extract_location_header(response: dict[str, Any]) -> str | None:
    """Extract Location header from redirect response."""
    headers = response.get('headers', [])
    for header in headers:
        if header.get('name', '').lower() == 'location':
            return header.get('value', '')
    return None


def _extract_auth_headers(
    url: str,
    request: dict[str, Any],
    response: dict[str, Any]
) -> list[dict[str, Any]]:
    """Extract authentication-related headers from request/response."""
    auth_data = []

    # Check request headers
    req_headers = request.get('headers', [])
    for header in req_headers:
        name = header.get('name', '').lower()
        value = header.get('value', '')

        if name in ('authorization', 'x-auth-token', 'x-api-key'):
            auth_data.append({
                'url': url,
                'header_type': name,
                'value': value[:50] + '...' if len(value) > 50 else value,  # Truncate
                'direction': 'request'
            })

    # Check response headers
    resp_headers = response.get('headers', [])
    for header in resp_headers:
        name = header.get('name', '').lower()
        value = header.get('value', '')

        if name in ('www-authenticate', 'authentication-info', 'proxy-authenticate'):
            auth_data.append({
                'url': url,
                'header_type': name,
                'value': value,
                'direction': 'response'
            })

    return auth_data


def _extract_cookies(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract Set-Cookie headers and parse cookie attributes."""
    cookies = []

    # HAR format includes parsed cookies
    response_cookies = response.get('cookies', [])

    for cookie in response_cookies:
        cookies.append({
            'name': cookie.get('name', ''),
            'domain': cookie.get('domain', ''),
            'path': cookie.get('path', '/'),
            'secure': cookie.get('secure', False),
            'httpOnly': cookie.get('httpOnly', False),
            'sameSite': cookie.get('sameSite', ''),
        })

    return cookies


def get_primary_auth_endpoint(insight: HARAuthInsight) -> str | None:
    """
    Determine the most likely primary authentication endpoint.

    Prioritizes:
    1. Successful POST to login endpoint
    2. First login endpoint found
    3. API endpoint with auth success
    """
    if not insight:
        return None

    # Check successful POSTs first
    for post in insight.successful_posts:
        url = post['url']
        parsed = urlparse(url)
        path = parsed.path.lower()

        if _is_login_endpoint(path, 'POST'):
            return url

    # Fallback to first login endpoint
    if insight.login_endpoints:
        return insight.login_endpoints[0]

    # Last resort: API endpoint
    if insight.api_endpoints:
        return insight.api_endpoints[0]

    return None
