"""
Burp Suite Export Module

Generates HTTP request files compatible with Burp Suite Repeater/Intruder.
Format: Raw HTTP requests that can be imported directly into Burp Suite.
"""
from __future__ import annotations

import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


def export_to_burp_http(
    final_url: str,
    cookies: List[str],
    recorded_actions: List[Dict[str, Any]],
    *,
    username_placeholder: str = "${USERNAME}",
    password_placeholder: str = "${PASSWORD}",
    form_action_url: Optional[str] = None,
    method: str = "POST",
    include_cookies: bool = True,
) -> str:
    """
    Export authentication flow as raw HTTP request for Burp Suite.

    Args:
        final_url: The final authenticated URL (used for Cookie header)
        cookies: List of cookie names from successful auth
        recorded_actions: List of actions recorded during automation
        username_placeholder: Placeholder for username in request
        password_placeholder: Placeholder for password in request
        form_action_url: Form action URL (defaults to final_url)
        method: HTTP method (POST, GET, etc.)
        include_cookies: Whether to include Cookie header

    Returns:
        Raw HTTP request string compatible with Burp Suite
    """

    # Parse URL to extract components
    parsed = urlparse(form_action_url or final_url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    # Build form data from recorded actions
    form_params = []
    for action in recorded_actions:
        if action.get("action") == "type":
            # Extract field name from selector
            selector = action.get("selector", "")
            value = action.get("value", "")

            # Try to extract field name from CSS selector
            field_name = _extract_field_name(selector)
            if field_name and value:
                form_params.append(f"{field_name}={value}")

    # Build request body
    body = "&".join(form_params) if form_params else ""

    # Build HTTP request
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Mozilla/5.0 (AuthRecon Security Scanner)",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {len(body)}",
        "Origin: " + f"{parsed.scheme}://{parsed.netloc}",
        "Connection: close",
        "Referer: " + (form_action_url or final_url),
        "Upgrade-Insecure-Requests: 1",
    ]

    # Add Cookie header if cookies were captured
    if include_cookies and cookies:
        cookie_pairs = [f"{name}=CAPTURED_VALUE" for name in cookies]
        lines.append("Cookie: " + "; ".join(cookie_pairs))

    # Add blank line before body
    lines.append("")
    lines.append(body)

    return "\n".join(lines)


def export_to_burp_json(
    final_url: str,
    cookies: List[str],
    recorded_actions: List[Dict[str, Any]],
    pre_auth_html: str = "",
    post_auth_html: str = "",
    timeline_events: List[str] = None,
) -> str:
    """
    Export authentication data as JSON for Burp Suite extensions.

    This format can be consumed by custom Burp extensions for automated testing.

    Returns:
        JSON string with comprehensive auth flow data
    """

    parsed = urlparse(final_url)

    data = {
        "target": {
            "host": parsed.netloc,
            "protocol": parsed.scheme,
            "url": final_url,
        },
        "authentication": {
            "type": "form-based",
            "cookies": cookies,
            "actions": recorded_actions,
        },
        "timeline": timeline_events or [],
        "artifacts": {
            "pre_auth_html_length": len(pre_auth_html),
            "post_auth_html_length": len(post_auth_html),
        },
        "metadata": {
            "exported_by": "AuthRecon",
            "format_version": "1.0",
        }
    }

    return json.dumps(data, indent=2)


def _extract_field_name(selector: str) -> Optional[str]:
    """
    Extract field name from CSS selector.

    Examples:
        css=[name='username'] -> username
        css=input[name='email'] -> email
        css=#login-field -> login-field
    """
    if not selector:
        return None

    # Remove 'css=' prefix if present
    selector = selector.replace("css=", "").strip()

    # Try to extract from [name='...'] attribute
    if "[name=" in selector:
        start = selector.index("[name=") + 6
        # Handle both single and double quotes
        if selector[start] in ("'", '"'):
            quote = selector[start]
            start += 1
            try:
                end = selector.index(quote, start)
                return selector[start:end]
            except ValueError:
                pass

    # Try to extract from [id='...'] or #id
    if "#" in selector:
        # Extract ID
        id_part = selector.split("#")[1].split("[")[0].split(".")[0].split(":")[0]
        return id_part

    return None
