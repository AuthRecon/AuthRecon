"""
OWASP ZAP Export Module

Generates authentication configuration for OWASP ZAP.
Exports in ZAP's JSON context format for form-based authentication.
"""
from __future__ import annotations

import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


def export_to_zap(
    final_url: str,
    cookies: List[str],
    recorded_actions: List[Dict[str, Any]],
    *,
    context_name: str = "AuthRecon Authentication",
    username_field: Optional[str] = None,
    password_field: Optional[str] = None,
    form_action_url: Optional[str] = None,
) -> str:
    """
    Export authentication configuration for OWASP ZAP.

    Creates a ZAP context configuration that can be imported into ZAP
    for automated authentication during scanning.

    Args:
        final_url: The final authenticated URL
        cookies: List of cookie names from successful auth
        recorded_actions: List of actions recorded during automation
        context_name: Name for the ZAP context
        username_field: Name of username field (auto-detected if not provided)
        password_field: Name of password field (auto-detected if not provided)
        form_action_url: Form action URL (defaults to final_url)

    Returns:
        JSON string in ZAP context format
    """

    target_url = form_action_url or final_url
    parsed = urlparse(target_url)

    # Auto-detect field names from recorded actions
    detected_username_field = username_field
    detected_password_field = password_field

    for action in recorded_actions:
        if action.get("action") == "type":
            selector = action.get("selector", "")
            value = action.get("value", "")
            field_name = _extract_field_name(selector)

            if not field_name:
                continue

            if "${USERNAME}" in value and not detected_username_field:
                detected_username_field = field_name
            elif "${PASSWORD}" in value and not detected_password_field:
                detected_password_field = field_name

    # Build ZAP context configuration
    context = {
        "contextType": "Form-based Auth",
        "context": {
            "name": context_name,
            "description": f"Authentication context exported from AuthRecon for {parsed.netloc}",
            "includedURLs": [
                f"{parsed.scheme}://{parsed.netloc}/.*"
            ],
            "excludedURLs": [],
            "authentication": {
                "type": "formBasedAuthentication",
                "parameters": {
                    "loginUrl": target_url,
                    "loginRequestData": _build_login_request_data(
                        recorded_actions,
                        detected_username_field,
                        detected_password_field
                    ),
                }
            },
            "sessionManagement": {
                "type": "cookieBasedSessionManagement",
                "parameters": {}
            },
            "users": [
                {
                    "name": "AuthRecon Test User",
                    "credentials": {
                        "type": "UsernamePasswordAuthenticationCredentials",
                        "username": "{%username%}",
                        "password": "{%password%}"
                    },
                    "enabled": True
                }
            ],
            "forcedUser": {
                "userId": 0,
                "enabled": False
            }
        },
        "metadata": {
            "exported_by": "AuthRecon",
            "version": "1.0",
            "username_field": detected_username_field,
            "password_field": detected_password_field,
            "cookies_captured": cookies
        }
    }

    return json.dumps(context, indent=2)


def export_to_zap_script(
    final_url: str,
    cookies: List[str],
    recorded_actions: List[Dict[str, Any]],
    *,
    username_field: Optional[str] = None,
    password_field: Optional[str] = None,
) -> str:
    """
    Export as ZAP automation script (Zest script format).

    This generates a Zest script that can be imported into ZAP for
    automated authentication replay.

    Returns:
        JSON string in Zest script format
    """

    parsed = urlparse(final_url)

    # Detect field names
    detected_username_field = username_field
    detected_password_field = password_field

    for action in recorded_actions:
        if action.get("action") == "type":
            selector = action.get("selector", "")
            value = action.get("value", "")
            field_name = _extract_field_name(selector)

            if not field_name:
                continue

            if "${USERNAME}" in value and not detected_username_field:
                detected_username_field = field_name
            elif "${PASSWORD}" in value and not detected_password_field:
                detected_password_field = field_name

    # Build Zest script
    script = {
        "about": "AuthRecon Authentication Script",
        "zestVersion": "0.3",
        "title": "AuthRecon Login Script",
        "description": f"Automated login script for {parsed.netloc}",
        "prefix": "",
        "type": "Standalone",
        "parameters": {
            "tokenStart": "{{",
            "tokenEnd": "}}",
            "tokens": {
                "username": "",
                "password": ""
            },
            "elementType": "ZestVariables"
        },
        "statements": [
            {
                "elementType": "ZestRequest",
                "url": final_url,
                "method": "POST",
                "headers": f"User-Agent: Mozilla/5.0\\r\\nContent-Type: application/x-www-form-urlencoded",
                "data": _build_login_request_data(
                    recorded_actions,
                    detected_username_field,
                    detected_password_field,
                    zest_format=True
                ),
                "response": {
                    "url": final_url,
                    "statusCode": 200,
                    "headers": "",
                    "body": ""
                },
                "assertions": [],
                "followRedirects": True
            }
        ],
        "authentication": []
    }

    return json.dumps(script, indent=2)


def _build_login_request_data(
    recorded_actions: List[Dict[str, Any]],
    username_field: Optional[str],
    password_field: Optional[str],
    zest_format: bool = False
) -> str:
    """
    Build login request data string from recorded actions.

    Args:
        recorded_actions: List of recorded actions
        username_field: Username field name
        password_field: Password field name
        zest_format: Use {{var}} format (Zest) vs {%var%} format (ZAP)

    Returns:
        URL-encoded form data string
    """
    params = []

    username_placeholder = "{{username}}" if zest_format else "{%username%}"
    password_placeholder = "{{password}}" if zest_format else "{%password%}"

    for action in recorded_actions:
        if action.get("action") == "type":
            selector = action.get("selector", "")
            value = action.get("value", "")
            field_name = _extract_field_name(selector)

            if not field_name:
                continue

            if "${USERNAME}" in value:
                params.append(f"{field_name}={username_placeholder}")
            elif "${PASSWORD}" in value:
                params.append(f"{field_name}={password_placeholder}")
            else:
                params.append(f"{field_name}={value}")

    return "&".join(params)


def _extract_field_name(selector: str) -> Optional[str]:
    """Extract field name from CSS selector."""
    if not selector:
        return None

    selector = selector.replace("css=", "").strip()

    # Try [name='...']
    if "[name=" in selector:
        start = selector.index("[name=") + 6
        if selector[start] in ("'", '"'):
            quote = selector[start]
            start += 1
            try:
                end = selector.index(quote, start)
                return selector[start:end]
            except ValueError:
                pass

    # Try #id
    if "#" in selector:
        id_part = selector.split("#")[1].split("[")[0].split(".")[0].split(":")[0]
        return id_part

    return None
