"""
Postman Collection Export Module

Generates Postman Collection v2.1 format for authentication flows.
"""
from __future__ import annotations

import json
import uuid
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


def export_to_postman(
    final_url: str,
    cookies: List[str],
    recorded_actions: List[Dict[str, Any]],
    *,
    collection_name: str = "AuthRecon Authentication Flow",
    username_var: str = "{{username}}",
    password_var: str = "{{password}}",
    form_action_url: Optional[str] = None,
    method: str = "POST",
) -> str:
    """
    Export authentication flow as Postman Collection v2.1.

    Args:
        final_url: The final authenticated URL
        cookies: List of cookie names from successful auth
        recorded_actions: List of actions recorded during automation
        collection_name: Name for the Postman collection
        username_var: Postman variable syntax for username
        password_var: Postman variable syntax for password
        form_action_url: Form action URL (defaults to final_url)
        method: HTTP method

    Returns:
        JSON string in Postman Collection v2.1 format
    """

    target_url = form_action_url or final_url
    parsed = urlparse(target_url)

    # Build form data from recorded actions
    form_data = []
    for action in recorded_actions:
        if action.get("action") == "type":
            selector = action.get("selector", "")
            value = action.get("value", "")
            field_name = _extract_field_name(selector)

            if field_name:
                # Replace placeholders with Postman variables
                actual_value = value
                if "${USERNAME}" in value:
                    actual_value = username_var
                elif "${PASSWORD}" in value:
                    actual_value = password_var

                form_data.append({
                    "key": field_name,
                    "value": actual_value,
                    "type": "text"
                })

    # Build Postman collection structure
    collection = {
        "info": {
            "_postman_id": str(uuid.uuid4()),
            "name": collection_name,
            "description": "Authentication flow exported from AuthRecon security scanner",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Authenticate",
                "event": [
                    {
                        "listen": "test",
                        "script": {
                            "exec": [
                                "// Test for successful authentication",
                                "pm.test(\"Status code is 200 or 302\", function () {",
                                "    pm.expect(pm.response.code).to.be.oneOf([200, 302, 301]);",
                                "});",
                                "",
                                "// Extract cookies",
                                "pm.test(\"Session cookies present\", function () {",
                                "    pm.expect(pm.cookies.toObject()).to.have.property('sessionid');",
                                "});",
                            ],
                            "type": "text/javascript"
                        }
                    }
                ],
                "request": {
                    "method": method.upper(),
                    "header": [
                        {
                            "key": "User-Agent",
                            "value": "Mozilla/5.0 (AuthRecon)",
                            "type": "text"
                        },
                        {
                            "key": "Accept",
                            "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "type": "text"
                        },
                        {
                            "key": "Content-Type",
                            "value": "application/x-www-form-urlencoded",
                            "type": "text"
                        },
                        {
                            "key": "Origin",
                            "value": f"{parsed.scheme}://{parsed.netloc}",
                            "type": "text"
                        },
                        {
                            "key": "Referer",
                            "value": target_url,
                            "type": "text"
                        }
                    ],
                    "body": {
                        "mode": "urlencoded",
                        "urlencoded": form_data
                    },
                    "url": {
                        "raw": target_url,
                        "protocol": parsed.scheme,
                        "host": parsed.netloc.split("."),
                        "path": parsed.path.strip("/").split("/") if parsed.path else [],
                        "query": _parse_query_string(parsed.query) if parsed.query else []
                    },
                    "description": "Authentication request captured by AuthRecon"
                },
                "response": []
            }
        ],
        "variable": [
            {
                "key": "username",
                "value": "YOUR_USERNAME_HERE",
                "type": "string"
            },
            {
                "key": "password",
                "value": "YOUR_PASSWORD_HERE",
                "type": "string"
            },
            {
                "key": "base_url",
                "value": f"{parsed.scheme}://{parsed.netloc}",
                "type": "string"
            }
        ]
    }

    return json.dumps(collection, indent=2)


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


def _parse_query_string(query: str) -> List[Dict[str, str]]:
    """Parse query string into Postman query params format."""
    if not query:
        return []

    params = []
    for param in query.split("&"):
        if "=" in param:
            key, value = param.split("=", 1)
            params.append({"key": key, "value": value})
        else:
            params.append({"key": param, "value": ""})

    return params
