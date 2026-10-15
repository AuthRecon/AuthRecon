"""
RQ worker entry point.

Implements the automation pipeline for supported authentication flows.
Currently basic HTTP authentication runs through headless Selenium while
other auth types fall back to the legacy simulator.
"""
import logging
import json
from copy import deepcopy
import re
import hashlib
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any, Sequence
from urllib.parse import urljoin

import requests
from rq import Connection, Worker

from app.db import SessionLocal
from app.models import Run, TimelineEvent, Artifact, StoredCredential
from app.services.credentials import get_plain_secret
from app.core.security import get_credential_cipher
from app.schemas.run import RunStatus
from app.schemas.artifact import ArtifactType
from app.services.queue import get_redis_connection
from app.services.artifact_links import build_placeholder_url
from app.services.automation import (
    run_basic_auth,
    run_form_login,
    run_azure_login,
    run_okta_login,
    run_ldap_login,
    run_oauth_login,
    run_saml_login,
    AutomationFailure,
    CredentialRejected,
)
from app.services.side_files import build_side_file
from app.services.verify_pattern import choose_verify_pattern
from app.services.automation.navigation import drain_notes as drain_navigation_notes
from app.services.live_timeline import current as live_timeline_current, event_prefix, live_timeline, not_yet_written
from app.services.vnc_session import live_view
from app.services.storage import get_artifact_storage
from app.services.artifact_crypto import read_artifact_bytes, register_model_hooks, write_key_for_run
from app.services.profiles import get_profile_artifact_cipher
from app.services.artifact_crypto import encrypt_run_cookies
from app.core.urls import stable_page_url, strip_userinfo
from app.services.tech_fingerprint import analyze_tech_fingerprint
from app.services.flow_summarizer import generate_flow_summary
from app.services.exports.burp import export_to_burp_http
from app.services.exports.curl import export_to_curl, export_to_curl_script
from app.services.exports.postman import export_to_postman
from app.services.exports.zap import export_to_zap
from sqlalchemy.orm.attributes import flag_modified

logger = logging.getLogger(__name__)
register_model_hooks()

_HAR_CREATOR = {"name": "Auth Recon Worker", "version": "1.0"}


def _normalize_cookies_payload(cookies: Any) -> list[dict[str, Any]]:
    """
    Accept legacy string arrays or full cookie dicts and return a normalized list of cookie dicts.
    """
    if not cookies:
        return []
    normalized: list[dict[str, Any]] = []
    for cookie in cookies:
        if isinstance(cookie, dict):
            normalized.append(cookie)
        elif isinstance(cookie, str):
            normalized.append({"name": cookie})
    return normalized


def _cookie_names(cookies: Any) -> list[str]:
    """
    Extract cookie names from either dict or string entries for downstream consumers (tech fingerprinting).
    """
    names: list[str] = []
    if not cookies:
        return names
    for cookie in cookies:
        if isinstance(cookie, dict):
            name = cookie.get("name")
            if name:
                names.append(str(name))
        elif isinstance(cookie, str):
            names.append(cookie)
    return names


def _run_cookie_cipher(db, run):
    """Cipher for cookie values in a run's security_context: the owner's
    profile key, or the deployment master key for runs with no owner."""
    if run.submitted_by is not None:
        return get_profile_artifact_cipher(db, run.submitted_by)
    return get_credential_cipher()


def _encrypt_security_context_cookies(security_context: dict | None, cipher) -> None:
    """
    Encrypt all cookie values in-place within security_context using the provided cipher.
    Cookies are stored with plaintext in value_encrypted during extraction, this encrypts them.
    """
    if not security_context:
        return

    cookies_analysis = security_context.get("cookies")
    if not cookies_analysis or not isinstance(cookies_analysis, dict):
        return

    cookies_list = cookies_analysis.get("cookies")
    if not cookies_list or not isinstance(cookies_list, list):
        return

    for cookie in cookies_list:
        if not isinstance(cookie, dict):
            continue

        # Get plaintext value from value_encrypted field
        plaintext_value = cookie.get("value_encrypted")
        if plaintext_value and isinstance(plaintext_value, str):
            # Encrypt the value using Fernet cipher
            encrypted_bytes = cipher.encrypt(plaintext_value.encode("utf-8"))
            # Store as base64-encoded string for JSON
            cookie["value_encrypted"] = encrypted_bytes.decode("utf-8")


@dataclass
class RoleVariant:
    index: int
    label: str
    username: str
    password: str
    auth_hint: str
    tags: list[str]
    slug: str
    scope_entry: dict | None = None


@dataclass
class VariantResult:
    success: bool
    final_url: str | None = None
    pattern: str | None = None
    llm_pattern: str | None = None
    session_cookies: list[dict[str, Any]] = field(default_factory=list)
    security_context: dict | None = None  # SecurityContext as dict (will be stored as JSONB)
    pre_auth_html: str | None = None
    post_auth_html: str | None = None
    har_entries: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    events: list[TimelineEvent] = field(default_factory=list)
    error: str | None = None
    completed_at: datetime | None = None
    # Selectors the successful attempt actually used, for playbook learning.
    learned_selectors: dict[str, Any] | None = None
    # True when this variant already counted a playbook success, so learning
    # must not count the same run again.
    playbook_success_recorded: bool = False


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # pragma: no cover - HTML parser
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name and name.lower() == "href" and value:
                cleaned = value.strip()
                if cleaned:
                    self._links.add(cleaned)

    @property
    def links(self) -> set[str]:
        return self._links


def _normalize_link(base_url: str, href: str) -> str | None:
    if href.startswith("javascript:"):
        return None
    if href.startswith("#"):
        return None
    return urljoin(base_url, href)


def _build_sitemap_document(base_url: str, *html_documents: str | None) -> bytes:
    extractor = _LinkExtractor()
    for html_doc in html_documents:
        if html_doc:
            extractor.feed(html_doc)
    unique_links: list[str] = []
    seen: set[str] = set()

    for href in extractor.links:
        normalized = _normalize_link(base_url, href)
        if not normalized:
            continue
        if normalized not in seen:
            unique_links.append(normalized)
            seen.add(normalized)

    if base_url and base_url not in seen:
        unique_links.insert(0, base_url)

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for link in unique_links:
        lines.append(f"  <url><loc>{link}</loc></url>")
    lines.append("</urlset>")
    return "\n".join(lines).encode("utf-8")


def _build_side_from_recorded_actions(
    run_id: str,
    target_url: str,
    recorded_actions: list,
    verification_pattern: str = None,
    final_url: str = None,
) -> dict:
    """Build Selenium IDE .side file from JS-recorded user interactions."""
    import uuid

    # Open + settle — same pattern as build_side_file so scanners behave consistently
    commands = [
        {"id": str(uuid.uuid4()), "command": "open",  "target": target_url, "targets": [], "value": ""},
        {"id": str(uuid.uuid4()), "command": "pause", "target": "2000",     "targets": [], "value": ""},
    ]

    seen_types: dict = {}  # target -> last value recorded (dedup in-order)

    for action in recorded_actions:
        cmd    = action.get("command", "")
        target = action.get("target", "")
        value  = action.get("value", "")

        if cmd == "open":
            # Subsequent opens are server-side redirects that happen automatically;
            # don't re-issue them or the scanner double-navigates.
            continue

        elif cmd in ("click", "clickLink"):
            loc = [target, target.split('=')[0] if '=' in target else "css"]
            commands.append({"id": str(uuid.uuid4()), "command": "waitForElementVisible",
                             "target": target, "targets": [loc], "value": "15000"})
            commands.append({"id": str(uuid.uuid4()), "command": "click",
                             "target": target, "targets": [loc], "value": ""})

        elif cmd == "type":
            if seen_types.get(target) == value:
                continue  # blur fires multiple times on same value; keep first
            seen_types[target] = value
            loc = [target, target.split('=')[0] if '=' in target else "css"]
            commands.append({"id": str(uuid.uuid4()), "command": "waitForElementVisible",
                             "target": target, "targets": [loc], "value": "15000"})
            commands.append({"id": str(uuid.uuid4()), "command": "type",
                             "target": target, "targets": [loc], "value": value})

        elif cmd == "submit":
            # No specific button recorded — send ENTER on the last typed field
            last_typed = next(reversed(seen_types), None)
            if last_typed:
                commands.append({"id": str(uuid.uuid4()), "command": "sendKeys",
                                 "target": last_typed, "targets": [], "value": "${KEY_ENTER}"})

    # Final settle pause so scanner doesn't race against post-login redirect
    commands.append({"id": str(uuid.uuid4()), "command": "pause", "target": "6000",
                     "targets": [], "value": ""})

    return {
        "id": run_id,
        "version": "2.0",
        "name": f"AuthRecon Manual Recording - {target_url}",
        "url": target_url,
        "tests": [{"id": f"{run_id}-test", "name": "Authentication Flow", "commands": commands}],
        "suites": [{
            "id": f"{run_id}-suite", "name": "Default Suite",
            "persistSession": False, "parallel": False, "timeout": 300,
            "tests": [f"{run_id}-test"],
        }],
        "plugins": [{
            "id": "login", "enabled": True,
            "config": {"loginUrl": target_url, "pageToVerify": stable_page_url(final_url) or target_url},
        }],
        "urls": [target_url],
        "pluginsVersion": {},
    }


def _generate_manual_curl_script(final_url: str, cookies: list, target_url: str) -> str:
    """
    Generate bash script with curl command for authenticated requests (manual recording mode).

    Args:
        final_url: The authenticated page URL
        cookies: List of cookie dicts with name, value, domain, etc.
        target_url: Original target URL

    Returns:
        Bash script string
    """
    from urllib.parse import urlparse

    parsed = urlparse(final_url)

    # Build cookie string
    cookie_parts = []
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value", "")
        if name and value:
            cookie_parts.append(f"{name}={value}")

    cookie_string = "; ".join(cookie_parts) if cookie_parts else "REPLACE_WITH_SESSION_COOKIE"

    lines = [
        "#!/bin/bash",
        "# AuthRecon - Authenticated Request Script",
        "# Generated by AuthRecon Manual Recording Mode",
        "",
        "# This script demonstrates how to make authenticated requests",
        "# using the captured session cookies",
        "",
        "# Configuration",
        f'TARGET_URL="{final_url}"',
        f'ORIGIN_URL="{target_url}"',
        "",
        "# Session cookies (captured during manual authentication)",
        f'COOKIES="{cookie_string}"',
        "",
        "# Make authenticated request",
        "echo 'Making authenticated request to $TARGET_URL'",
        "curl -X GET \\",
        "  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \\",
        "  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \\",
        "  -H 'Accept-Language: en-US,en;q=0.5' \\",
        '  -H "Cookie: $COOKIES" \\',
        "  -H 'Connection: keep-alive' \\",
        "  -L \\",
        '  "$TARGET_URL"',
        "",
        "# Example: Save response to file",
        "# curl ... -o response.html",
        "",
        "# Example: Include response headers",
        "# curl ... -i",
        "",
        "# Example: Follow redirects with verbose output",
        "# curl ... -L -v",
        "",
        "# End of script",
    ]

    return "\n".join(lines)


def _generate_manual_burp_request(final_url: str, cookies: list) -> str:
    """
    Generate raw HTTP request for Burp Suite (manual recording mode).

    Args:
        final_url: The authenticated page URL
        cookies: List of cookie dicts with name, value, domain, etc.

    Returns:
        Raw HTTP request string
    """
    from urllib.parse import urlparse

    parsed = urlparse(final_url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    # Build cookie header
    cookie_parts = []
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value", "")
        if name and value:
            cookie_parts.append(f"{name}={value}")

    cookie_header = "; ".join(cookie_parts) if cookie_parts else "session=REPLACE_ME"

    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate",
        f"Cookie: {cookie_header}",
        "Connection: close",
        "Upgrade-Insecure-Requests: 1",
        "",
        ""
    ]

    return "\n".join(lines)


def _generate_manual_postman_collection(final_url: str, cookies: list, target_url: str) -> dict:
    """
    Generate Postman collection for authenticated requests (manual recording mode).

    Args:
        final_url: The authenticated page URL
        cookies: List of cookie dicts with name, value, domain, etc.
        target_url: Original target URL

    Returns:
        Postman collection dict
    """
    from urllib.parse import urlparse

    parsed = urlparse(final_url)

    # Build Postman cookies
    postman_cookies = []
    for cookie in cookies:
        name = cookie.get("name", "")
        value = cookie.get("value", "")
        domain = cookie.get("domain", parsed.netloc)
        path = cookie.get("path", "/")

        if name and value:
            postman_cookies.append({
                "key": name,
                "value": value,
                "domain": domain,
                "path": path
            })

    collection = {
        "info": {
            "name": "AuthRecon - Manual Recording Session",
            "description": "Authenticated requests captured during manual recording mode",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Authenticated Request",
                "request": {
                    "method": "GET",
                    "header": [
                        {
                            "key": "User-Agent",
                            "value": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                            "type": "text"
                        },
                        {
                            "key": "Accept",
                            "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "type": "text"
                        }
                    ],
                    "url": {
                        "raw": final_url,
                        "protocol": parsed.scheme,
                        "host": parsed.netloc.split('.'),
                        "path": parsed.path.split('/')[1:] if parsed.path else [],
                        "query": []
                    },
                    "description": f"Authenticated request to {final_url} using session cookies"
                },
                "response": []
            }
        ],
        "variable": [
            {
                "key": "base_url",
                "value": f"{parsed.scheme}://{parsed.netloc}",
                "type": "string"
            },
            {
                "key": "target_url",
                "value": target_url,
                "type": "string"
            }
        ]
    }

    # Add cookies as collection-level auth
    if postman_cookies:
        collection["auth"] = {
            "type": "noauth"
        }
        # Note: Postman cookies are typically managed separately via cookie manager
        # We include them in the description
        cookie_str = "; ".join([f"{c['key']}={c['value']}" for c in postman_cookies])
        collection["info"]["description"] += f"\n\nRequired Cookies:\n{cookie_str}"

    return collection


def _generate_manual_zap_context(final_url: str, cookies: list, target_url: str) -> str:
    """
    Generate OWASP ZAP context XML (manual recording mode).

    Args:
        final_url: The authenticated page URL
        cookies: List of cookie dicts with name, value, domain, etc.
        target_url: Original target URL

    Returns:
        ZAP context XML string
    """
    from urllib.parse import urlparse
    from xml.sax.saxutils import escape

    parsed = urlparse(final_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Build session tokens (cookies)
    session_tokens = []
    for cookie in cookies:
        name = cookie.get("name", "")
        if name:
            session_tokens.append(f'    <token>{escape(name)}</token>')

    session_tokens_xml = "\n".join(session_tokens) if session_tokens else '    <token>JSESSIONID</token>'

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
        '<configuration>',
        '  <context>',
        '    <name>AuthRecon Manual Recording</name>',
        '    <desc>Context for authenticated scanning captured via manual recording</desc>',
        '    <inscope>true</inscope>',
        '    <incregexes>',
        f'      <incregex>{escape(base_url)}/.*</incregex>',
        '    </incregexes>',
        '    <tech>',
        '      <include>Db</include>',
        '      <include>Language</include>',
        '      <include>OS</include>',
        '      <include>SCM</include>',
        '      <include>WS</include>',
        '    </tech>',
        '    <urlparser>',
        '      <class>org.zaproxy.zap.model.StandardParameterParser</class>',
        '      <config/>',
        '    </urlparser>',
        '    <authentication>',
        '      <type>2</type>',
        '      <strategy>EACH_RESP</strategy>',
        '      <pollurl/>',
        '      <polldata/>',
        '      <pollheaders/>',
        '      <pollfreq>60</pollfreq>',
        '      <pollunits>REQUESTS</pollunits>',
        '    </authentication>',
        '    <sessionManagement>',
        '      <type>1</type>',
        '    </sessionManagement>',
        '    <sessiontokens>',
        session_tokens_xml,
        '    </sessiontokens>',
        '  </context>',
        '</configuration>',
    ]

    return "\n".join(xml_lines)


def _build_har_document(run_id: str, start_time: datetime, entries: list[dict[str, Any]]) -> bytes:
    har_entries: list[dict[str, Any]] = []
    for index, item in enumerate(entries):
        started = start_time + timedelta(milliseconds=index * 120)
        har_entries.append(
            {
                "startedDateTime": started.isoformat(),
                "time": item.get("time", 0),
                "request": {
                    "method": item.get("method", "GET"),
                    "url": item.get("url"),
                    "httpVersion": "HTTP/1.1",
                    "headers": item.get("request_headers", []),
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": item.get("status", 200),
                    "statusText": item.get("statusText", "OK"),
                    "httpVersion": "HTTP/1.1",
                    "headers": item.get("response_headers", []),
                    "cookies": [],
                    "content": {
                        "size": item.get("bodySize", 0),
                        "mimeType": item.get("mimeType", "text/html"),
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": item.get("bodySize", 0),
                },
                "cache": {},
                "timings": {
                    "send": 5,
                    "wait": item.get("time", 0),
                    "receive": 5,
                },
                "pageref": run_id,
            }
        )

    har = {
        "log": {
            "version": "1.2",
            "creator": _HAR_CREATOR,
            "pages": [
                {
                    "id": run_id,
                    "startedDateTime": start_time.isoformat(),
                    "title": entries[-1].get("title", run_id) if entries else run_id,
                    "pageTimings": {
                        "onLoad": entries[-1].get("time", 0) if entries else 0,
                    },
                }
            ],
            "entries": har_entries,
        }
    }
    return json.dumps(har, indent=2).encode("utf-8")


def _slugify_label(value: str, index: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", (value or "").strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or f"role-{index:02d}"


def _prefixed_name(variant: RoleVariant, base_name: str, multi_role: bool) -> str:
    if multi_role:
        return f"{variant.slug}-{base_name}"
    return base_name


def _artifact_id(run_id: str, variant: RoleVariant, suffix: str, multi_role: bool) -> str:
    if multi_role:
        candidate = f"{run_id}-R{variant.index:02d}-{suffix}"
    else:
        candidate = f"{run_id}-{suffix}"

    if len(candidate) <= 40:
        return candidate

    digest = hashlib.blake2s(candidate.encode("utf-8"), digest_size=6).hexdigest()
    fallback = f"{run_id}-{digest}"
    return fallback[:40]


def _make_role_event(run_id: str, variant: RoleVariant, message: str, multi_role: bool) -> TimelineEvent:
    prefix = f"[{variant.label}] " if multi_role else ""
    event = TimelineEvent(
        run_id=run_id,
        occurred_at=datetime.now(timezone.utc),
        message=f"{prefix}{message}",
    )
    # Inside a run's live_timeline the event is saved now, with its real time;
    # the end-of-run save then skips it (see _not_written_live).
    current = live_timeline_current()
    event._written_live = bool(current and current.run_id == run_id and current.write(event.message, event.occurred_at))
    return event


def _not_written_live(events: list[TimelineEvent]) -> list[TimelineEvent]:
    return [e for e in events if not getattr(e, "_written_live", False)]


def _build_variants(run: Run, detected_label: str, username: str | None, secret_used: str | None) -> list[RoleVariant]:
    variants: list[RoleVariant] = []
    options = run.options if isinstance(run.options, dict) else {}
    scope = options.get("scope") if isinstance(options, dict) else {}
    raw_roles = scope.get("roles") if isinstance(scope, dict) else None

    if isinstance(raw_roles, list) and raw_roles:
        cipher = get_credential_cipher()
        for index, role in enumerate(raw_roles, start=1):
            if not isinstance(role, dict):
                continue
            role_username = (role.get("username") or "").strip()
            enc_secret = role.get("secret")
            if not role_username or not isinstance(enc_secret, str):
                logger.warning("Role %s for run %s missing username or secret.", index, run.id)
                continue
            try:
                password = cipher.decrypt(enc_secret.encode("utf-8")).decode("utf-8")
            except Exception:  # pragma: no cover - defensive logging
                logger.warning("Unable to decrypt credential for role %s on run %s.", index, run.id)
                continue
            label = (role.get("label") or f"Role {index}").strip() or f"Role {index}"
            auth_hint = (role.get("auth_type") or detected_label) or detected_label
            tags = role.get("tags") if isinstance(role.get("tags"), list) else []
            slug = _slugify_label(label, index)
            role["slug"] = slug
            variants.append(
                RoleVariant(
                    index=index,
                    label=label,
                    username=role_username,
                    password=password,
                    auth_hint=auth_hint,
                    tags=[str(tag) for tag in tags if isinstance(tag, str)],
                    slug=slug,
                    scope_entry=role,
                )
            )
    else:
        label = "Primary"
        slug = _slugify_label(label, 1)
        variants.append(
            RoleVariant(
                index=1,
                label=label,
                username=(username or "").strip(),
                password=secret_used or "",
                auth_hint=detected_label,
                tags=[],
                slug=slug,
                scope_entry=None,
            )
        )

    return variants


def _encode_utf8(content: str | None) -> bytes:
    return (content or "").encode("utf-8")


def _fetch_pre_auth_html(url: str) -> str | None:
    try:
        response = requests.get(url, timeout=10)
        if response.ok and response.text:
            return response.text
        return response.text or None
    except Exception:  # pragma: no cover - best effort network fetch
        return None


def _generate_export_artifacts(
    run: Run,
    variant: RoleVariant,
    automation: Any,
    storage: Any,
    finish: datetime,
    multi_role: bool,
    record: Any,
) -> list[Artifact]:
    """
    Generate export artifacts for security testing tools.

    Creates:
    - Burp Suite HTTP request file
    - curl command script
    - Postman Collection v2.1
    - OWASP ZAP context config
    """
    artifacts = []

    cookie_names = _cookie_names(automation.cookies)

    # Convert recorded actions to dict format for export functions
    actions_dict = [
        {
            "action": action.action,
            "selector": action.selector,
            "value": action.value,
            "note": action.note,
        }
        for action in (automation.recorded_actions or [])
    ]

    try:
        # 1. Burp Suite HTTP Request
        burp_content = export_to_burp_http(
            final_url=automation.final_url or run.target_url,
            cookies=cookie_names,
            recorded_actions=actions_dict,
            form_action_url=run.target_url,
        )
        burp_name = _prefixed_name(variant, "burp_request.txt", multi_role)
        burp_path = storage.save_bytes(run.id, burp_name, burp_content.encode("utf-8"))
        artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "BURP", multi_role),
                run_id=run.id,
                name=burp_name,
                description=f"Burp Suite HTTP request for {variant.label} - Import into Burp Repeater/Intruder",
                type="burp_request",
                size_bytes=len(burp_content.encode("utf-8")),
                storage_path=burp_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )
        record("Generated Burp Suite request file.")
    except Exception as e:
        logger.warning(f"Failed to generate Burp export: {e}")

    try:
        # 2. curl Command Script
        curl_content = export_to_curl_script(
            final_url=automation.final_url or run.target_url,
            cookies=cookie_names,
            recorded_actions=actions_dict,
            form_action_url=run.target_url,
        )
        curl_name = _prefixed_name(variant, "auth_request.sh", multi_role)
        curl_path = storage.save_bytes(run.id, curl_name, curl_content.encode("utf-8"))
        artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "CURL", multi_role),
                run_id=run.id,
                name=curl_name,
                description=f"Bash script with curl command for {variant.label} - Executable authentication replay",
                type="curl_script",
                size_bytes=len(curl_content.encode("utf-8")),
                storage_path=curl_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )
        record("Generated curl script.")
    except Exception as e:
        logger.warning(f"Failed to generate curl export: {e}")

    try:
        # 3. Postman Collection
        postman_content = export_to_postman(
            final_url=automation.final_url or run.target_url,
            cookies=cookie_names,
            recorded_actions=actions_dict,
            collection_name=f"AuthRecon - {variant.label}",
            form_action_url=run.target_url,
        )
        postman_name = _prefixed_name(variant, "postman_collection.json", multi_role)
        postman_path = storage.save_bytes(run.id, postman_name, postman_content.encode("utf-8"))
        artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "POSTMAN", multi_role),
                run_id=run.id,
                name=postman_name,
                description=f"Postman Collection v2.1 for {variant.label} - Import into Postman/Newman",
                type="postman_collection",
                size_bytes=len(postman_content.encode("utf-8")),
                storage_path=postman_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )
        record("Generated Postman collection.")
    except Exception as e:
        logger.warning(f"Failed to generate Postman export: {e}")

    try:
        # 4. OWASP ZAP Context
        zap_content = export_to_zap(
            final_url=automation.final_url or run.target_url,
            cookies=cookie_names,
            recorded_actions=actions_dict,
            context_name=f"AuthRecon - {variant.label}",
            form_action_url=run.target_url,
        )
        zap_name = _prefixed_name(variant, "zap_context.json", multi_role)
        zap_path = storage.save_bytes(run.id, zap_name, zap_content.encode("utf-8"))
        artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "ZAP", multi_role),
                run_id=run.id,
                name=zap_name,
                description=f"OWASP ZAP context configuration for {variant.label} - Import into ZAP for authenticated scanning",
                type="zap_context",
                size_bytes=len(zap_content.encode("utf-8")),
                storage_path=zap_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )
        record("Generated OWASP ZAP context.")
    except Exception as e:
        logger.warning(f"Failed to generate ZAP export: {e}")

    return artifacts


def _persist_snapshot_artifacts(
    run: Run,
    start_time: datetime,
    variant_results: list[tuple[RoleVariant, VariantResult]],
    storage: "ArtifactStorage",
    artifacts_to_add: list[Artifact],
    multi_role: bool,
) -> None:
    for variant, result in variant_results:
        completed_at = result.completed_at or datetime.now(timezone.utc)
        pre_html = result.pre_auth_html or f"<html><body><p>Pre-authentication snapshot for {variant.label} could not be captured.</p></body></html>"
        post_html = result.post_auth_html or f"<html><body><p>Post-authentication snapshot for {variant.label} could not be captured.</p></body></html>"

        sitemap_base = result.final_url or run.final_url or run.target_url
        sitemap_bytes = _build_sitemap_document(sitemap_base, pre_html, post_html)
        sitemap_name = _prefixed_name(variant, "sitemap.xml", multi_role)
        sitemap_path = storage.save_bytes(run.id, sitemap_name, sitemap_bytes)
        artifacts_to_add.append(
            Artifact(
                id=_artifact_id(run.id, variant, "SITEMAP", multi_role),
                run_id=run.id,
                name=sitemap_name,
                description=f"XML sitemap derived from captured pages for {variant.label}.",
                type=ArtifactType.sitemap.value,
                size_bytes=len(sitemap_bytes),
                storage_path=sitemap_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=completed_at,
            )
        )

        pre_bytes = _encode_utf8(pre_html)
        pre_name = _prefixed_name(variant, "pre_auth.html", multi_role)
        pre_path = storage.save_bytes(run.id, pre_name, pre_bytes)
        artifacts_to_add.append(
            Artifact(
                id=_artifact_id(run.id, variant, "HTML-PRE", multi_role),
                run_id=run.id,
                name=pre_name,
                description=f"HTML snapshot prior to authentication for {variant.label}.",
                type=ArtifactType.html.value,
                size_bytes=len(pre_bytes),
                storage_path=pre_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=completed_at,
            )
        )

        post_bytes = _encode_utf8(post_html)
        post_name = _prefixed_name(variant, "post_auth.html", multi_role)
        post_path = storage.save_bytes(run.id, post_name, post_bytes)
        artifacts_to_add.append(
            Artifact(
                id=_artifact_id(run.id, variant, "HTML-POST", multi_role),
                run_id=run.id,
                name=post_name,
                description=f"HTML snapshot captured after authentication for {variant.label}.",
                type=ArtifactType.html.value,
                size_bytes=len(post_bytes),
                storage_path=post_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=completed_at,
            )
        )

        # HAR file generation: Try Playwright first (real HAR), fallback to synthetic
        har_bytes = None
        har_description = None

        if result.success and result.session_cookies:
            try:
                from app.services.automation.multi_engine import capture_playwright_har_post_auth
                import asyncio

                # Run async Playwright HAR capture
                har_bytes = asyncio.run(capture_playwright_har_post_auth(
                    run_id=f"{run.id}-{variant.slug}" if multi_role else run.id,
                    target_url=sitemap_base,
                    cookies=result.session_cookies,
                    timeout_seconds=30
                ))

                if har_bytes:
                    har_description = (
                        f"Post-login HAR for {variant.label}: the authenticated landing page re-loaded "
                        "with the captured session cookies. It does not contain the login requests "
                        "themselves (see playwright-network.har, when present, for those)."
                    )
                    logger.info(f"Playwright HAR captured for {run.id} variant {variant.label}: {len(har_bytes)} bytes")

                    # Scan for JavaScript secrets (pre-auth)
                    try:
                        from app.services.js_secret_scanner import scan_javascript_secrets
                        js_secrets_analysis = scan_javascript_secrets(har_bytes, pre_auth=True)
                        if js_secrets_analysis and js_secrets_analysis.get("total_findings", 0) > 0:
                            logger.info(f"⚠️ Found {js_secrets_analysis['total_findings']} secret(s) in JavaScript files (pre-auth) for {run.id}")
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["js_secrets"] = js_secrets_analysis
                            for secret in js_secrets_analysis.get("findings", []):
                                if secret.get("severity") == "CRITICAL":
                                    logger.info(f"🔴 CRITICAL: {secret.get('type')} found in {secret.get('file')}:{secret.get('line')} for {run.id}")
                        else:
                            logger.info(f"✅ No secrets detected in JavaScript files for {run.id}")
                    except Exception as e:
                        logger.warning(f"JS secret scanner failed for {run.id}: {str(e)}")
            except Exception as e:
                logger.warning(f"Playwright HAR capture failed for {run.id}: {e}")
                # Continue to synthetic fallback

        # Fallback to synthetic HAR if Playwright didn't capture
        if not har_bytes:
            har_entries = result.har_entries or [
                {
                    "url": sitemap_base,
                    "method": "GET",
                    "status": 200,
                    "statusText": "OK",
                    "mimeType": "text/html",
                    "bodySize": len(post_bytes),
                    "time": 180,
                    "title": f"{variant.label} authenticated page",
                }
            ]
            har_run_id = f"{run.id}-{variant.slug}" if multi_role else run.id
            har_bytes = _build_har_document(har_run_id, start_time, har_entries)
            har_description = (
                f"Approximate HAR for {variant.label}, reconstructed from automation events "
                "(no live network capture was available). Use for reference only."
            )
            logger.info(f"Using synthetic HAR for {run.id} variant {variant.label}")

        har_name = _prefixed_name(variant, "network.har", multi_role)
        har_path = storage.save_bytes(run.id, har_name, har_bytes)
        artifacts_to_add.append(
            Artifact(
                id=_artifact_id(run.id, variant, "HAR", multi_role),
                run_id=run.id,
                name=har_name,
                description=har_description,
                type=ArtifactType.har.value,
                size_bytes=len(har_bytes),
                storage_path=har_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=completed_at,
            )
        )


def _execute_variant(
    run: Run,
    variant: RoleVariant,
    *,
    llm_allowed: bool,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    detected_label_readable: str,
    headless: bool = True,
) -> VariantResult:
    auth_hint = (variant.auth_hint or "").lower()
    used_basic_auth = auth_hint == "basic_auth" and variant.username
    used_azure_auth = auth_hint == "azure_ad" and variant.username and variant.password
    used_saml_auth = auth_hint in {"saml", "saml_login", "saml2"} and variant.username and variant.password
    used_okta_auth = auth_hint == "okta" and variant.username and variant.password
    used_ldap_auth = auth_hint == "ldap" and variant.username and variant.password
    used_oauth_auth = auth_hint == "oauth" and variant.username and variant.password
    used_form_auth = auth_hint in {"form_auth", "form-based", "form_based", "js_form_auth"} and variant.username and variant.password
    used_two_step = auth_hint in {"two_step_form", "multi_step_form"} and variant.username and variant.password

    # Extract login_hint and domain_prefix from run options
    login_hint = None
    domain_prefix = None
    if isinstance(run.options, dict):
        login_hint = run.options.get("login_hint")
        domain_prefix = run.options.get("domain_prefix")

    if used_basic_auth:
        return _run_basic_variant(run, variant, storage, multi_role, headless)
    if used_azure_auth:
        return _run_azure_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless)
    if used_saml_auth:
        return _run_saml_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless)
    if used_okta_auth:
        return _run_okta_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless)
    if used_ldap_auth:
        return _run_ldap_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless)
    if used_oauth_auth:
        return _run_oauth_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless)
    if used_form_auth:
        return _run_form_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless, llm_allowed)
    if used_two_step:
        return _run_two_step_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless)
    return _run_unsupported_variant(run, variant, auth_hint, detected_label_readable)


def _run_basic_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    multi_role: bool,
    headless: bool = True,
) -> VariantResult:
    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))

    pre_auth_html = _fetch_pre_auth_html(run.target_url)
    if pre_auth_html is None:
        record("Unable to capture pre-authentication challenge for basic auth.")
    har_entries = [
        {
            "url": run.target_url,
            "method": "GET",
            "status": 401 if pre_auth_html is None else 200,
            "statusText": "Unauthorized" if pre_auth_html is None else "OK",
            "mimeType": "text/html",
            "bodySize": len(pre_auth_html or ""),
            "time": 140,
            "title": f"{variant.label} pre-authentication challenge",
        }
    ]

    try:
        record("Detected basic authentication; launching headless browser.")
        automation = run_basic_auth(run.target_url, variant.username or "", variant.password or "", headless=headless)
        record("Submitted basic authentication challenge.")
        record("Captured authenticated response.")

        finish = datetime.now(timezone.utc)
        final_url = automation.final_url or run.target_url
        description = f"[{variant.label}] Authenticated page screenshot captured via Selenium at {final_url}."
        screenshot_name = _prefixed_name(variant, "authenticated.png", multi_role)
        storage_path = storage.save_bytes(run.id, screenshot_name, automation.screenshot)

        har_entries.append(
            {
                "url": final_url,
                "method": "GET",
                "status": 200,
                "statusText": "OK",
                "mimeType": "text/html",
                "bodySize": len((automation.html_source or "").encode("utf-8")),
                "time": 180,
                "title": f"{variant.label} authenticated page",
            }
        )

        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "BASIC-SHOT", multi_role),
                run_id=run.id,
                name=screenshot_name,
                description=description,
                type=ArtifactType.screenshot.value,
                size_bytes=len(automation.screenshot),
                storage_path=storage_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        # Multi-engine support: Run HTTPX if selected (fast HTTP Basic Auth)
        engines = run.options.get("engines", ["selenium"]) if isinstance(run.options, dict) else ["selenium"]
        if "httpx" in engines:
            try:
                import asyncio
                from app.services.automation.patterns.httpx.basic_auth import attempt_basic_auth_httpx
                time.sleep(1)  # Shorter delay for HTTPX (it's fast)
                record("Running HTTPX engine for fast Basic Auth...")
                httpx_result = asyncio.run(attempt_basic_auth_httpx(
                    run_id=f"{run.id}-httpx", target_url=run.target_url,
                    username=variant.username, password=variant.password,
                    timeout_seconds=30
                ))
                if httpx_result.success and httpx_result.timeline_json:
                    # Save HTTPX timeline (lightweight alternative to HAR)
                    httpx_timeline_name = _prefixed_name(variant, "httpx-timeline.json", multi_role)
                    httpx_timeline_path = storage.save_bytes(run.id, httpx_timeline_name, httpx_result.timeline_json)
                    result.artifacts.append(Artifact(
                        id=_artifact_id(run.id, variant, "HTTPX-TIMELINE", multi_role), run_id=run.id,
                        name=httpx_timeline_name, description=f"HTTPX HTTP timeline for Basic Auth ({variant.label}).",
                        type=ArtifactType.har.value,  # Reuse HAR type for now
                        size_bytes=len(httpx_result.timeline_json),
                        storage_path=httpx_timeline_path, download_url=None, role_slug=variant.slug,
                        created_at=datetime.now(timezone.utc),
                    ))
                    record(f"HTTPX timeline captured ({len(httpx_result.timeline_json)} bytes)")

                    # HTTPX has no screenshots (headless HTTP client)
                    # Merge HTTPX cookies with Selenium cookies if both succeeded
                    if httpx_result.cookies:
                        record(f"HTTPX extracted {len(httpx_result.cookies)} cookies")
            except Exception as e:
                record(f"HTTPX engine failed: {str(e)}")

        result.success = True
        result.final_url = final_url
        result.pattern = automation.page_title
        result.llm_pattern = None
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = pre_auth_html
        result.post_auth_html = automation.html_source or ""
        result.har_entries = har_entries
        result.completed_at = finish
    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("Basic auth automation failed for run %s", run.id)
        record(f"Basic authentication automation failed: {exc}")
        result.error = str(exc)
        result.pre_auth_html = pre_auth_html
        result.post_auth_html = None
        result.har_entries = har_entries
        result.completed_at = datetime.now(timezone.utc)

    return result


def _run_azure_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    headless: bool = True,
) -> VariantResult:
    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))

    try:
        record("Detected Azure AD authentication; launching headless browser.")
        automation = run_azure_login(
            run.target_url,
            variant.username or "",
            variant.password or "",
            login_hint=login_hint,
            domain_prefix=domain_prefix,
            headless=headless
        )
        for message in not_yet_written(automation.events):
            record(message)

        finish = datetime.now(timezone.utc)
        side_bytes = build_side_file(run.target_url, automation, variant.username or "", variant.password or "")
        # Plaintext credentials stay inside the .side (Tenable needs them);
        # ArtifactStorage encrypts the whole file at rest with the owner's key.
        encrypted_side_bytes = side_bytes
        side_is_encrypted = True

        side_name = _prefixed_name(variant, f"login_{finish.strftime('%Y%m%d_%H%M%S')}.side", multi_role)
        side_path = storage.save_bytes(run.id, side_name, encrypted_side_bytes)
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "SIDE", multi_role),
                run_id=run.id,
                name=side_name,
                description=f"Selenium IDE (.side) automation script generated from captured Azure login flow for {variant.label}.",
                type=ArtifactType.side_file.value,
                size_bytes=len(encrypted_side_bytes),
                storage_path=side_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
                is_encrypted=side_is_encrypted,
            )
        )
        record("Generated Selenium IDE .side file.")

        # Generate export artifacts for security testing tools
        export_artifacts = _generate_export_artifacts(
            run, variant, automation, storage, finish, multi_role, record
        )
        result.artifacts.extend(export_artifacts)

        for index, screenshot in enumerate(automation.screenshots, start=1):
            screenshot_name = _prefixed_name(variant, screenshot.file_name, multi_role)
            storage_path = storage.save_bytes(run.id, screenshot_name, screenshot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"AZURE-{index:02d}", multi_role),
                    run_id=run.id,
                    name=screenshot_name,
                    description=screenshot.description or f"Captured during Azure automation for {variant.label}.",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(screenshot.data),
                    storage_path=storage_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                )
            )

        result.success = True
        result.final_url = automation.final_url or run.target_url
        result.pattern = automation.pattern
        result.llm_pattern = None
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = automation.pre_auth_html
        result.post_auth_html = automation.post_auth_html
        result.completed_at = finish
    except AutomationFailure as failure:
        logger.warning("Azure AD automation failed for run %s: %s", run.id, failure)
        failure_time = datetime.now(timezone.utc)
        for message in not_yet_written(failure.events):
            record(message)
        record("Azure authentication automation failed.")

        for index, screenshot in enumerate(failure.screenshots, start=1):
            screenshot_name = _prefixed_name(variant, screenshot.file_name, multi_role)
            storage_path = storage.save_bytes(run.id, screenshot_name, screenshot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"AZURE-ERR-{index:02d}", multi_role),
                    run_id=run.id,
                    name=screenshot_name,
                    description=screenshot.description or f"Captured Azure error state for {variant.label}.",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(screenshot.data),
                    storage_path=storage_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=failure_time,
                )
            )

        if failure.html:
            error_html_name = _prefixed_name(variant, "azure_error.html", multi_role)
            html_bytes = failure.html.encode("utf-8", errors="replace")
            html_path = storage.save_bytes(run.id, error_html_name, html_bytes)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, "AZURE-ERR-HTML", multi_role),
                    run_id=run.id,
                    name=error_html_name,
                    description=f"Captured HTML during Azure authentication failure for {variant.label}.",
                    type=ArtifactType.html.value,
                    size_bytes=len(html_bytes),
                    storage_path=html_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=failure_time,
                )
            )
            result.post_auth_html = failure.html

        result.error = failure.message
        result.pre_auth_html = failure.html or result.pre_auth_html
        result.completed_at = failure_time
    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("Azure AD automation failed for run %s", run.id)
        record(f"Azure authentication automation failed: {exc}")
        result.error = str(exc)
        result.completed_at = datetime.now(timezone.utc)

    return result


def _run_saml_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    headless: bool = True,
) -> VariantResult:
    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))

    try:
        record("Detected SAML 2.0 authentication; launching headless browser.")
        automation = run_saml_login(
            run.target_url,
            variant.username or "",
            variant.password or "",
            domain_prefix=domain_prefix,
            headless=headless
        )
        for message in not_yet_written(automation.events):
            record(message)

        finish = datetime.now(timezone.utc)
        side_bytes = build_side_file(run.target_url, automation, variant.username or "", variant.password or "")
        # Plaintext credentials stay inside the .side (Tenable needs them);
        # ArtifactStorage encrypts the whole file at rest with the owner's key.
        encrypted_side_bytes = side_bytes
        side_is_encrypted = True

        side_name = _prefixed_name(variant, f"login_{finish.strftime('%Y%m%d_%H%M%S')}.side", multi_role)
        side_path = storage.save_bytes(run.id, side_name, encrypted_side_bytes)
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "SIDE", multi_role),
                run_id=run.id,
                name=side_name,
                description=f"Selenium IDE (.side) automation script generated from captured SAML login flow for {variant.label}.",
                type=ArtifactType.side_file.value,
                size_bytes=len(encrypted_side_bytes),
                storage_path=side_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
                is_encrypted=side_is_encrypted,
            )
        )
        record("Generated Selenium IDE .side file.")

        # Generate export artifacts for security testing tools
        export_artifacts = _generate_export_artifacts(
            run, variant, automation, storage, finish, multi_role, record
        )
        result.artifacts.extend(export_artifacts)

        for index, screenshot in enumerate(automation.screenshots, start=1):
            screenshot_name = _prefixed_name(variant, screenshot.file_name, multi_role)
            storage_path = storage.save_bytes(run.id, screenshot_name, screenshot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"SAML-{index:02d}", multi_role),
                    run_id=run.id,
                    name=screenshot_name,
                    description=screenshot.description or f"Captured during SAML automation for {variant.label}.",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(screenshot.data),
                    storage_path=storage_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                )
            )

        result.success = True
        result.final_url = automation.final_url or run.target_url
        result.pattern = automation.pattern
        result.llm_pattern = None
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = automation.pre_auth_html
        result.post_auth_html = automation.post_auth_html
        result.completed_at = finish

        # Multi-engine support: Run Playwright if selected
        engines = run.options.get("engines", ["selenium"]) if isinstance(run.options, dict) else ["selenium"]
        if "playwright" in engines:
            try:
                import asyncio
                from app.services.automation.patterns.playwright.saml_login import attempt_saml_login_playwright
                time.sleep(2)
                record("Running Playwright engine for SAML HAR capture...")
                playwright_result = asyncio.run(attempt_saml_login_playwright(
                    run_id=f"{run.id}-playwright", target_url=run.target_url,
                    username=variant.username, password=variant.password,
                    timeout_seconds=45, domain_prefix=domain_prefix
                ))
                if playwright_result.success and playwright_result.har_bytes:
                    pw_har_name = _prefixed_name(variant, "playwright-network.har", multi_role)
                    pw_har_path = storage.save_bytes(run.id, pw_har_name, playwright_result.har_bytes)
                    result.artifacts.append(Artifact(
                        id=_artifact_id(run.id, variant, "PW-SAML-HAR", multi_role), run_id=run.id,
                        name=pw_har_name, description=f"Playwright HAR for SAML flow ({variant.label}).",
                        type=ArtifactType.har.value, size_bytes=len(playwright_result.har_bytes),
                        storage_path=pw_har_path, download_url=None, role_slug=variant.slug,
                        created_at=datetime.now(timezone.utc),
                    ))
                    record(f"Playwright HAR captured ({len(playwright_result.har_bytes)} bytes)")

                    # Scan for JavaScript secrets (pre-auth)
                    try:
                        from app.services.js_secret_scanner import scan_javascript_secrets
                        js_secrets = scan_javascript_secrets(playwright_result.har_bytes, pre_auth=True)
                        if js_secrets:
                            record(f"⚠️ Found {len(js_secrets)} secret(s) in JavaScript files (pre-auth)")
                            # Add to security context
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["js_secrets"] = js_secrets
                            # Log critical findings
                            for secret in js_secrets:
                                if secret.get("severity") == "CRITICAL":
                                    record(f"🔴 CRITICAL: {secret.get('type')} found in {secret.get('file')}:{secret.get('line')}")
                        else:
                            record("✅ No secrets detected in JavaScript files")
                    except Exception as e:
                        record(f"JS secret scanner failed: {str(e)}")

                    # Analyze HAR for authentication intelligence
                    try:
                        from app.services.har_analyzer import analyze_har
                        har_insight = analyze_har(playwright_result.har_bytes)
                        if har_insight:
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["har_insights"] = {
                                "login_endpoints": har_insight.login_endpoints,
                                "api_endpoints": har_insight.api_endpoints[:10],  # Limit to first 10
                                "has_api_auth": har_insight.has_api_auth,
                                "has_multi_step": har_insight.has_multi_step,
                                "total_requests": har_insight.total_requests,
                                "auth_related_requests": har_insight.auth_related_requests,
                            }
                            record(f"HAR analysis: {har_insight.total_requests} requests, {har_insight.auth_related_requests} auth-related")
                            if har_insight.has_api_auth:
                                record("  └─ API-first authentication flow detected")
                            if har_insight.has_multi_step:
                                record("  └─ Multi-step authentication detected")
                    except Exception as e:
                        record(f"HAR analysis failed: {str(e)}")
                    for pw_index, pw_screenshot in enumerate(playwright_result.screenshots, start=1):
                        pw_screenshot_name = _prefixed_name(variant, f"playwright-{pw_screenshot.file_name}", multi_role)
                        pw_screenshot_path = storage.save_bytes(run.id, pw_screenshot_name, pw_screenshot.data)
                        result.artifacts.append(Artifact(
                            id=_artifact_id(run.id, variant, f"PW-SAML-{pw_index:02d}", multi_role), run_id=run.id,
                            name=pw_screenshot_name, description=pw_screenshot.description,
                            type=ArtifactType.screenshot.value, size_bytes=len(pw_screenshot.data),
                            storage_path=pw_screenshot_path, download_url=None, role_slug=variant.slug,
                            created_at=datetime.now(timezone.utc),
                        ))
                    record(f"Saved {len(playwright_result.screenshots)} Playwright screenshots")
            except Exception as e:
                record(f"Playwright engine failed: {str(e)}")

    except AutomationFailure as failure:
        logger.warning("SAML authentication failed for run %s: %s", run.id, failure)
        failure_time = datetime.now(timezone.utc)
        for message in not_yet_written(failure.events):
            record(message)
        record("SAML authentication automation failed.")

        for index, screenshot in enumerate(failure.screenshots, start=1):
            screenshot_name = _prefixed_name(variant, screenshot.file_name, multi_role)
            storage_path = storage.save_bytes(run.id, screenshot_name, screenshot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"SAML-ERR-{index:02d}", multi_role),
                    run_id=run.id,
                    name=screenshot_name,
                    description=screenshot.description or f"Captured SAML error state for {variant.label}.",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(screenshot.data),
                    storage_path=storage_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=failure_time,
                )
            )

        if failure.html:
            error_html_name = _prefixed_name(variant, "saml_error.html", multi_role)
            html_bytes = failure.html.encode("utf-8", errors="replace")
            html_path = storage.save_bytes(run.id, error_html_name, html_bytes)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, "SAML-ERR-HTML", multi_role),
                    run_id=run.id,
                    name=error_html_name,
                    description=f"Captured HTML during SAML authentication failure for {variant.label}.",
                    type=ArtifactType.html.value,
                    size_bytes=len(html_bytes),
                    storage_path=html_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=failure_time,
                )
            )
            result.post_auth_html = failure.html

        result.error = failure.message
        result.pre_auth_html = failure.html or result.pre_auth_html
        result.completed_at = failure_time
    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("SAML authentication failed for run %s", run.id)
        record(f"SAML authentication automation failed: {exc}")
        result.error = str(exc)
        result.completed_at = datetime.now(timezone.utc)

    return result


def _run_okta_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    headless: bool = True,
) -> VariantResult:
    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))

    try:
        record("Detected Okta authentication; launching headless browser.")
        automation = run_okta_login(
            run.target_url,
            variant.username or "",
            variant.password or "",
            headless=headless,
            login_hint=login_hint,
            domain_prefix=domain_prefix
        )
        for message in not_yet_written(automation.events):
            record(message)

        finish = datetime.now(timezone.utc)
        side_bytes = build_side_file(run.target_url, automation, variant.username or "", variant.password or "")
        # Plaintext credentials stay inside the .side (Tenable needs them);
        # ArtifactStorage encrypts the whole file at rest with the owner's key.
        encrypted_side_bytes = side_bytes
        side_is_encrypted = True

        side_name = _prefixed_name(variant, f"login_{finish.strftime('%Y%m%d_%H%M%S')}.side", multi_role)
        side_path = storage.save_bytes(run.id, side_name, encrypted_side_bytes)
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "OKTA-SIDE", multi_role),
                run_id=run.id,
                name=side_name,
                description=f"[{variant.label}] Selenium IDE side file",
                type=ArtifactType.side_file.value,
                size_bytes=len(encrypted_side_bytes),
                storage_path=side_path,
                download_url=None,
                is_encrypted=side_is_encrypted,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        # Save Burp Suite export
        from app.services.exports.burp import export_to_burp_xml
        burp_xml = export_to_burp_xml(run.target_url, automation)
        burp_name = _prefixed_name(variant, f"burp_export_{finish.strftime('%Y%m%d_%H%M%S')}.xml", multi_role)
        burp_path = storage.save_bytes(run.id, burp_name, burp_xml.encode("utf-8"))
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "OKTA-BURP", multi_role),
                run_id=run.id,
                name=burp_name,
                description=f"[{variant.label}] Burp Suite XML export",
                type=ArtifactType.burp_export.value,
                size_bytes=len(burp_xml.encode("utf-8")),
                storage_path=burp_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        # Save curl command export
        from app.services.exports.curl import export_to_curl
        curl_script = export_to_curl(run.target_url, automation)
        curl_name = _prefixed_name(variant, f"curl_commands_{finish.strftime('%Y%m%d_%H%M%S')}.sh", multi_role)
        curl_path = storage.save_bytes(run.id, curl_name, curl_script.encode("utf-8"))
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "OKTA-CURL", multi_role),
                run_id=run.id,
                name=curl_name,
                description=f"[{variant.label}] curl commands export",
                type=ArtifactType.curl_export.value,
                size_bytes=len(curl_script.encode("utf-8")),
                storage_path=curl_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        # Save Postman collection export
        from app.services.exports.postman import export_to_postman_collection
        postman_json = export_to_postman_collection(run.target_url, automation)
        postman_name = _prefixed_name(variant, f"postman_collection_{finish.strftime('%Y%m%d_%H%M%S')}.json", multi_role)
        postman_path = storage.save_bytes(run.id, postman_name, postman_json.encode("utf-8"))
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "OKTA-POSTMAN", multi_role),
                run_id=run.id,
                name=postman_name,
                description=f"[{variant.label}] Postman collection export",
                type=ArtifactType.postman_export.value,
                size_bytes=len(postman_json.encode("utf-8")),
                storage_path=postman_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        # Save OWASP ZAP export
        from app.services.exports.zap import export_to_zap_yaml
        zap_yaml = export_to_zap_yaml(run.target_url, automation)
        zap_name = _prefixed_name(variant, f"zap_automation_{finish.strftime('%Y%m%d_%H%M%S')}.yaml", multi_role)
        zap_path = storage.save_bytes(run.id, zap_name, zap_yaml.encode("utf-8"))
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "OKTA-ZAP", multi_role),
                run_id=run.id,
                name=zap_name,
                description=f"[{variant.label}] OWASP ZAP automation framework export",
                type=ArtifactType.zap_export.value,
                size_bytes=len(zap_yaml.encode("utf-8")),
                storage_path=zap_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        for idx, sc in enumerate(automation.screenshots, start=1):
            desc = sc.description or f"[{variant.label}] Step {idx} screenshot"
            shot_name = _prefixed_name(variant, sc.file_name, multi_role)
            shot_path = storage.save_bytes(run.id, shot_name, sc.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"OKTA-SHOT-{idx}", multi_role),
                    run_id=run.id,
                    name=shot_name,
                    description=desc,
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(sc.data),
                    storage_path=shot_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                )
            )

        # Multi-engine support: Run Playwright if selected
        engines = run.options.get("engines", ["selenium"]) if isinstance(run.options, dict) else ["selenium"]
        if "playwright" in engines:
            try:
                import asyncio
                from app.services.automation.patterns.playwright.okta_login import attempt_okta_login_playwright
                time.sleep(2)
                record("Running Playwright engine for Okta HAR capture...")
                playwright_result = asyncio.run(attempt_okta_login_playwright(
                    run_id=f"{run.id}-playwright", target_url=run.target_url,
                    username=variant.username, password=variant.password,
                    timeout_seconds=60
                ))
                if playwright_result.success and playwright_result.har_bytes:
                    pw_har_name = _prefixed_name(variant, "playwright-network.har", multi_role)
                    pw_har_path = storage.save_bytes(run.id, pw_har_name, playwright_result.har_bytes)
                    result.artifacts.append(Artifact(
                        id=_artifact_id(run.id, variant, "PW-OKTA-HAR", multi_role), run_id=run.id,
                        name=pw_har_name, description=f"Playwright HAR for Okta flow ({variant.label}).",
                        type=ArtifactType.har.value, size_bytes=len(playwright_result.har_bytes),
                        storage_path=pw_har_path, download_url=None, role_slug=variant.slug,
                        created_at=datetime.now(timezone.utc),
                    ))
                    record(f"Playwright HAR captured ({len(playwright_result.har_bytes)} bytes)")

                    # Scan for JavaScript secrets (pre-auth)
                    try:
                        from app.services.js_secret_scanner import scan_javascript_secrets
                        js_secrets = scan_javascript_secrets(playwright_result.har_bytes, pre_auth=True)
                        if js_secrets:
                            record(f"⚠️ Found {len(js_secrets)} secret(s) in JavaScript files (pre-auth)")
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["js_secrets"] = js_secrets
                            for secret in js_secrets:
                                if secret.get("severity") == "CRITICAL":
                                    record(f"🔴 CRITICAL: {secret.get('type')} found in {secret.get('file')}:{secret.get('line')}")
                        else:
                            record("✅ No secrets detected in JavaScript files")
                    except Exception as e:
                        record(f"JS secret scanner failed: {str(e)}")

                    # Analyze HAR for authentication intelligence
                    try:
                        from app.services.har_analyzer import analyze_har
                        har_insight = analyze_har(playwright_result.har_bytes)
                        if har_insight:
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["har_insights"] = {
                                "login_endpoints": har_insight.login_endpoints,
                                "api_endpoints": har_insight.api_endpoints[:10],  # Limit to first 10
                                "has_api_auth": har_insight.has_api_auth,
                                "has_multi_step": har_insight.has_multi_step,
                                "total_requests": har_insight.total_requests,
                                "auth_related_requests": har_insight.auth_related_requests,
                            }
                            record(f"HAR analysis: {har_insight.total_requests} requests, {har_insight.auth_related_requests} auth-related")
                            if har_insight.has_api_auth:
                                record("  └─ API-first authentication flow detected")
                            if har_insight.has_multi_step:
                                record("  └─ Multi-step authentication detected")
                    except Exception as e:
                        record(f"HAR analysis failed: {str(e)}")
                    for pw_index, pw_screenshot in enumerate(playwright_result.screenshots, start=1):
                        pw_screenshot_name = _prefixed_name(variant, f"playwright-{pw_screenshot.file_name}", multi_role)
                        pw_screenshot_path = storage.save_bytes(run.id, pw_screenshot_name, pw_screenshot.data)
                        result.artifacts.append(Artifact(
                            id=_artifact_id(run.id, variant, f"PW-OKTA-{pw_index:02d}", multi_role), run_id=run.id,
                            name=pw_screenshot_name, description=pw_screenshot.description,
                            type=ArtifactType.screenshot.value, size_bytes=len(pw_screenshot.data),
                            storage_path=pw_screenshot_path, download_url=None, role_slug=variant.slug,
                            created_at=datetime.now(timezone.utc),
                        ))
                    record(f"Saved {len(playwright_result.screenshots)} Playwright screenshots")
            except Exception as e:
                record(f"Playwright engine failed: {str(e)}")

        result.success = True
        result.final_url = automation.final_url or run.target_url
        result.pattern = automation.heading or automation.success_message or automation.page_title
        result.llm_pattern = None
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = automation.pre_auth_html or ""
        result.post_auth_html = automation.post_auth_html or ""
        result.completed_at = finish
    except AutomationFailure as failure:
        failure_time = datetime.now(timezone.utc)
        record(f"Okta automation terminated with error: {failure.message}")

        if failure.screenshots:
            for idx, sc in enumerate(failure.screenshots, start=1):
                desc = sc.description or f"[{variant.label}] Failure screenshot {idx}"
                shot_name = _prefixed_name(variant, sc.file_name, multi_role)
                shot_path = storage.save_bytes(run.id, shot_name, sc.data)
                result.artifacts.append(
                    Artifact(
                        id=_artifact_id(run.id, variant, f"OKTA-FAIL-{idx}", multi_role),
                        run_id=run.id,
                        name=shot_name,
                        description=desc,
                        type=ArtifactType.screenshot.value,
                        size_bytes=len(sc.data),
                        storage_path=shot_path,
                        download_url=None,
                        role_slug=variant.slug,
                        created_at=failure_time,
                    )
                )
            result.post_auth_html = failure.html

        result.error = failure.message
        result.pre_auth_html = failure.html or result.pre_auth_html
        result.completed_at = failure_time
    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("Okta automation failed for run %s", run.id)
        record(f"Okta authentication automation failed: {exc}")
        result.error = str(exc)
        result.completed_at = datetime.now(timezone.utc)

    return result


def _run_ldap_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    headless: bool = True,
) -> VariantResult:
    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))

    options = run.options if isinstance(run.options, dict) else {}
    forced_auth_type = ""
    detected_auth_type = None
    detected_confidence = 0
    if isinstance(options, dict):
        forced_auth_type = str(options.get("forced_auth_type") or "").strip().lower()
        detected_auth = options.get("detected_auth")
        if isinstance(detected_auth, dict):
            detected_auth_type = str(detected_auth.get("auth_type") or "").strip().lower() or None
            try:
                detected_confidence = int(detected_auth.get("confidence") or 0)
            except Exception:
                detected_confidence = 0

    def _should_downshift(message: str | None) -> bool:
        if forced_auth_type:
            return False
        msg = (message or "").lower()
        triggers = (
            "did not expose a username field",
            "did not expose a password field",
            "unable to locate a username/email field",
            "unable to locate a username field",
            "connection refused",
        )
        return any(trigger in msg for trigger in triggers)

    def _fallback_to_form(reason: str) -> VariantResult | None:
        if forced_auth_type:
            return None
        record(reason)
        return _run_form_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix)

    if (
        not forced_auth_type
        and detected_auth_type in {"form_based", "form_post", "form_auth", "two_step_form"}
        and detected_confidence >= 60
    ):
        record(f"Detection suggested {detected_auth_type.replace('_', ' ')}; routing to form-based automation instead of LDAP/ADFS.")
        return _run_form_variant(run, variant, storage, db, multi_role, login_hint, domain_prefix, headless)

    try:
        record("Detected LDAP/ADFS authentication; launching headless browser.")
        automation = run_ldap_login(
            run.target_url,
            variant.username or "",
            variant.password or "",
            login_hint=login_hint,
            domain_prefix=domain_prefix,
            headless=headless
        )
        for message in not_yet_written(automation.events):
            record(message)

        finish = datetime.now(timezone.utc)

        # Generate all export artifacts (Burp, curl, Postman, ZAP, etc.)
        export_artifacts = _generate_export_artifacts(
            run, variant, automation, storage, finish, multi_role, record
        )
        result.artifacts.extend(export_artifacts)

        side_bytes = build_side_file(run.target_url, automation, variant.username or "", variant.password or "")
        # Plaintext credentials stay inside the .side (Tenable needs them);
        # ArtifactStorage encrypts the whole file at rest with the owner's key.
        encrypted_side_bytes = side_bytes
        side_is_encrypted = True

        side_name = _prefixed_name(variant, f"login_{finish.strftime('%Y%m%d_%H%M%S')}.side", multi_role)
        side_path = storage.save_bytes(run.id, side_name, encrypted_side_bytes)
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "LDAP-SIDE", multi_role),
                run_id=run.id,
                name=side_name,
                description=f"[{variant.label}] Selenium IDE side file",
                type=ArtifactType.side_file.value,
                size_bytes=len(encrypted_side_bytes),
                storage_path=side_path,
                download_url=None,
                is_encrypted=side_is_encrypted,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        for index, shot in enumerate(automation.screenshots or [], start=1):
            shot_name = _prefixed_name(variant, shot.file_name or f"screenshot_{index}.png", multi_role)
            shot_path = storage.save_bytes(run.id, shot_name, shot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"LDAP-SHOT-{index:02d}", multi_role),
                    run_id=run.id,
                    name=shot_name,
                    description=shot.description or f"[{variant.label}] Screenshot {index}",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(shot.data),
                    storage_path=shot_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                )
        )

        result.success = True
        result.final_url = automation.final_url
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = automation.pre_auth_html
        result.post_auth_html = automation.post_auth_html
        result.completed_at = finish
        record("LDAP/ADFS authentication succeeded.")

        # Multi-engine support: Run Playwright if selected
        engines = run.options.get("engines", ["selenium"]) if isinstance(run.options, dict) else ["selenium"]

        if "playwright" in engines:
            try:
                import asyncio
                from app.services.automation.patterns.playwright.ldap_login import attempt_ldap_login_playwright

                # Stagger delay to avoid session conflicts
                time.sleep(2)
                record("Running Playwright engine for LDAP/ADFS HAR capture...")

                playwright_result = asyncio.run(attempt_ldap_login_playwright(
                    run_id=f"{run.id}-playwright",
                    target_url=run.target_url,
                    username=variant.username,
                    password=variant.password,
                    timeout_seconds=45,
                    login_hint=login_hint,
                    domain_prefix=domain_prefix
                ))

                if playwright_result.success and playwright_result.har_bytes:
                    # Save Playwright HAR file
                    pw_har_name = _prefixed_name(variant, "playwright-network.har", multi_role)
                    pw_har_path = storage.save_bytes(run.id, pw_har_name, playwright_result.har_bytes)
                    result.artifacts.append(
                        Artifact(
                            id=_artifact_id(run.id, variant, "PW-LDAP-HAR", multi_role),
                            run_id=run.id,
                            name=pw_har_name,
                            description=f"Complete HAR file captured via Playwright for LDAP/ADFS auth ({variant.label}).",
                            type=ArtifactType.har.value,
                            size_bytes=len(playwright_result.har_bytes),
                            storage_path=pw_har_path,
                            download_url=None,
                            role_slug=variant.slug,
                            created_at=datetime.now(timezone.utc),
                        )
                    )
                    record(f"Playwright HAR captured ({len(playwright_result.har_bytes)} bytes)")

                    # Scan for JavaScript secrets (pre-auth)
                    try:
                        from app.services.js_secret_scanner import scan_javascript_secrets
                        js_secrets = scan_javascript_secrets(playwright_result.har_bytes, pre_auth=True)
                        if js_secrets:
                            record(f"⚠️ Found {len(js_secrets)} secret(s) in JavaScript files (pre-auth)")
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["js_secrets"] = js_secrets
                            for secret in js_secrets:
                                if secret.get("severity") == "CRITICAL":
                                    record(f"🔴 CRITICAL: {secret.get('type')} found in {secret.get('file')}:{secret.get('line')}")
                        else:
                            record("✅ No secrets detected in JavaScript files")
                    except Exception as e:
                        record(f"JS secret scanner failed: {str(e)}")

                    # Analyze HAR for authentication intelligence
                    try:
                        from app.services.har_analyzer import analyze_har
                        har_insight = analyze_har(playwright_result.har_bytes)
                        if har_insight:
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["har_insights"] = {
                                "login_endpoints": har_insight.login_endpoints,
                                "api_endpoints": har_insight.api_endpoints[:10],  # Limit to first 10
                                "has_api_auth": har_insight.has_api_auth,
                                "has_multi_step": har_insight.has_multi_step,
                                "total_requests": har_insight.total_requests,
                                "auth_related_requests": har_insight.auth_related_requests,
                            }
                            record(f"HAR analysis: {har_insight.total_requests} requests, {har_insight.auth_related_requests} auth-related")
                            if har_insight.has_api_auth:
                                record("  └─ API-first authentication flow detected")
                            if har_insight.has_multi_step:
                                record("  └─ Multi-step authentication detected")
                    except Exception as e:
                        record(f"HAR analysis failed: {str(e)}")

                    # Save Playwright screenshots
                    for pw_index, pw_screenshot in enumerate(playwright_result.screenshots, start=1):
                        pw_screenshot_name = _prefixed_name(variant, f"playwright-{pw_screenshot.file_name}", multi_role)
                        pw_screenshot_path = storage.save_bytes(run.id, pw_screenshot_name, pw_screenshot.data)
                        result.artifacts.append(
                            Artifact(
                                id=_artifact_id(run.id, variant, f"PW-LDAP-{pw_index:02d}", multi_role),
                                run_id=run.id,
                                name=pw_screenshot_name,
                                description=pw_screenshot.description,
                                type=ArtifactType.screenshot.value,
                                size_bytes=len(pw_screenshot.data),
                                storage_path=pw_screenshot_path,
                                download_url=None,
                                role_slug=variant.slug,
                                created_at=datetime.now(timezone.utc),
                            )
                        )
                    record(f"Saved {len(playwright_result.screenshots)} Playwright screenshots")
                else:
                    record("Playwright engine completed but authentication may have failed")

            except Exception as e:
                record(f"Playwright engine failed: {str(e)}")
                # Don't fail entire run if Playwright fails

    except AutomationFailure as failure:
        failure_time = datetime.now(timezone.utc)
        record(f"LDAP/ADFS authentication failed: {failure.message}")

        if failure.screenshots:
            for index, shot in enumerate(failure.screenshots, start=1):
                shot_name = _prefixed_name(variant, f"failure_screenshot_{index}.png", multi_role)
                shot_path = storage.save_bytes(run.id, shot_name, shot.data)
                result.artifacts.append(
                    Artifact(
                        id=_artifact_id(run.id, variant, f"LDAP-FAIL-{index:02d}", multi_role),
                        run_id=run.id,
                        name=shot_name,
                        description=f"[{variant.label}] Failure screenshot {index}",
                        type=ArtifactType.screenshot.value,
                        size_bytes=len(shot.data),
                        storage_path=shot_path,
                        download_url=None,
                        role_slug=variant.slug,
                        created_at=failure_time,
                    )
            )
            result.post_auth_html = failure.html

        result.error = failure.message
        result.pre_auth_html = failure.html or result.pre_auth_html
        result.completed_at = failure_time
        fallback = _fallback_to_form("LDAP indicators missing or unresponsive; retrying as form-based login.") if _should_downshift(failure.message) else None
        if fallback:
            return fallback
    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("LDAP/ADFS automation failed for run %s", run.id)
        record(f"LDAP/ADFS authentication automation failed: {exc}")
        # Fallback: if LDAP selectors were missing, try form-based variant
        result.error = str(exc)
        result.completed_at = datetime.now(timezone.utc)
        fallback = _fallback_to_form("LDAP indicators not present; retrying as form-based login.") if _should_downshift(str(exc)) else None
        if fallback:
            return fallback

    return result


def _run_oauth_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    headless: bool = True,
) -> VariantResult:
    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))

    try:
        record("Detected OAuth 2.0 / OIDC authentication; launching headless browser.")
        automation = run_oauth_login(
            run.target_url,
            variant.username or "",
            variant.password or "",
            login_hint=login_hint,
            domain_prefix=domain_prefix,
            headless=headless
        )
        for message in not_yet_written(automation.events):
            record(message)

        finish = datetime.now(timezone.utc)

        # Generate all export artifacts (Burp, curl, Postman, ZAP, etc.)
        export_artifacts = _generate_export_artifacts(
            run, variant, automation, storage, finish, multi_role, record
        )
        result.artifacts.extend(export_artifacts)

        side_bytes = build_side_file(run.target_url, automation, variant.username or "", variant.password or "")
        # Plaintext credentials stay inside the .side (Tenable needs them);
        # ArtifactStorage encrypts the whole file at rest with the owner's key.
        encrypted_side_bytes = side_bytes
        side_is_encrypted = True

        side_name = _prefixed_name(variant, f"login_{finish.strftime('%Y%m%d_%H%M%S')}.side", multi_role)
        side_path = storage.save_bytes(run.id, side_name, encrypted_side_bytes)
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "OAUTH-SIDE", multi_role),
                run_id=run.id,
                name=side_name,
                description=f"[{variant.label}] Selenium IDE side file",
                type=ArtifactType.side_file.value,
                size_bytes=len(encrypted_side_bytes),
                storage_path=side_path,
                download_url=None,
                is_encrypted=side_is_encrypted,
                role_slug=variant.slug,
                created_at=finish,
            )
        )

        for index, shot in enumerate(automation.screenshots or [], start=1):
            shot_name = _prefixed_name(variant, shot.file_name or f"screenshot_{index}.png", multi_role)
            shot_path = storage.save_bytes(run.id, shot_name, shot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"OAUTH-SHOT-{index:02d}", multi_role),
                    run_id=run.id,
                    name=shot_name,
                    description=shot.description or f"[{variant.label}] Screenshot {index}",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(shot.data),
                    storage_path=shot_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                )
        )

        # Multi-engine support: Run Playwright if selected
        engines = run.options.get("engines", ["selenium"]) if isinstance(run.options, dict) else ["selenium"]
        if "playwright" in engines:
            try:
                import asyncio
                from app.services.automation.patterns.playwright.oauth_login import attempt_oauth_login_playwright
                time.sleep(2)
                record("Running Playwright engine for OAuth HAR capture...")
                playwright_result = asyncio.run(attempt_oauth_login_playwright(
                    run_id=f"{run.id}-playwright", target_url=run.target_url,
                    username=variant.username, password=variant.password,
                    timeout_seconds=60, login_hint=login_hint, domain_prefix=domain_prefix
                ))
                if playwright_result.success and playwright_result.har_bytes:
                    pw_har_name = _prefixed_name(variant, "playwright-network.har", multi_role)
                    pw_har_path = storage.save_bytes(run.id, pw_har_name, playwright_result.har_bytes)
                    result.artifacts.append(Artifact(
                        id=_artifact_id(run.id, variant, "PW-OAUTH-HAR", multi_role), run_id=run.id,
                        name=pw_har_name, description=f"Playwright HAR for OAuth flow ({variant.label}).",
                        type=ArtifactType.har.value, size_bytes=len(playwright_result.har_bytes),
                        storage_path=pw_har_path, download_url=None, role_slug=variant.slug,
                        created_at=datetime.now(timezone.utc),
                    ))
                    record(f"Playwright HAR captured ({len(playwright_result.har_bytes)} bytes)")

                    # Scan for JavaScript secrets (pre-auth)
                    try:
                        from app.services.js_secret_scanner import scan_javascript_secrets
                        js_secrets = scan_javascript_secrets(playwright_result.har_bytes, pre_auth=True)
                        if js_secrets:
                            record(f"⚠️ Found {len(js_secrets)} secret(s) in JavaScript files (pre-auth)")
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["js_secrets"] = js_secrets
                            for secret in js_secrets:
                                if secret.get("severity") == "CRITICAL":
                                    record(f"🔴 CRITICAL: {secret.get('type')} found in {secret.get('file')}:{secret.get('line')}")
                        else:
                            record("✅ No secrets detected in JavaScript files")
                    except Exception as e:
                        record(f"JS secret scanner failed: {str(e)}")

                    # Analyze HAR for authentication intelligence
                    try:
                        from app.services.har_analyzer import analyze_har
                        har_insight = analyze_har(playwright_result.har_bytes)
                        if har_insight:
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["har_insights"] = {
                                "login_endpoints": har_insight.login_endpoints,
                                "api_endpoints": har_insight.api_endpoints[:10],  # Limit to first 10
                                "has_api_auth": har_insight.has_api_auth,
                                "has_multi_step": har_insight.has_multi_step,
                                "total_requests": har_insight.total_requests,
                                "auth_related_requests": har_insight.auth_related_requests,
                            }
                            record(f"HAR analysis: {har_insight.total_requests} requests, {har_insight.auth_related_requests} auth-related")
                            if har_insight.has_api_auth:
                                record("  └─ API-first authentication flow detected")
                            if har_insight.has_multi_step:
                                record("  └─ Multi-step authentication detected")
                    except Exception as e:
                        record(f"HAR analysis failed: {str(e)}")

                    for pw_index, pw_screenshot in enumerate(playwright_result.screenshots, start=1):
                        pw_screenshot_name = _prefixed_name(variant, f"playwright-{pw_screenshot.file_name}", multi_role)
                        pw_screenshot_path = storage.save_bytes(run.id, pw_screenshot_name, pw_screenshot.data)
                        result.artifacts.append(Artifact(
                            id=_artifact_id(run.id, variant, f"PW-OAUTH-{pw_index:02d}", multi_role), run_id=run.id,
                            name=pw_screenshot_name, description=pw_screenshot.description,
                            type=ArtifactType.screenshot.value, size_bytes=len(pw_screenshot.data),
                            storage_path=pw_screenshot_path, download_url=None, role_slug=variant.slug,
                            created_at=datetime.now(timezone.utc),
                        ))
                    record(f"Saved {len(playwright_result.screenshots)} Playwright screenshots")
            except Exception as e:
                record(f"Playwright engine failed: {str(e)}")

        result.success = True
        result.pattern = automation.pattern  # real text from the landed page
        result.final_url = automation.final_url
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = automation.pre_auth_html
        result.post_auth_html = automation.post_auth_html
        result.completed_at = finish
        record("OAuth 2.0 authentication succeeded.")

    except AutomationFailure as failure:
        failure_time = datetime.now(timezone.utc)
        record(f"OAuth 2.0 authentication failed: {failure.message}")

        if failure.screenshots:
            for index, shot in enumerate(failure.screenshots, start=1):
                shot_name = _prefixed_name(variant, f"failure_screenshot_{index}.png", multi_role)
                shot_path = storage.save_bytes(run.id, shot_name, shot.data)
                result.artifacts.append(
                    Artifact(
                        id=_artifact_id(run.id, variant, f"OAUTH-FAIL-{index:02d}", multi_role),
                        run_id=run.id,
                        name=shot_name,
                        description=f"[{variant.label}] Failure screenshot {index}",
                        type=ArtifactType.screenshot.value,
                        size_bytes=len(shot.data),
                        storage_path=shot_path,
                        download_url=None,
                        role_slug=variant.slug,
                        created_at=failure_time,
                    )
                )
            result.post_auth_html = failure.html

        result.error = failure.message
        result.pre_auth_html = failure.html or result.pre_auth_html
        result.completed_at = failure_time
    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("OAuth 2.0 automation failed for run %s", run.id)
        record(f"OAuth 2.0 authentication automation failed: {exc}")
        result.error = str(exc)
        result.completed_at = datetime.now(timezone.utc)

    return result


def _get_latest_ai_suggestion(run: Run) -> dict | None:
    """
    The most recent AI-recorded selector suggestion for this run (see
    app/api/ai_assist.py, POST /runs/{id}/ai-suggestion), or None if there
    isn't one. Raw dict as recorded — auth_type, selectors, confidence,
    reasoning, submitted_at, submitted_by_profile_id.
    """
    options = run.options or {}
    suggestions = options.get("ai_suggestions") or []
    return suggestions[-1] if suggestions else None


def _build_ai_selector_override(run: Run) -> dict | None:
    """
    Convert the most recent AI-recorded suggestion into the same dict shape
    run_form_login()'s playbook_selectors parameter already expects.
    Returns None if there's no suggestion, or it's missing the minimum
    fields needed (a password selector) to be worth trying.

    This never touches a credential value — it only carries selector
    strings and metadata the suggesting model provided. See
    SECURITY.md for why that model never sees or provides one.
    """
    latest = _get_latest_ai_suggestion(run)
    if not latest or not latest.get("password_selector"):
        return None

    return {
        "username_selector": latest.get("username_selector"),
        "password_selector": latest.get("password_selector"),
        "submit_selector": latest.get("submit_selector"),
        "is_generic": False,
    }


def _run_form_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    headless: bool = True,
    llm_allowed: bool = False,
) -> VariantResult:
    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))
    max_attempts = 3
    last_error: Exception | None = None
    used_ai_selectors = False  # surfaced via result.llm_pattern on success — see DetectionEvidence.jsx

    # Phase 4: Check for existing playbook (historical learning)
    playbook = None
    playbook_selectors = None
    try:
        from app.services.learning import lookup_playbook
        playbook = lookup_playbook(
            target_url=run.target_url,
            auth_type="form_based",
            db=db,
            profile_id=run.submitted_by_profile_id,
            min_confidence=70
        )
        if playbook and playbook.is_reliable(70):
            record(f"Found reliable playbook (confidence: {playbook.confidence_score}%, {playbook.success_count} successes)")
            playbook_selectors = playbook.selectors
        elif playbook:
            record(f"Found playbook but confidence too low ({playbook.confidence_score}%), using heuristic detection")
    except Exception as e:
        logger.warning(f"Failed to lookup playbook for run {run.id}: {e}", exc_info=True)

    for attempt in range(1, max_attempts + 1):
        try:
            record(f"Detected form-based authentication; attempt {attempt}/{max_attempts}.")
            automation = run_form_login(
                run.target_url,
                variant.username or "",
                variant.password or "",
                login_hint=login_hint,
                domain_prefix=domain_prefix,
                headless=headless,
                playbook_selectors=playbook_selectors  # Phase 4: Deterministic execution
            )
            last_error = None
            break
        except Exception as exc:
            last_error = exc
            logger.warning("Form auth attempt %s/%s failed for run %s: %s", attempt, max_attempts, run.id, exc)
            record(f"Attempt {attempt} failed: {str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__}")
            if playbook and playbook_selectors:
                # Count each attempt that used the playbook, so a timeout
                # followed by a successful retry isn't recorded as clean.
                try:
                    from app.services.learning import record_playbook_usage
                    record_playbook_usage(playbook, success=False, db=db)
                    record("Playbook usage recorded (failure)")
                except Exception as e:
                    logger.warning(f"Failed to record playbook usage for run {run.id}: {e}", exc_info=True)
            if isinstance(exc, CredentialRejected):
                # The site said the credentials are wrong. Resubmitting the same
                # ones only burns lockout attempts on the target account.
                record("The site rejected these credentials; not retrying (avoids account lockout).")
                break
            if attempt < max_attempts:
                time.sleep(2)
                continue
    else:
        # Heuristic detection and any existing playbook both failed. If AI
        # assistance is allowed for this run (llm_allowed) and someone has
        # already recorded a selector suggestion for it — via the MCP
        # get_stuck_run_context()/submit_login_suggestion() flow, see
        # SECURITY.md — try that as a last resort before giving up.
        # This is the same run_form_login()/playbook_selectors mechanism
        # the historical-learning playbook path already uses; the only
        # difference is where the selectors came from. The credential
        # value itself never changes hands here — variant.username/password
        # are already on this object, same as every other attempt above.
        ai_selectors = _build_ai_selector_override(run) if llm_allowed else None
        if ai_selectors:
            try:
                record("Heuristic detection and playbook exhausted; trying AI-suggested selectors.")
                automation = run_form_login(
                    run.target_url,
                    variant.username or "",
                    variant.password or "",
                    login_hint=login_hint,
                    domain_prefix=domain_prefix,
                    headless=headless,
                    playbook_selectors=ai_selectors,
                )
                last_error = None
                used_ai_selectors = True
                record("AI-suggested selectors succeeded.")
            except Exception as exc:
                last_error = exc
                logger.warning("AI-suggested selector attempt failed for run %s: %s", run.id, exc)
                record(f"AI-suggested selectors also failed: {exc}")

    if last_error is not None:
        record("Form authentication failed.")
        result.error = str(last_error) if last_error else "Unknown form auth failure"
        result.completed_at = datetime.now(timezone.utc)
        # The exceptions raised here (e.g. "unable to locate a password
        # field") don't carry captured HTML — they're plain RuntimeErrors,
        # not AutomationFailure. Without this, get_stuck_run_context()
        # would have nothing but the "could not be captured" placeholder
        # to show, which defeats the point of the AI-assist path this
        # failure is meant to feed. A plain HTTP fetch isn't identical to
        # what Selenium saw (no JS execution, no post-interaction state),
        # but for a page whose fields are present in the static HTML —
        # which is the case for the kind of pages this path exists to
        # help with — it's enough to work from.
        result.pre_auth_html = _fetch_pre_auth_html(run.target_url)

        return result

    try:
        for message in not_yet_written(automation.events):
            record(message)

        finish = datetime.now(timezone.utc)

        side_bytes = build_side_file(run.target_url, automation, variant.username or "", variant.password or "")
        # Plaintext credentials stay inside the .side (Tenable needs them);
        # ArtifactStorage encrypts the whole file at rest with the owner's key.
        encrypted_side_bytes = side_bytes
        side_is_encrypted = True
        side_name = _prefixed_name(variant, f"login_{finish.strftime('%Y%m%d_%H%M%S')}.side", multi_role)
        side_path = storage.save_bytes(run.id, side_name, encrypted_side_bytes)
        result.artifacts.append(
            Artifact(
                id=_artifact_id(run.id, variant, "SIDE", multi_role),
                run_id=run.id,
                name=side_name,
                description=f"Selenium IDE (.side) automation script generated from captured login flow for {variant.label}.",
                type=ArtifactType.side_file.value,
                size_bytes=len(encrypted_side_bytes),
                storage_path=side_path,
                download_url=None,
                role_slug=variant.slug,
                created_at=finish,
                is_encrypted=side_is_encrypted,
            )
        )
        record("Generated Selenium IDE .side file.")

        # Generate export artifacts for security testing tools
        export_artifacts = _generate_export_artifacts(
            run, variant, automation, storage, finish, multi_role, record
        )
        result.artifacts.extend(export_artifacts)

        har_entries = [
            {
                "url": run.target_url,
                "method": "GET",
                "status": 200,
                "statusText": "OK",
                "mimeType": "text/html",
                "bodySize": len((automation.pre_auth_html or "").encode("utf-8")),
                "time": 160,
                "title": f"{variant.label} login form",
            },
            {
                "url": run.target_url,
                "method": "POST",
                "status": 302,
                "statusText": "Redirect",
                "mimeType": "application/x-www-form-urlencoded",
                "bodySize": 0,
                "time": 210,
                "title": f"{variant.label} submit credentials",
            },
            {
                "url": automation.final_url or run.target_url,
                "method": "GET",
                "status": 200,
                "statusText": "OK",
                "mimeType": "text/html",
                "bodySize": len((automation.post_auth_html or "").encode("utf-8")),
                "time": 250,
                "title": f"{variant.label} authenticated landing page",
            },
        ]

        for index, screenshot in enumerate(automation.screenshots, start=1):
            screenshot_name = _prefixed_name(variant, screenshot.file_name, multi_role)
            storage_path = storage.save_bytes(run.id, screenshot_name, screenshot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"FORM-{index:02d}", multi_role),
                    run_id=run.id,
                    name=screenshot_name,
                    description=screenshot.description or f"Screenshot captured during form-based automation for {variant.label}.",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(screenshot.data),
                    storage_path=storage_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                )
            )

        result.success = True
        result.final_url = automation.final_url or run.target_url
        result.pattern = automation.pattern
        if used_ai_selectors:
            # Surfaced in the UI via DetectionEvidence.jsx's "Pattern Analysis
            # (LLM)" card — this field already existed in the schema/frontend
            # but nothing populated it until now. Full suggestion content
            # (confidence, reasoning, exact selectors) is in
            # run.options["ai_suggestions"], retrievable via
            # GET /runs/{id}/ai-context; this is the at-a-glance summary.
            suggestion = _get_latest_ai_suggestion(run) or {}
            result.llm_pattern = (
                f"Heuristic detection and the existing playbook both failed to find a "
                f"login form. The login was completed using AI-suggested selectors "
                f"(confidence {suggestion.get('confidence', '?')}): "
                f"{suggestion.get('reasoning', 'no reasoning recorded')}"
            )
        else:
            result.llm_pattern = None
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = automation.pre_auth_html
        result.post_auth_html = automation.post_auth_html
        result.har_entries = har_entries
        result.completed_at = finish

        result.learned_selectors = {
            key: value
            for key, value in {
                "username_selector": automation.username_selector,
                "password_selector": automation.password_selector,
                "submit_selector": automation.submit_selector,
                "submit_method": automation.submit_method,
            }.items()
            if value
        } or None

        # Phase 4: Record playbook usage (historical learning) — only when its
        # selectors were actually used for this login.
        if playbook and playbook_selectors and not used_ai_selectors:
            try:
                from app.services.learning import record_playbook_usage
                record_playbook_usage(playbook, success=True, db=db)
                result.playbook_success_recorded = True
                record(f"Playbook usage recorded (success)")
            except Exception as e:
                logger.warning(f"Failed to record playbook usage for run {run.id}: {e}", exc_info=True)

        # Multi-engine support: Run additional engines if selected
        engines = run.options.get("engines", ["selenium"]) if isinstance(run.options, dict) else ["selenium"]
        if "playwright" in engines:
            try:
                import asyncio
                from app.services.automation.patterns.playwright.form_login import attempt_form_login_playwright

                # Stagger delay to avoid session conflicts
                time.sleep(2)
                record("Running Playwright engine for complete HAR capture...")

                playwright_result = asyncio.run(attempt_form_login_playwright(
                    run_id=f"{run.id}-playwright",
                    target_url=run.target_url,
                    username=variant.username,
                    password=variant.password,
                    timeout_seconds=45
                ))

                if playwright_result.success and playwright_result.har_bytes:
                    # Save Playwright HAR file
                    pw_har_name = _prefixed_name(variant, "playwright-network.har", multi_role)
                    pw_har_path = storage.save_bytes(run.id, pw_har_name, playwright_result.har_bytes)
                    result.artifacts.append(
                        Artifact(
                            id=_artifact_id(run.id, variant, "PW-HAR", multi_role),
                            run_id=run.id,
                            name=pw_har_name,
                            description=f"Complete HAR file captured via Playwright for {variant.label} (full auth flow).",
                            type=ArtifactType.har.value,
                            size_bytes=len(playwright_result.har_bytes),
                            storage_path=pw_har_path,
                            download_url=None,
                            role_slug=variant.slug,
                            created_at=datetime.now(timezone.utc),
                        )
                    )
                    record(f"Playwright HAR captured ({len(playwright_result.har_bytes)} bytes)")

                    # Scan for JavaScript secrets (pre-auth)
                    try:
                        from app.services.js_secret_scanner import scan_javascript_secrets
                        js_secrets = scan_javascript_secrets(playwright_result.har_bytes, pre_auth=True)
                        if js_secrets:
                            record(f"⚠️ Found {len(js_secrets)} secret(s) in JavaScript files (pre-auth)")
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["js_secrets"] = js_secrets
                            for secret in js_secrets:
                                if secret.get("severity") == "CRITICAL":
                                    record(f"🔴 CRITICAL: {secret.get('type')} found in {secret.get('file')}:{secret.get('line')}")
                        else:
                            record("✅ No secrets detected in JavaScript files")
                    except Exception as e:
                        record(f"JS secret scanner failed: {str(e)}")

                    # Save Playwright screenshots
                    for pw_index, pw_screenshot in enumerate(playwright_result.screenshots, start=1):
                        pw_screenshot_name = _prefixed_name(variant, f"playwright-{pw_screenshot.file_name}", multi_role)
                        pw_screenshot_path = storage.save_bytes(run.id, pw_screenshot_name, pw_screenshot.data)
                        result.artifacts.append(
                            Artifact(
                                id=_artifact_id(run.id, variant, f"PW-SHOT-{pw_index:02d}", multi_role),
                                run_id=run.id,
                                name=pw_screenshot_name,
                                description=pw_screenshot.description or f"Playwright screenshot for {variant.label}.",
                                type=ArtifactType.screenshot.value,
                                size_bytes=len(pw_screenshot.data),
                                storage_path=pw_screenshot_path,
                                download_url=None,
                                role_slug=variant.slug,
                                created_at=datetime.now(timezone.utc),
                            )
                        )
                else:
                    record(f"Playwright engine completed but did not capture HAR")
            except Exception as pw_exc:
                logger.warning(f"Playwright engine failed for run {run.id}: {pw_exc}")
                record(f"Playwright engine failed: {pw_exc}")

    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("Form auth automation failed for run %s", run.id)
        record(f"Form authentication automation failed: {exc}")
        result.error = str(exc)
        result.completed_at = datetime.now(timezone.utc)

    return result


def _run_two_step_variant(
    run: Run,
    variant: RoleVariant,
    storage: "ArtifactStorage",
    db: SessionLocal,
    multi_role: bool,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
    headless: bool = True,
) -> VariantResult:
    """Execute two-step form authentication (email → password flow)."""
    from app.services.automation.patterns.two_step_form import run_two_step_form_login
    from app.services.side_files import build_two_step_side_file

    result = VariantResult(success=False)
    record = lambda msg: result.events.append(_make_role_event(run.id, variant, msg, multi_role))
    max_attempts = 3
    last_error: Exception | None = None

    entry_url = _detected_entry_url(run)
    try:
        record(f"Detected two-step form authentication; launching headless browser at {entry_url}.")
        from app.services.automation.types import AutomationFailure

        for attempt in range(1, max_attempts + 1):
            try:
                automation = run_two_step_form_login(
                    entry_url,
                    variant.username or "",
                    variant.password or "",
                    login_hint=login_hint,
                    domain_prefix=domain_prefix,
                    headless=headless
                )
                last_error = None
                break
            except AutomationFailure as exc:
                last_error = exc
                result.error = exc.message
                for event_msg in not_yet_written(exc.events):
                    record(event_msg)
                for screenshot in exc.screenshots:
                    screenshot_name = _prefixed_name(variant, screenshot.file_name, multi_role)
                    storage_path = storage.save_bytes(run.id, screenshot_name, screenshot.data)
                    result.artifacts.append(
                        Artifact(
                            id=_artifact_id(run.id, variant, f"FAIL-{len(result.artifacts):02d}", multi_role),
                            run_id=run.id,
                            name=screenshot_name,
                            description=screenshot.description or f"Screenshot from failed two-step authentication attempt for {variant.label}.",
                            type=ArtifactType.screenshot.value,
                            size_bytes=len(screenshot.data),
                            storage_path=storage_path,
                            download_url=None,
                            role_slug=variant.slug,
                            created_at=datetime.now(timezone.utc),
                        )
                    )
                result.pre_auth_html = exc.html or ""
                record(f"Attempt {attempt} failed: {exc.message}")
                if isinstance(exc, CredentialRejected):
                    record("The site rejected these credentials; not retrying (avoids account lockout).")
                elif attempt < max_attempts:
                    time.sleep(2)
                    continue
                result.completed_at = datetime.now(timezone.utc)
                return result

        finish = datetime.now(timezone.utc)

        result.success = True
        result.completed_at = finish
        result.final_url = automation.final_url
        result.pattern = automation.pattern
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        result.pre_auth_html = automation.pre_auth_html
        result.post_auth_html = automation.post_auth_html

        # Log automation events
        for event_msg in not_yet_written(automation.events):
            record(event_msg)

        # Generate .side file from recorded actions
        if automation.recorded_actions:
            side_bytes = build_two_step_side_file(
                entry_url, automation.recorded_actions, variant.username or "", variant.password or "",
                final_url=automation.final_url,
            )
            # Plaintext credentials stay inside the .side (Tenable needs them);
            # ArtifactStorage encrypts the whole file at rest with the owner's key.
            encrypted_side_bytes = side_bytes
            side_is_encrypted = True
            side_name = _prefixed_name(variant, f"two_step_login_{finish.strftime('%Y%m%d_%H%M%S')}.side", multi_role)
            side_path = storage.save_bytes(run.id, side_name, encrypted_side_bytes)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, "SIDE", multi_role),
                    run_id=run.id,
                    name=side_name,
                    description=f"Selenium IDE (.side) automation script for two-step login flow for {variant.label}.",
                    type=ArtifactType.side_file.value,
                    size_bytes=len(encrypted_side_bytes),
                    storage_path=side_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                    is_encrypted=side_is_encrypted,
                )
            )
            record("Generated Selenium IDE .side file for two-step flow.")

            # Generate export artifacts for security testing tools
            export_artifacts = _generate_export_artifacts(
                run, variant, automation, storage, finish, multi_role, record
            )
            result.artifacts.extend(export_artifacts)

        # Save screenshots
        for index, screenshot in enumerate(automation.screenshots, start=1):
            screenshot_name = _prefixed_name(variant, screenshot.file_name, multi_role)
            storage_path = storage.save_bytes(run.id, screenshot_name, screenshot.data)
            result.artifacts.append(
                Artifact(
                    id=_artifact_id(run.id, variant, f"TWO-STEP-{index:02d}", multi_role),
                    run_id=run.id,
                    name=screenshot_name,
                    description=screenshot.description or f"Screenshot captured during two-step authentication for {variant.label}.",
                    type=ArtifactType.screenshot.value,
                    size_bytes=len(screenshot.data),
                    storage_path=storage_path,
                    download_url=None,
                    role_slug=variant.slug,
                    created_at=finish,
                )
            )
            record(f"Captured screenshot: {screenshot.file_name}")

        # Build HAR entries
        har_entries = [
            {
                "url": run.target_url,
                "method": "GET",
                "status": 200,
                "statusText": "OK",
                "mimeType": "text/html",
                "bodySize": len((automation.pre_auth_html or "").encode("utf-8")),
                "time": 160,
                "title": f"{variant.label} email/username entry",
            },
            {
                "url": run.target_url,
                "method": "POST",
                "status": 200,
                "statusText": "OK",
                "mimeType": "text/html",
                "bodySize": 0,
                "time": 210,
                "title": f"{variant.label} submit email/username",
            },
            {
                "url": automation.final_url or run.target_url,
                "method": "POST",
                "status": 302,
                "statusText": "Redirect",
                "mimeType": "application/x-www-form-urlencoded",
                "bodySize": 0,
                "time": 260,
                "title": f"{variant.label} submit password",
            },
            {
                "url": automation.final_url or run.target_url,
                "method": "GET",
                "status": 200,
                "statusText": "OK",
                "mimeType": "text/html",
                "bodySize": len((automation.post_auth_html or "").encode("utf-8")),
                "time": 310,
                "title": f"{variant.label} authenticated landing page",
            },
        ]

        # If we got here, automation succeeded (AutomationFailure would have been caught above)
        result.success = True
        result.final_url = automation.final_url or run.target_url
        result.pattern = automation.pattern
        result.session_cookies = _normalize_cookies_payload(automation.cookies)
        # Preserve js_secrets if already set, then merge automation.security_context
        js_secrets_backup = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
        result.security_context = automation.security_context.model_dump(mode="json") if automation.security_context else None
        if js_secrets_backup:
            if result.security_context is None:
                result.security_context = {}
            result.security_context["js_secrets"] = js_secrets_backup
        record("Two-step authentication completed successfully.")

        result.pre_auth_html = automation.pre_auth_html
        result.post_auth_html = automation.post_auth_html
        result.har_entries = har_entries
        result.completed_at = finish

        # Multi-engine support: Run Playwright if selected
        engines = run.options.get("engines", ["selenium"]) if isinstance(run.options, dict) else ["selenium"]

        if "playwright" in engines:
            try:
                import asyncio
                from app.services.automation.patterns.playwright.two_step_form import attempt_two_step_login_playwright

                # Stagger delay to avoid session conflicts
                time.sleep(2)
                record("Running Playwright engine for two-step auth HAR capture...")

                playwright_result = asyncio.run(attempt_two_step_login_playwright(
                    run_id=f"{run.id}-playwright",
                    target_url=entry_url,
                    username=variant.username,
                    password=variant.password,
                    timeout_seconds=45,
                    login_hint=login_hint,
                    domain_prefix=domain_prefix
                ))

                if playwright_result.success and playwright_result.har_bytes:
                    # Save Playwright HAR file
                    pw_har_name = _prefixed_name(variant, "playwright-network.har", multi_role)
                    pw_har_path = storage.save_bytes(run.id, pw_har_name, playwright_result.har_bytes)
                    result.artifacts.append(
                        Artifact(
                            id=_artifact_id(run.id, variant, "PW-HAR", multi_role),
                            run_id=run.id,
                            name=pw_har_name,
                            description=f"Complete HAR file captured via Playwright for two-step auth ({variant.label}).",
                            type=ArtifactType.har.value,
                            size_bytes=len(playwright_result.har_bytes),
                            storage_path=pw_har_path,
                            download_url=None,
                            role_slug=variant.slug,
                            created_at=datetime.now(timezone.utc),
                        )
                    )
                    record(f"Playwright HAR captured ({len(playwright_result.har_bytes)} bytes)")

                    # Scan for JavaScript secrets (pre-auth)
                    try:
                        from app.services.js_secret_scanner import scan_javascript_secrets
                        js_secrets = scan_javascript_secrets(playwright_result.har_bytes, pre_auth=True)
                        if js_secrets:
                            record(f"⚠️ Found {len(js_secrets)} secret(s) in JavaScript files (pre-auth)")
                            if result.security_context is None:
                                result.security_context = {}
                            result.security_context["js_secrets"] = js_secrets
                            for secret in js_secrets:
                                if secret.get("severity") == "CRITICAL":
                                    record(f"🔴 CRITICAL: {secret.get('type')} found in {secret.get('file')}:{secret.get('line')}")
                        else:
                            record("✅ No secrets detected in JavaScript files")
                    except Exception as e:
                        record(f"JS secret scanner failed: {str(e)}")

                    # Save Playwright screenshots
                    for pw_index, pw_screenshot in enumerate(playwright_result.screenshots, start=1):
                        pw_screenshot_name = _prefixed_name(variant, f"playwright-{pw_screenshot.file_name}", multi_role)
                        pw_screenshot_path = storage.save_bytes(run.id, pw_screenshot_name, pw_screenshot.data)
                        result.artifacts.append(
                            Artifact(
                                id=_artifact_id(run.id, variant, f"PW-TWO-STEP-{pw_index:02d}", multi_role),
                                run_id=run.id,
                                name=pw_screenshot_name,
                                description=pw_screenshot.description,
                                type=ArtifactType.screenshot.value,
                                size_bytes=len(pw_screenshot.data),
                                storage_path=pw_screenshot_path,
                                download_url=None,
                                role_slug=variant.slug,
                                created_at=datetime.now(timezone.utc),
                            )
                        )
                    record(f"Saved {len(playwright_result.screenshots)} Playwright screenshots")
                else:
                    record("Playwright engine completed but authentication may have failed")

            except Exception as e:
                record(f"Playwright engine failed: {str(e)}")
                # Don't fail entire run if Playwright fails

    except Exception as exc:  # pragma: no cover - webdriver failures
        logger.exception("Two-step form automation failed for run %s", run.id)
        record(f"Two-step authentication automation failed: {exc}")
        result.error = str(exc)
        result.completed_at = datetime.now(timezone.utc)

    return result


def _run_unsupported_variant(
    run: Run,
    variant: RoleVariant,
    auth_hint: str,
    detected_label_readable: str,
) -> VariantResult:
    """
    Handles authentication types that are not yet supported by automation.

    Returns an honest failure with a clear error message instead of simulating
    fake artifacts and timeline events. This maintains data integrity by ensuring
    we never report success when no real automation occurred.

    Supported auth types: see the dispatch in _execute_variant above.
    """
    supported_types = ["form_based", "two_step_form", "basic_auth", "azure_ad", "okta", "saml", "ldap", "oauth"]

    result = VariantResult(success=False)
    result.started_at = datetime.now(timezone.utc)

    # Check if detection failed due to network errors (firewall, timeout, etc.)
    detected_auth = run.options.get("detected_auth", {}) if isinstance(run.options, dict) else {}
    detection_error = detected_auth.get("error")
    signals = detected_auth.get("signals", [])

    # Look for network errors or early termination in signals
    network_errors = [s for s in signals if s.get("type") in ("network_error", "early_termination")]
    is_network_failure = bool(network_errors) or (detection_error and "timeout" in detection_error.lower())

    # If network failure, show that as the primary error
    if is_network_failure:
        error_detail = detection_error or network_errors[0].get("detail", "Connection failed")
        result.error = (
            f"Target appears unreachable - network timeout or firewall blocking access.\n\n"
            f"Error: {error_detail}\n\n"
            f"This is likely a network/firewall issue, not an authentication problem. "
            f"Please verify the target URL is accessible from this server."
        )
    # HTTP-level challenges a Selenium script can't answer: say what to do
    # in the scanner instead of a generic "unsupported".
    elif auth_hint in _HTTP_CHALLENGE_GUIDANCE:
        scheme = _HTTP_CHALLENGE_GUIDANCE[auth_hint]
        result.error = (
            f"The target uses {scheme} (an HTTP-level challenge). A Selenium .side script "
            f"cannot answer it, so AuthRecon does not generate one.\n\n"
            f"For the scan, use your scanner's HTTP authentication settings for {scheme} "
            f"with these credentials, if your scanner version supports that scheme."
        )
    # Clear, honest error message for actual unsupported auth types
    elif auth_hint:
        result.error = (
            f"Authentication type '{auth_hint}' (detected as '{detected_label_readable}') "
            f"is not yet supported by AuthRecon automation.\n\n"
            f"Currently supported types: {', '.join(supported_types)}\n\n"
            f"If you know the login type, rerun with the authentication type override set, "
            f"or use manual recording mode to drive the login yourself."
        )
    else:
        result.error = (
            f"Unable to determine authentication type for this target "
            f"(detected as '{detected_label_readable}'). "
            f"Rerun with the authentication type override set, or use manual recording mode.\n\n"
            f"Currently supported types: {', '.join(supported_types)}"
        )

    # Add a timeline event so operators see why automation stopped
    if is_network_failure:
        timeline_msg = f"[{variant.label}] Target unreachable - network timeout or firewall. Run failed before authentication could be attempted."
    else:
        timeline_msg = f"[{variant.label}] Detected '{detected_label_readable}' authentication which is not supported yet. Run failed before collecting artifacts."
    result.events.append(
        TimelineEvent(
            run_id=run.id,
            occurred_at=datetime.now(timezone.utc),
            message=timeline_msg,
        )
    )

    result.completed_at = datetime.now(timezone.utc)

    return result


def _options_with_role_results(options: dict | None, variant_results: list) -> dict:
    """Copy of run.options with each role's slug/status/final_url/error set."""
    new_options = deepcopy(options) if isinstance(options, dict) else {}
    roles = (new_options.get("scope") or {}).get("roles")
    if not isinstance(roles, list):
        return new_options
    for variant, result in variant_results:
        position = variant.index - 1  # variants are built with enumerate(raw_roles, start=1)
        if variant.scope_entry is None or not (0 <= position < len(roles)) or not isinstance(roles[position], dict):
            continue
        entry = roles[position]
        entry["slug"] = variant.slug
        entry["status"] = "succeeded" if result.success else "failed"
        entry["final_url"] = strip_userinfo(result.final_url)
        if result.error:
            entry["error"] = result.error
        else:
            entry.pop("error", None)
    return new_options


_HTTP_CHALLENGE_GUIDANCE = {
    "windows_integrated": "Windows Integrated Authentication (Kerberos/NTLM)",
    "digest_auth": "HTTP Digest authentication",
}


def process_run(run_id: str) -> None:
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if not run:
            return

        try:
            start = datetime.now(timezone.utc)
            run.status = RunStatus.running
            run.started_at = start
            db.add(
                TimelineEvent(
                    run_id=run.id,
                    occurred_at=start,
                    message="Worker started",
                )
            )
            db.commit()
            db.refresh(run)

            llm_allowed = True
            if run.submitted_by:
                llm_allowed = bool(run.submitted_by.llm_enabled)

            options = run.options if isinstance(run.options, dict) else {}
            detected_info = options.get("detected_auth") if isinstance(options, dict) else None

            options_dict = options if isinstance(options, dict) else {}
            raw_forced_auth = options_dict.get("forced_auth_type")
            forced_auth_type = (raw_forced_auth or "").strip().lower() or None
            run_auth_type = (run.auth_type or "").strip().lower()
            detected_label = forced_auth_type or run_auth_type or "authentication"
            if isinstance(detected_info, dict):
                detected_candidate = detected_info.get("auth_type")
                prefers_detection = (
                    not forced_auth_type
                    and (not run_auth_type or run_auth_type in {"generic", "unknown"})
                )
                if detected_candidate and prefers_detection:
                    detected_label = detected_candidate
            detected_label_readable = str(detected_label).replace("_", " ")

            secret_used: str | None = None
            username: str | None = None
            if isinstance(options, dict):
                credential_id = options.get("credential_id")
                username = options.get("username")
                if credential_id:
                    credential = db.get(StoredCredential, credential_id)
                    if credential:
                        secret_used = get_plain_secret(credential)
                elif "one_time_secret" in options:
                    cipher = get_credential_cipher()
                    enc_secret = options.get("one_time_secret")
                    if isinstance(enc_secret, str):
                        secret_used = cipher.decrypt(enc_secret.encode("utf-8")).decode("utf-8")

            variants = _build_variants(run, detected_label, username, secret_used)
            if not variants:
                failure_event = TimelineEvent(
                    run_id=run.id,
                    occurred_at=datetime.now(timezone.utc),
                    message="No credential variants available; run cannot proceed.",
                )
                run.status = RunStatus.failed
                run.finished_at = datetime.now(timezone.utc)
                run.pattern = "Credential data missing"
                run.session_cookies = []
                db.add(failure_event)
                db.commit()
                return

            multi_role = len(variants) > 1
            storage = get_artifact_storage()
            # Bind the at-rest key in this session (provisioning it if needed) so
            # every artifact below is encrypted with the owner's key.
            storage.bind_run_key(run.id, write_key_for_run(db, run))
            db.commit()
            events_to_add: list[TimelineEvent] = []
            forced_auth_type = forced_auth_type or None
            provided_hint = options_dict.get("login_hint")
            if forced_auth_type:
                events_to_add.append(
                    TimelineEvent(
                        run_id=run.id,
                        occurred_at=datetime.now(timezone.utc),
                        message=f"Auth type override applied: '{forced_auth_type}'.",
                    )
                )
            if provided_hint:
                events_to_add.append(
                    TimelineEvent(
                        run_id=run.id,
                        occurred_at=datetime.now(timezone.utc),
                        message=f"Login hint provided: \"{provided_hint}\".",
                    )
                )
            artifacts_to_add: list[Artifact] = []
            variant_results: list[tuple[RoleVariant, VariantResult]] = []
            options_modified = False

            # Live view (opt-in): a per-run display streamed through the portal's
            # authenticated VNC proxy. The stack tears it down and clears
            # run.vnc_port as soon as the variants finish, before completion.
            headless = True
            stream_stack = ExitStack()
            # Mask every exact occurrence of this run's passwords in its HARs.
            stream_stack.enter_context(
                storage.redacting(run.id, [secret_used, *(v.password for v in variants)])
            )
            if run.streaming_enabled:
                try:
                    stream_stack.enter_context(live_view(db, run.id))
                    headless = False
                    stream_message = "Live browser view started"
                except Exception as exc:  # never fail the run because the live view failed
                    logger.warning("Live view unavailable for run %s: %s", run.id, exc)
                    stream_message = "Live browser view could not start; continuing without it"
                db.add(
                    TimelineEvent(
                        run_id=run.id,
                        occurred_at=datetime.now(timezone.utc),
                        message=stream_message,
                    )
                )
                db.commit()
            drain_navigation_notes()

            # Timeline events are written as they happen (real timestamps, and
            # the live view shows progress) instead of all at the end.
            with stream_stack, live_timeline(run.id):
                for variant in variants:
                    events_to_add.append(_make_role_event(run.id, variant, "Starting automation", multi_role))
                    with event_prefix(f"[{variant.label}] " if multi_role else ""):
                        result = _execute_variant(
                            run,
                            variant,
                            llm_allowed=llm_allowed,
                            storage=storage,
                            db=db,
                            multi_role=multi_role,
                            detected_label_readable=detected_label_readable,
                            headless=headless,
                        )
                    variant_results.append((variant, result))
                    events_to_add.extend(result.events)
                    for note in drain_navigation_notes():
                        events_to_add.append(_make_role_event(run.id, variant, note, multi_role))
                    status_text = "completed" if result.success else "failed"
                    events_to_add.append(_make_role_event(run.id, variant, f"Automation {status_text}", multi_role))
                    artifacts_to_add.extend(result.artifacts)
                    if variant.scope_entry is not None:
                        variant.scope_entry["status"] = "succeeded" if result.success else "failed"
                        variant.scope_entry["final_url"] = result.final_url
                        if result.error:
                            variant.scope_entry["error"] = result.error
                        elif "error" in variant.scope_entry:
                            variant.scope_entry.pop("error", None)
                        options_modified = True

            # Write each role's outcome into a fresh copy of run.options. The
            # scope_entry dicts above belong to the options loaded at start; any
            # commit since then (playbook bookkeeping, live timeline) expired
            # that object, so mutating them in place was silently lost and the
            # UI showed every role as "pending" forever.
            if any(v.scope_entry is not None for v, _ in variant_results):
                run.options = _options_with_role_results(run.options, variant_results)
                options_modified = False  # reassigned: already tracked

            first_success = next((res for _, res in variant_results if res.success), None)
            normalized_cookies = _normalize_cookies_payload(first_success.session_cookies if first_success else None)

            run.finished_at = datetime.now(timezone.utc)
            if first_success:
                run.final_url = strip_userinfo(first_success.final_url) or run.target_url
                # Text on the post-login page and not on the login page, or None
                # (the WAS card then asks the operator); never a placeholder.
                run.pattern = choose_verify_pattern(
                    [first_success.pattern], first_success.post_auth_html, first_success.pre_auth_html
                )
                run.llm_pattern = first_success.llm_pattern
                if normalized_cookies:
                    run.session_cookies_enc = encrypt_run_cookies(db, run, normalized_cookies)
                run.session_cookies = []
            else:
                run.final_url = run.target_url
                run.pattern = "Authentication automation failed"
                run.llm_pattern = None
                run.session_cookies = []
                # Store the first error message for display in UI
                first_error = next((res.error for _, res in variant_results if res.error), None)
                if first_error:
                    run.error_message = first_error

            # A multi-role run where some roles logged in still produced usable
            # artifacts for those roles, so it counts as succeeded, with a
            # warning naming the roles that failed.
            run.status = RunStatus.succeeded if first_success else RunStatus.failed
            failed_roles = [v.label for v, res in variant_results if not res.success]
            if run.status == RunStatus.succeeded and failed_roles:
                completion_message = (
                    "Run completed with warnings: login failed for "
                    + ", ".join(failed_roles)
                    + ". Artifacts are available for the other roles."
                )
            elif run.status == RunStatus.succeeded:
                completion_message = "Run completed successfully"
            else:
                completion_message = "Run completed with errors"
            events_to_add.append(
                TimelineEvent(
                    run_id=run.id,
                    occurred_at=datetime.now(timezone.utc),
                    message=completion_message,
                )
            )

            fingerprint_source = first_success or (variant_results[0][1] if variant_results else None)
            cookies_for_fingerprint = (
                normalized_cookies
                if first_success
                else _normalize_cookies_payload(fingerprint_source.session_cookies) if fingerprint_source else []
            )
            if fingerprint_source:
                try:
                    fingerprint = analyze_tech_fingerprint(
                        run.final_url or run.target_url,
                        html_samples=(fingerprint_source.pre_auth_html, fingerprint_source.post_auth_html),
                        cookies=_cookie_names(cookies_for_fingerprint),
                    )
                except Exception:  # pragma: no cover - defensive logging
                    logger.debug("Tech fingerprint analysis failed for run %s", run.id, exc_info=True)
                    fingerprint = None
                if fingerprint:
                    run.tech_fingerprint = fingerprint

                # Extract security context from first successful variant
                if fingerprint_source.security_context:
                    run.security_context = fingerprint_source.security_context
                    flag_modified(run, "security_context")

            _persist_snapshot_artifacts(run, start, variant_results, storage, artifacts_to_add, multi_role)

            # Update security_context with any additions from _persist_snapshot_artifacts (e.g., js_secrets)
            for variant, result in variant_results:
                logger.info(f"[DEBUG] Checking variant {variant.label}: has security_context={result.security_context is not None}, type={type(result.security_context)}")
                if result.security_context:
                    logger.info(f"[DEBUG] security_context keys: {result.security_context.keys() if hasattr(result.security_context, 'keys') else 'N/A'}")
                    js_secrets = result.security_context.get("js_secrets") if isinstance(result.security_context, dict) else None
                    if js_secrets:
                        logger.info(f"[DEBUG] Found {len(js_secrets)} js_secrets, copying to run.security_context")
                        if run.security_context is None:
                            run.security_context = {}
                        run.security_context["js_secrets"] = js_secrets
                        flag_modified(run, "security_context")
                        break  # Only need one variant's js_secrets

            if options_modified:
                flag_modified(run, "options")

            events_to_add = _not_written_live(events_to_add)
            if events_to_add:
                db.add_all(events_to_add)
            if artifacts_to_add:
                db.add_all(artifacts_to_add)

            # Encrypt cookie values in security_context now: learning below
            # commits the session, and nothing may reach the DB in plaintext.
            if run.security_context:
                try:
                    _encrypt_security_context_cookies(run.security_context, _run_cookie_cipher(db, run))
                    flag_modified(run, "security_context")
                except Exception as e:
                    logger.warning(f"Failed to encrypt cookies for run {run.id}: {e}", exc_info=True)

            # Phase 4: Learn from successful runs (historical learning)
            if run.status == RunStatus.succeeded:
                try:
                    from app.services.learning import learn_from_successful_run
                    successful = [res for _, res in variant_results if res.success]
                    playbook = learn_from_successful_run(
                        run=run,
                        db=db,
                        profile_id=run.submitted_by_profile_id,
                        selectors=next((r.learned_selectors for r in successful if r.learned_selectors), None),
                        success_already_recorded=any(r.playbook_success_recorded for r in successful),
                    )
                    if playbook:
                        logger.info(
                            f"Learned playbook {playbook.id} from run {run.id} "
                            f"(domain: {playbook.domain}, auth: {playbook.auth_type})"
                        )
                except Exception as e:
                    # Don't fail the run if learning fails
                    logger.warning(f"Failed to learn from run {run.id}: {e}", exc_info=True)


            # Generate authentication flow summary
            try:
                # Find HAR artifact for flow analysis
                har_artifact = next((a for a in run.artifacts if a.type == ArtifactType.har), None)
                har_bytes = None

                if har_artifact and har_artifact.storage_path:
                    try:
                        har_bytes = read_artifact_bytes(db, run, har_artifact, storage)
                    except Exception as e:
                        logger.debug(f"Failed to read HAR artifact for flow summary: {e}")

                # Generate summary from run data and HAR
                run_data = {
                    "auth_type": run.auth_type,
                    "final_url": run.final_url,
                    "tech_fingerprint": run.tech_fingerprint,
                    "options": run.options,
                    "pattern": run.pattern,
                    "session_cookies": [{"name": n} for n in _cookie_names(normalized_cookies)],
                }

                flow_summary = generate_flow_summary(run_data, har_bytes=har_bytes)
                if flow_summary:
                    run.flow_summary = flow_summary
                    logger.debug(f"Generated flow summary for run {run.id}")

            except Exception as e:
                # Don't fail the run if summary generation fails
                logger.warning(f"Failed to generate flow summary for run {run.id}: {e}", exc_info=True)

            db.commit()
        except Exception as exc:  # pragma: no cover - defensive logging and recovery
            logger.exception("Worker error while processing run %s", run_id)
            db.rollback()
            now = datetime.now(timezone.utc)
            run.status = RunStatus.failed
            run.finished_at = now
            if not run.pattern:
                run.pattern = "Worker execution failed"
            run.llm_pattern = None
            run.session_cookies = []
            message = str(exc) or exc.__class__.__name__
            db.add(
                TimelineEvent(
                    run_id=run.id,
                    occurred_at=now,
                    message=f"Worker error: {message[:240]}",
                )
            )
            try:
                db.commit()
            except Exception:
                db.rollback()
            raise
    finally:
        get_artifact_storage().release_run(run_id)
        _remove_temp_hars(run_id)
        db.close()


def _remove_temp_hars(run_id: str) -> None:
    """Delete Playwright's unmasked /tmp HAR copies; the stored copy is masked and encrypted."""
    import glob
    import os
    import tempfile

    tmp = tempfile.gettempdir()
    for path in {*glob.glob(os.path.join(tmp, f"{run_id}*.har")), os.path.join(tmp, f"manual-{run_id}.har")}:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            logger.warning("Could not remove temporary HAR for run %s", run_id)


def run_worker() -> None:
    with Connection(get_redis_connection()):
        worker = Worker(["runs", "scanner"])
        worker.work(with_scheduler=True)


if __name__ == "__main__":
    run_worker()
def _detected_entry_url(run: Run) -> str:
    options = run.options if isinstance(run.options, dict) else {}
    if isinstance(options, dict):
        detected = options.get("detected_auth")
        if isinstance(detected, dict):
            final_url = detected.get("final_url")
            if isinstance(final_url, str) and final_url.startswith(("http://", "https://")):
                return final_url
    return run.target_url


# Manual Recording Session Handler (runs in worker container with VNC)
def process_manual_session(run_id: str, target_url: str):
    """
    Launch and maintain a Playwright browser for manual recording.
    This runs in the worker container which has VNC services running.
    Each session gets its own Xvfb display and VNC server for isolation.

    Current implementation: Dynamic display allocation (displays :100-:199)
    - Provides process + X11 display separation
    - Suitable for trusted team environments
    - Up to 100 concurrent manual sessions

    Future enhancement: Ephemeral container per session
    - Spin up temporary Docker container per manual job
    - Full container-level isolation
    - Better for multi-tenant/adversarial scenarios
    - Requires Docker API access and orchestration changes
    """
    import asyncio
    import logging
    import subprocess
    import os
    import time
    from playwright.async_api import async_playwright
    from app.services.automation.navigation import (
        DISABLE_HTTP2_ARG,
        HTTP2_FALLBACK_NOTE,
        should_retry_without_http2,
    )
    from app.models import Run, TimelineEvent
    from app.db import get_db
    from datetime import datetime, timezone
    from app.schemas.run import RunStatus

    logger = logging.getLogger(__name__)

    async def _run_session():
        db = next(get_db())
        # Per-session display + VNC; closing the stack clears run.vnc_port and
        # tears the processes down (see app/services/vnc_session.py).
        stream_stack = ExitStack()

        try:
            _run = db.get(Run, run_id)
            get_artifact_storage().bind_run_key(run_id, write_key_for_run(db, _run))
            db.commit()
            stream_stack.enter_context(live_view(db, run_id))
            logger.info(f"[Manual Recording {run_id}] Live view ready")

            # Launch browser with this display
            logger.info(f"[Manual Recording {run_id}] Launching browser for {target_url}")

            async with async_playwright() as p:
                async def _open_recording_browser(disable_http2: bool = False):
                    browser = await p.chromium.launch(
                        headless=False,  # Visible browser for VNC
                        args=[DISABLE_HTTP2_ARG] if disable_http2 else [],
                    )

                    # Create context with HAR recording
                    context = await browser.new_context(
                        record_har_path=f"/tmp/manual-{run_id}.har",
                        record_har_omit_content=False,
                    )

                    # Inject JavaScript to record user interactions for .side file generation
                    # IMPORTANT: Use add_init_script() to inject on EVERY page navigation
                    # (page.evaluate() only runs once and is lost on navigation)
                    await context.add_init_script("""
                        // Initialize recording array (persist across page navigations using localStorage)
                        const STORAGE_KEY = '_authrecon_actions';

                        // Load existing actions from localStorage (survives page navigation)
                        let stored = null;
                        try {
                            stored = localStorage.getItem(STORAGE_KEY);
                        } catch (e) {
                            console.warn('[AuthRecon Recording] localStorage not available, actions may be lost on navigation');
                        }

                        window._authrecon_recorded_actions = stored ? JSON.parse(stored) : [];
                        window._authrecon_last_url = window.location.href;

                        // Helper to save actions to localStorage after each event
                        function saveActions() {
                            try {
                                localStorage.setItem(STORAGE_KEY, JSON.stringify(window._authrecon_recorded_actions));
                            } catch (e) {
                                // Ignore storage errors
                            }
                        }

                        // Record initial page load (only if not already recorded)
                        const currentUrl = window.location.href;
                        const lastAction = window._authrecon_recorded_actions[window._authrecon_recorded_actions.length - 1];
                        if (!lastAction || lastAction.target !== currentUrl) {
                            window._authrecon_recorded_actions.push({
                                command: 'open',
                                target: currentUrl,
                                value: '',
                                timestamp: Date.now()
                            });
                            saveActions();
                        }

                        // Helper: Generate selector for element
                        function getSelector(element) {
                            // Priority: id > name > data-testid > unique CSS
                            if (element.id) {
                                return 'id=' + element.id;
                            }
                            if (element.name) {
                                return 'name=' + element.name;
                            }
                            if (element.getAttribute('data-testid')) {
                                return 'css=[data-testid="' + element.getAttribute('data-testid') + '"]';
                            }

                            // Generate CSS selector
                            let path = [];
                            let current = element;
                            while (current && current.nodeType === Node.ELEMENT_NODE && current !== document.body) {
                                let selector = current.nodeName.toLowerCase();
                                if (current.className && typeof current.className === 'string') {
                                    let classes = current.className.trim().split(/\\s+/).filter(c => c && !c.match(/^(ng-|ui-)/));
                                    if (classes.length > 0) {
                                        selector += '.' + classes.slice(0, 2).join('.');
                                    }
                                }
                                path.unshift(selector);
                                current = current.parentElement;
                            }
                            return 'css=' + path.slice(-3).join(' > ');
                        }

                        // Track clicks
                        document.addEventListener('click', (e) => {
                            try {
                                let selector = getSelector(e.target);
                                let tagName = e.target.tagName.toLowerCase();

                                // Determine command type
                                let command = 'click';
                                if (tagName === 'a') {
                                    command = 'clickLink';
                                } else if (tagName === 'button' || (tagName === 'input' && e.target.type === 'submit')) {
                                    command = 'click';
                                }

                                window._authrecon_recorded_actions.push({
                                    command: command,
                                    target: selector,
                                    value: e.target.textContent ? e.target.textContent.trim().slice(0, 50) : '',
                                    timestamp: Date.now()
                                });
                                saveActions();

                                console.log('[AuthRecon Recording]', command, selector);
                            } catch (err) {
                                console.error('[AuthRecon Recording] Click tracking error:', err);
                            }
                        }, true);

                        // Track live input values so submit-flush knows what was typed
                        let currentInputValues = new Map();
                        document.addEventListener('input', (e) => {
                            try {
                                if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                                    currentInputValues.set(getSelector(e.target), e.target.value);
                                }
                            } catch (err) {}
                        }, true);

                        // Record type on blur — fires when focus leaves field, BEFORE any navigation.
                        // This replaces the old 500ms debounce which was killed by page navigations.
                        document.addEventListener('blur', (e) => {
                            try {
                                if ((e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') && e.target.value) {
                                    let selector = getSelector(e.target);
                                    let isPassword = e.target.type === 'password';
                                    let value = e.target.value;

                                    // Skip if already recorded with same value for this selector
                                    let existing = null;
                                    for (let i = window._authrecon_recorded_actions.length - 1; i >= 0; i--) {
                                        let a = window._authrecon_recorded_actions[i];
                                        if (a.command === 'type' && a.target === selector) { existing = a; break; }
                                    }
                                    if (existing && existing.value === value) return;

                                    window._authrecon_recorded_actions.push({
                                        command: 'type', target: selector, value: value, timestamp: Date.now()
                                    });
                                    saveActions();
                                    console.log('[AuthRecon Recording] type (blur)', selector, isPassword ? '***' : value);
                                }
                            } catch (err) {
                                console.error('[AuthRecon Recording] Blur tracking error:', err);
                            }
                        }, true);

                        // On submit: flush any inputs not yet captured by blur, then record submit
                        document.addEventListener('submit', (e) => {
                            try {
                                currentInputValues.forEach((value, selector) => {
                                    if (!value) return;
                                    let existing = null;
                                    for (let i = window._authrecon_recorded_actions.length - 1; i >= 0; i--) {
                                        let a = window._authrecon_recorded_actions[i];
                                        if (a.command === 'type' && a.target === selector) { existing = a; break; }
                                    }
                                    if (!existing || existing.value !== value) {
                                        window._authrecon_recorded_actions.push({
                                            command: 'type', target: selector, value: value, timestamp: Date.now()
                                        });
                                    }
                                });
                                saveActions();
                                console.log('[AuthRecon Recording] submit flush complete');
                            } catch (err) {
                                console.error('[AuthRecon Recording] Submit tracking error:', err);
                            }
                        }, true);

                        // Track navigation changes (SPAs, redirects)
                        setInterval(() => {
                            try {
                                if (window.location.href !== window._authrecon_last_url) {
                                    window._authrecon_recorded_actions.push({
                                        command: 'open',
                                        target: window.location.href,
                                        value: '',
                                        timestamp: Date.now()
                                    });
                                    saveActions();
                                    window._authrecon_last_url = window.location.href;
                                    console.log('[AuthRecon Recording] navigation', window.location.href);
                                }
                            } catch (err) {
                                console.error('[AuthRecon Recording] Navigation tracking error:', err);
                            }
                        }, 250);

                        console.log('[AuthRecon Recording] Interaction recording initialized');
                    """)
                    logger.info(f"[Manual Recording {run_id}] Interaction recording script injected")
                    return browser, context

                browser, context = await _open_recording_browser()

                def _timeline(message: str) -> None:
                    db.add(TimelineEvent(run_id=run_id, occurred_at=datetime.now(timezone.utc), message=message))
                    db.commit()

                # Create page and navigate. A failed initial navigation must not
                # end the session: the operator can still navigate in the live view.
                page = await context.new_page()
                logger.info(f"[Manual Recording {run_id}] Navigating to target")
                navigated = False
                try:
                    await page.goto(target_url)
                    navigated = True
                except Exception as nav_exc:
                    if should_retry_without_http2(nav_exc, http2_disabled=False):
                        logger.warning(f"[Manual Recording {run_id}] Navigation timed out; retrying with HTTP/2 disabled")
                        _timeline(HTTP2_FALLBACK_NOTE)
                        for closable in (context, browser):
                            try:
                                await closable.close()
                            except Exception:
                                pass
                        browser, context = await _open_recording_browser(disable_http2=True)
                        page = await context.new_page()
                        try:
                            await page.goto(target_url)
                            navigated = True
                        except Exception as retry_exc:
                            logger.warning(f"[Manual Recording {run_id}] Navigation retry failed: {type(retry_exc).__name__}")
                    else:
                        logger.warning(f"[Manual Recording {run_id}] Initial navigation failed: {type(nav_exc).__name__}")

                if navigated:
                    _timeline("Browser ready - log in manually in the live view")
                else:
                    _timeline(
                        "Could not load the target page automatically. The browser is still open: "
                        "navigate to the login page manually in the live view, then end the session when done."
                    )

                logger.info(f"[Manual Recording {run_id}] Browser ready - waiting for operator to end session")

                # Take screenshot of the initial page (pre-login)
                step_screenshots = []  # list of (label, url, png_bytes)
                try:
                    await asyncio.sleep(0.8)
                    _shot = await page.screenshot(full_page=True)
                    step_screenshots.append(("step-1-pre-login", page.url, _shot))
                    logger.info(f"[Manual Recording {run_id}] Step 1 screenshot (pre-login)")
                except Exception as _se:
                    logger.warning(f"[Manual Recording {run_id}] Pre-login screenshot failed: {_se}")

                _last_shot_url = page.url

                # Poll database to check if session should end
                while True:
                    await asyncio.sleep(3)

                    # Screenshot on every page navigation (post-login page, MFA, etc.)
                    try:
                        _cur_url = page.url
                        if _cur_url != _last_shot_url:
                            await asyncio.sleep(0.8)  # Let page settle after navigation
                            _shot = await page.screenshot(full_page=True)
                            _label = f"step-{len(step_screenshots) + 1}-navigation"
                            step_screenshots.append((_label, _cur_url, _shot))
                            _last_shot_url = _cur_url
                            logger.info(f"[Manual Recording {run_id}] Navigation screenshot ({_label}) at {_cur_url}")
                    except Exception as _se:
                        logger.warning(f"[Manual Recording {run_id}] Navigation screenshot failed: {_se}")

                    db.expire_all()
                    run = db.get(Run, run_id)
                    # If status changed from manual_recording, extract artifacts and close browser
                    if run.status != RunStatus.manual_recording:
                        logger.info(f"[Manual Recording {run_id}] Status changed to {run.status}, extracting artifacts")
                        break

                # Extract artifacts before closing browser
                from app.models import Artifact
                from app.schemas.artifact import ArtifactType
                from app.services.automation.security_context_extractor import (
                    extract_cookie_metadata,
                    analyze_cookie_security,
                    calculate_entropy
                )
                from app.services.tech_fingerprint import analyze_tech_fingerprint
                from app.services.flow_summarizer import generate_flow_summary
                from app.services.profiles import get_profile_artifact_cipher
                from bs4 import BeautifulSoup

                storage = get_artifact_storage()
                artifacts_created = []

                # Variables that need to be accessible in HAR processing block
                cookie_metadata_list = []
                final_page_html = ""

                try:
                    logger.info(f"[Manual Recording {run_id}] Extracting cookies, screenshot, and page content")

                    # Capture final URL
                    run.final_url = page.url

                    # Extract recorded interactions for .side file generation
                    recorded_actions = []
                    try:
                        recorded_actions = await page.evaluate("window._authrecon_recorded_actions || []")
                        logger.info(f"[Manual Recording {run_id}] Extracted {len(recorded_actions)} recorded actions")
                    except Exception as e:
                        logger.warning(f"[Manual Recording {run_id}] Failed to extract recorded actions: {e}")

                    # Extract final page HTML for pattern detection and tech fingerprinting
                    final_page_html = await page.content()
                    logger.info(f"[Manual Recording {run_id}] Captured final page HTML ({len(final_page_html)} bytes)")

                    # Extract verification pattern (success message/heading/title)
                    try:
                        soup = BeautifulSoup(final_page_html, 'html.parser')

                        # Try to extract success message (same selectors as automated runs)
                        success_message = None
                        success_selectors = [
                            ".flash.success",
                            ".flash",
                            ".alert-success",
                            ".alert",
                            "[role='alert']",
                            ".notification",
                            ".message",
                        ]
                        for selector in success_selectors:
                            elements = soup.select(selector)
                            for element in elements:
                                text = element.get_text(strip=True)
                                if text and len(text) > 0:
                                    success_message = text
                                    break
                            if success_message:
                                break

                        # Fallback: Extract heading
                        heading = None
                        if not success_message:
                            for tag in ['h1', 'h2', 'h3']:
                                h_element = soup.find(tag)
                                if h_element:
                                    heading = h_element.get_text(strip=True)
                                    break

                        # Fallback: Page title
                        page_title = None
                        if not success_message and not heading:
                            title_element = soup.find('title')
                            if title_element:
                                page_title = title_element.get_text(strip=True)

                        # Store verification pattern (first non-empty)
                        run.pattern = choose_verify_pattern([success_message, heading, page_title], final_page_html, None)
                        if run.pattern:
                            logger.info(f"[Manual Recording {run_id}] Detected verification pattern: {run.pattern[:50]}...")

                    except Exception as e:
                        logger.warning(f"[Manual Recording {run_id}] Failed to extract verification pattern: {e}")
                        run.pattern = None

                    # Get cookies from browser context (Playwright format includes expiry)
                    cookies = await context.cookies()
                    logger.info(f"[Manual Recording {run_id}] Extracted {len(cookies)} cookies")

                    # Build security context with full cookie analysis
                    cookie_metadata_list = []
                    for cookie in cookies:
                        # Convert Playwright cookie to format compatible with extract_cookie_metadata
                        # Playwright uses "expires" (Unix timestamp), Selenium uses "expiry"
                        cookie_dict = {
                            "name": cookie.get("name"),
                            "value": cookie.get("value"),
                            "domain": cookie.get("domain"),
                            "path": cookie.get("path", "/"),
                            "secure": cookie.get("secure", False),
                            "httpOnly": cookie.get("httpOnly", False),
                            "sameSite": cookie.get("sameSite", "None"),
                            "expiry": cookie.get("expires"),  # Playwright uses "expires", rename to "expiry"
                        }

                        # Use existing function to calculate TTL, entropy, security score
                        cookie_meta = extract_cookie_metadata(cookie_dict)
                        cookie_metadata_list.append(cookie_meta)

                    # Calculate overall security score
                    security_score, security_issues = analyze_cookie_security(cookie_metadata_list)

                    # Build security_context in proper format (matching SecurityContext schema)
                    run.security_context = {
                        "cookies": {
                            "total_count": len(cookie_metadata_list),
                            "session_count": len([c for c in cookie_metadata_list if c.is_session]),
                            "persistent_count": len([c for c in cookie_metadata_list if c.is_persistent]),
                            "secure_count": len([c for c in cookie_metadata_list if c.secure]),
                            "http_only_count": len([c for c in cookie_metadata_list if c.http_only]),
                            "same_site_none_count": len([c for c in cookie_metadata_list if c.same_site and c.same_site.value == "None"]),
                            "total_size_bytes": sum(c.size_bytes for c in cookie_metadata_list),
                            "security_score": security_score,
                            "issues": security_issues,
                            "cookies": [
                                {
                                    "name": c.name,
                                    "value_encrypted": c.value_encrypted,  # Plaintext for now, will encrypt below
                                    "value_hash": c.value_hash,
                                    "domain": c.domain,
                                    "path": c.path,
                                    "expires": c.expires,
                                    "expires_at": c.expires,  # UI expects expires_at for display
                                    "ttl_seconds": c.ttl_seconds,
                                    "http_only": c.http_only,
                                    "secure": c.secure,
                                    "same_site": c.same_site.value if c.same_site else None,
                                    "size_bytes": c.size_bytes,
                                    "is_session": c.is_session,
                                    "is_persistent": c.is_persistent,
                                    "entropy": c.entropy_score,  # UI expects "entropy" not "entropy_score"
                                    "entropy_score": c.entropy_score,  # Include both for compatibility
                                    "captured_at": c.captured_at.isoformat(),
                                    "security_issues": c.security_issues,
                                }
                                for c in cookie_metadata_list
                            ],
                        },
                        # Add minimal security_headers structure (ResponseHeaders schema)
                        "security_headers": {
                            "security": {
                                "security_score": 0.0,
                                "issues": ["Security header analysis not available for manual recording"],
                                "missing_headers": ["hsts", "csp", "x-frame-options", "x-content-type-options"]
                            },
                            "server": None,
                            "x_powered_by": None,
                            "framework_hints": [],
                            "raw": {}
                        },
                        # Calculate overall security score (40% cookies, 60% headers)
                        "overall_security_score": (security_score * 0.4),  # Only cookies for now, headers = 0
                        # Required: timestamp when extracted
                        "extracted_at": datetime.now(timezone.utc).isoformat(),
                        "extraction_version": "manual-recording-v1.0"
                    }

                    # Encrypt cookie values using profile cipher
                    _encrypt_security_context_cookies(run.security_context, _run_cookie_cipher(db, run))

                    # Store captured cookies encrypted (owner key, or master key).
                    _raw_cookies = [
                        {
                            "name": c.name,
                            "value": c.value_encrypted,  # cookie values already encrypted by _encrypt_security_context_cookies above
                            "domain": c.domain,
                            "path": c.path,
                            "secure": c.secure,
                            "httpOnly": c.http_only,
                            "sameSite": c.same_site.value if c.same_site else "None",
                        }
                        for c in cookie_metadata_list
                    ]
                    run.session_cookies_enc = encrypt_run_cookies(db, run, _raw_cookies)
                    run.session_cookies = []

                    # Take final screenshot
                    screenshot_bytes = await page.screenshot(full_page=True)
                    logger.info(f"[Manual Recording {run_id}] Captured screenshot ({len(screenshot_bytes)} bytes)")

                    # Save screenshot artifact
                    screenshot_name = f"manual-recording-final.png"
                    screenshot_path = storage.save_bytes(run_id, screenshot_name, screenshot_bytes)
                    screenshot_artifact = Artifact(
                        id=f"{run_id}-MANUAL-SCREENSHOT",
                        run_id=run_id,
                        name=screenshot_name,
                        description="Final screenshot captured at end of manual recording session",
                        type=ArtifactType.screenshot.value,
                        size_bytes=len(screenshot_bytes),
                        storage_path=screenshot_path,
                        download_url=None,
                        created_at=datetime.now(timezone.utc),
                        is_encrypted=False,
                    )
                    db.add(screenshot_artifact)
                    artifacts_created.append("screenshot")

                    # Save per-navigation step screenshots (pre-login, post-login, MFA pages, etc.)
                    for _si, (_slabel, _surl, _sdata) in enumerate(step_screenshots):
                        try:
                            _sname = f"manual-{_slabel}.png"
                            _spath = storage.save_bytes(run_id, _sname, _sdata)
                            db.add(Artifact(
                                id=f"{run_id}-MANUAL-STEP-{_si + 1}",
                                run_id=run_id,
                                name=_sname,
                                description=f"Step {_si + 1} screenshot at {_surl}",
                                type=ArtifactType.screenshot.value,
                                size_bytes=len(_sdata),
                                storage_path=_spath,
                                download_url=None,
                                created_at=datetime.now(timezone.utc),
                                is_encrypted=False,
                            ))
                        except Exception as _se:
                            logger.warning(f"[Manual Recording {run_id}] Failed to save step screenshot {_si + 1}: {_se}")
                    if step_screenshots:
                        artifacts_created.append(f"{len(step_screenshots)}-step-screenshots")

                    # Generate sitemap from final page HTML
                    try:
                        sitemap_bytes = _build_sitemap_document(run.final_url, final_page_html)
                        sitemap_name = "sitemap.xml"
                        sitemap_path = storage.save_bytes(run_id, sitemap_name, sitemap_bytes)
                        sitemap_artifact = Artifact(
                            id=f"{run_id}-MANUAL-SITEMAP",
                            run_id=run_id,
                            name=sitemap_name,
                            description="XML sitemap of discovered URLs from authenticated page",
                            type=ArtifactType.sitemap.value,
                            size_bytes=len(sitemap_bytes),
                            storage_path=sitemap_path,
                            download_url=None,
                            created_at=datetime.now(timezone.utc),
                            is_encrypted=False,
                        )
                        db.add(sitemap_artifact)
                        artifacts_created.append("sitemap")

                        # Count discovered URLs for logging
                        url_count = sitemap_bytes.decode('utf-8').count('<loc>')
                        logger.info(f"[Manual Recording {run_id}] Generated sitemap with {url_count} URLs")
                    except Exception as e:
                        logger.warning(f"[Manual Recording {run_id}] Sitemap generation failed: {e}")

                    # Generate Selenium .side file from recorded interactions
                    # NOTE: .side file contains ACTUAL credentials (not placeholders) because:
                    # - Tenable WAVS uploads .side files and replays them exactly as recorded
                    # - No variable substitution occurs - credentials must be embedded
                    # - This matches how automated runs store .side files
                    if recorded_actions and len(recorded_actions) > 0:
                        try:
                            side_document = _build_side_from_recorded_actions(
                                run_id,
                                target_url,
                                recorded_actions,
                                run.pattern,
                                final_url=run.final_url,
                            )
                            side_name = "manual-recording.side"
                            side_bytes = json.dumps(side_document, indent=2).encode('utf-8')
                            side_path = storage.save_bytes(run_id, side_name, side_bytes)
                            side_artifact = Artifact(
                                id=f"{run_id}-MANUAL-SIDE",
                                run_id=run_id,
                                name=side_name,
                                description="Selenium IDE recording of manual authentication flow (contains credentials)",
                                type=ArtifactType.side_file.value,
                                size_bytes=len(side_bytes),
                                storage_path=side_path,
                                download_url=None,
                                created_at=datetime.now(timezone.utc),
                                is_encrypted=False,  # Plaintext for Tenable WAVS compatibility
                            )
                            db.add(side_artifact)
                            artifacts_created.append("side-file")
                            logger.info(f"[Manual Recording {run_id}] Generated .side file with {len(recorded_actions)} actions")
                        except Exception as e:
                            logger.warning(f"[Manual Recording {run_id}] .side file generation failed: {e}")
                    else:
                        logger.warning(f"[Manual Recording {run_id}] No interactions recorded, skipping .side file generation")

                except Exception as e:
                    logger.error(f"[Manual Recording {run_id}] Failed to extract artifacts: {e}", exc_info=True)
                    db.rollback()

                # Close browser and context to flush HAR file
                logger.info(f"[Manual Recording {run_id}] Closing browser to flush HAR file")
                await context.close()
                await browser.close()

                # Now process HAR file after context is closed
                try:
                    har_file_path = f"/tmp/manual-{run_id}.har"
                    try:
                        with open(har_file_path, 'rb') as f:
                            har_bytes = f.read()
                        logger.info(f"[Manual Recording {run_id}] Read HAR file ({len(har_bytes)} bytes)")

                        # Save HAR artifact
                        har_name = "manual-recording.har"
                        har_storage_path = storage.save_bytes(run_id, har_name, har_bytes)
                        har_artifact = Artifact(
                            id=f"{run_id}-MANUAL-HAR",
                            run_id=run_id,
                            name=har_name,
                            description="HAR file captured during manual recording session",
                            type=ArtifactType.har.value,
                            size_bytes=len(har_bytes),
                            storage_path=har_storage_path,
                            download_url=None,
                            created_at=datetime.now(timezone.utc),
                            is_encrypted=False,
                        )
                        db.add(har_artifact)
                        artifacts_created.append("HAR")

                        # Analyze HAR for bearer tokens
                        from app.services.har_analyzer import analyze_har
                        har_insight = analyze_har(har_bytes)
                        if har_insight and har_insight.auth_headers:
                            bearer_tokens = [
                                h for h in har_insight.auth_headers
                                if h.get('header_type') == 'authorization' and 'bearer' in h.get('value', '').lower()
                            ]
                            if bearer_tokens:
                                logger.info(f"[Manual Recording {run_id}] Detected {len(bearer_tokens)} bearer tokens in HAR")
                            artifacts_created.append("HAR-analysis")

                        # Scan JavaScript files for secrets (post-auth)
                        try:
                            from app.services.js_secret_scanner import scan_javascript_secrets
                            js_secrets_result = scan_javascript_secrets(har_bytes, pre_auth=False)

                            # Add to security_context
                            if run.security_context:
                                run.security_context["js_secrets"] = js_secrets_result

                                # Log findings if any
                                total_findings = js_secrets_result.get("total_findings", 0)
                                if total_findings > 0:
                                    critical = js_secrets_result.get("critical_count", 0)
                                    high = js_secrets_result.get("high_count", 0)
                                    logger.warning(
                                        f"[Manual Recording {run_id}] JS Secrets: {total_findings} findings "
                                        f"({critical} critical, {high} high)"
                                    )
                                else:
                                    logger.info(f"[Manual Recording {run_id}] JS Secrets: No secrets detected")

                                artifacts_created.append("js-secrets")
                        except Exception as e:
                            logger.warning(f"[Manual Recording {run_id}] JS secrets scanning failed: {e}")

                        # Tech fingerprinting (detect frameworks, CMS, libraries)
                        try:
                            cookie_names = [c.name for c in cookie_metadata_list]
                            run.tech_fingerprint = analyze_tech_fingerprint(
                                run.target_url,
                                html_samples=[final_page_html],
                                cookies=cookie_names,
                                timeout=3.0
                            )
                            if run.tech_fingerprint:
                                frameworks = run.tech_fingerprint.get("js_frameworks", [])
                                cms = run.tech_fingerprint.get("cms", [])
                                if frameworks or cms:
                                    logger.info(f"[Manual Recording {run_id}] Tech fingerprint: {frameworks + cms}")
                                artifacts_created.append("tech-fingerprint")
                        except Exception as e:
                            logger.warning(f"[Manual Recording {run_id}] Tech fingerprinting failed: {e}")

                        # Generate flow summary (narrative description)
                        try:
                            run_data = {
                                "id": run_id,
                                "target_url": run.target_url,
                                "final_url": run.final_url,
                                "auth_type": "manual_recording",
                                "pattern": run.pattern,
                                "security_context": run.security_context,
                                "tech_fingerprint": run.tech_fingerprint,
                            }
                            run.flow_summary = generate_flow_summary(
                                run_data,
                                har_bytes=har_bytes,
                                har_insight=har_insight
                            )
                            if run.flow_summary:
                                logger.info(f"[Manual Recording {run_id}] Generated flow summary ({len(run.flow_summary)} chars)")
                                artifacts_created.append("flow-summary")
                        except Exception as e:
                            logger.warning(f"[Manual Recording {run_id}] Flow summary generation failed: {e}")

                        # Set authentication type
                        run.auth_type = "manual_recording"

                        # Generate DAST export files for security scanners
                        try:
                            # 1. curl script export
                            try:
                                curl_script = _generate_manual_curl_script(
                                    run.final_url,
                                    cookies,
                                    run.target_url
                                )
                                curl_name = "curl-authenticated.sh"
                                curl_bytes = curl_script.encode('utf-8')
                                curl_path = storage.save_bytes(run_id, curl_name, curl_bytes)
                                curl_artifact = Artifact(
                                    id=f"{run_id}-MANUAL-CURL",
                                    run_id=run_id,
                                    name=curl_name,
                                    description="Bash script with curl command for authenticated requests",
                                    type="export_curl",
                                    size_bytes=len(curl_bytes),
                                    storage_path=curl_path,
                                    download_url=None,
                                    created_at=datetime.now(timezone.utc),
                                    is_encrypted=False,
                                )
                                db.add(curl_artifact)
                                artifacts_created.append("curl-script")
                                logger.info(f"[Manual Recording {run_id}] Generated curl script")
                            except Exception as e:
                                logger.warning(f"[Manual Recording {run_id}] curl script generation failed: {e}")

                            # 2. Burp HTTP request export
                            try:
                                burp_request = _generate_manual_burp_request(
                                    run.final_url,
                                    cookies
                                )
                                burp_name = "burp-request.txt"
                                burp_bytes = burp_request.encode('utf-8')
                                burp_path = storage.save_bytes(run_id, burp_name, burp_bytes)
                                burp_artifact = Artifact(
                                    id=f"{run_id}-MANUAL-BURP",
                                    run_id=run_id,
                                    name=burp_name,
                                    description="Raw HTTP request for Burp Suite Repeater/Intruder",
                                    type="export_burp",
                                    size_bytes=len(burp_bytes),
                                    storage_path=burp_path,
                                    download_url=None,
                                    created_at=datetime.now(timezone.utc),
                                    is_encrypted=False,
                                )
                                db.add(burp_artifact)
                                artifacts_created.append("burp-request")
                                logger.info(f"[Manual Recording {run_id}] Generated Burp request")
                            except Exception as e:
                                logger.warning(f"[Manual Recording {run_id}] Burp request generation failed: {e}")

                            # 3. Postman collection export
                            try:
                                postman_collection = _generate_manual_postman_collection(
                                    run.final_url,
                                    cookies,
                                    run.target_url
                                )
                                postman_name = "postman-collection.json"
                                postman_bytes = json.dumps(postman_collection, indent=2).encode('utf-8')
                                postman_path = storage.save_bytes(run_id, postman_name, postman_bytes)
                                postman_artifact = Artifact(
                                    id=f"{run_id}-MANUAL-POSTMAN",
                                    run_id=run_id,
                                    name=postman_name,
                                    description="Postman collection with authenticated requests",
                                    type="export_postman",
                                    size_bytes=len(postman_bytes),
                                    storage_path=postman_path,
                                    download_url=None,
                                    created_at=datetime.now(timezone.utc),
                                    is_encrypted=False,
                                )
                                db.add(postman_artifact)
                                artifacts_created.append("postman-collection")
                                logger.info(f"[Manual Recording {run_id}] Generated Postman collection")
                            except Exception as e:
                                logger.warning(f"[Manual Recording {run_id}] Postman collection generation failed: {e}")

                            # 4. ZAP context export
                            try:
                                zap_context = _generate_manual_zap_context(
                                    run.final_url,
                                    cookies,
                                    run.target_url
                                )
                                zap_name = "zap-context.xml"
                                zap_bytes = zap_context.encode('utf-8')
                                zap_path = storage.save_bytes(run_id, zap_name, zap_bytes)
                                zap_artifact = Artifact(
                                    id=f"{run_id}-MANUAL-ZAP",
                                    run_id=run_id,
                                    name=zap_name,
                                    description="OWASP ZAP context with session tokens",
                                    type="export_zap",
                                    size_bytes=len(zap_bytes),
                                    storage_path=zap_path,
                                    download_url=None,
                                    created_at=datetime.now(timezone.utc),
                                    is_encrypted=False,
                                )
                                db.add(zap_artifact)
                                artifacts_created.append("zap-context")
                                logger.info(f"[Manual Recording {run_id}] Generated ZAP context")
                            except Exception as e:
                                logger.warning(f"[Manual Recording {run_id}] ZAP context generation failed: {e}")

                        except Exception as e:
                            logger.warning(f"[Manual Recording {run_id}] DAST export generation failed: {e}")

                    except FileNotFoundError:
                        logger.warning(f"[Manual Recording {run_id}] HAR file not found at {har_file_path}")
                    except Exception as e:
                        logger.error(f"[Manual Recording {run_id}] Failed to process HAR file: {e}", exc_info=True)

                    # Add timeline event
                    db.add(
                        TimelineEvent(
                            run_id=run_id,
                            occurred_at=datetime.now(timezone.utc),
                            message=f"Extracted artifacts: {', '.join(artifacts_created)} ({len(cookies)} cookies)",
                        )
                    )
                    db.commit()

                    logger.info(f"[Manual Recording {run_id}] Successfully extracted and saved artifacts: {artifacts_created}")

                except Exception as e:
                    logger.error(f"[Manual Recording {run_id}] Failed to process HAR file after context close: {e}", exc_info=True)
                    db.rollback()

        except Exception as e:
            logger.error(f"[Manual Recording {run_id}] Browser error: {e}", exc_info=True)
        finally:
            logger.info(f"[Manual Recording {run_id}] Closing live view")
            stream_stack.close()
            get_artifact_storage().release_run(run_id)
            _remove_temp_hars(run_id)
            db.close()

    # Run the async function
    asyncio.run(_run_session())
