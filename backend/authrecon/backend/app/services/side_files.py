from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse, urljoin

from app.core.urls import stable_page_url
from app.services.automation import FormAuthResult


def _first_non_empty(*candidates: Iterable[str | None] | str | None) -> str | None:
    for candidate in candidates:
        if isinstance(candidate, str):
            if candidate.strip():
                return candidate.strip()
        elif isinstance(candidate, Iterable):
            for item in candidate:
                if isinstance(item, str) and item.strip():
                    return item.strip()
    return None


def _normalize_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme:
        return None
    return url


def _resolve_relative(base_url: str | None, relative_url: str | None) -> str | None:
    if not relative_url:
        return None
    if relative_url.startswith("http://") or relative_url.startswith("https://"):
        return relative_url
    if base_url:
        try:
            return urljoin(base_url, relative_url)
        except Exception:  # pragma: no cover - defensive
            return None
    return None


def build_side_file(
    target_url: str,
    result: FormAuthResult,
    username: str,
    password: str,
) -> bytes:
    """
    Build a Selenium IDE .side file compatible with Tenable WAS scanners.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    login_url = _normalize_url(target_url) or "about:blank"
    final_url = _normalize_url(result.final_url) or _resolve_relative(login_url, result.final_url) or login_url

    actions = list(getattr(result, "recorded_actions", []) or [])

    if actions:
        commands = _commands_from_recorded_actions(actions, username, password, login_url)
    else:
        # Fallback path when no recorded actions available
        username_selector = result.username_selector or "xpath=//input[@type='text' or @type='email']"
        password_selector = result.password_selector or "xpath=//input[@type='password']"
        submit_selector = result.submit_selector
        submit_method = (result.submit_method or "").lower()

        # Tenable WAS expects actual credentials inline in .side file (not placeholders)
        commands = [
            {"command": "open", "target": login_url, "value": ""},
            {"command": "pause", "target": "2000", "value": ""},
            {"command": "waitForElementVisible", "target": username_selector, "value": "15000"},
            {"command": "type", "target": username_selector, "value": username},
            {"command": "waitForElementVisible", "target": password_selector, "value": "15000"},
            {"command": "type", "target": password_selector, "value": password},
        ]

        if submit_method == "click" and submit_selector:
            commands.extend(
                [
                    {"command": "waitForElementVisible", "target": submit_selector, "value": "15000"},
                    {"command": "click", "target": submit_selector, "value": ""},
                ]
            )
        else:
            commands.append({"command": "sendKeys", "target": password_selector, "value": "${KEY_ENTER}"})

        commands.append({"command": "pause", "target": "6000", "value": ""})


    side_document = {
        "id": f"form-auth-{timestamp}",
        "version": "2.0",
        "name": "Form Authentication",
        "url": login_url,
        "tests": [
            {
                "id": f"test-form-{timestamp}",
                "name": "Login Test",
                "commands": commands,
            }
        ],
        "suites": [
            {
                "id": f"suite-form-{timestamp}",
                "name": "Login Suite",
                "tests": [f"test-form-{timestamp}"],
            }
        ],
        "plugins": [
            {
                "id": "login",
                "enabled": True,
                "config": {
                    "loginUrl": login_url,
                    "pageToVerify": stable_page_url(final_url),
                },
            }
        ],
        "urls": [login_url],
        "pluginsVersion": {},
    }

    # Removed pattern verification - .side files are now pure automation, no test assertions

    return json.dumps(side_document, indent=2).encode("utf-8")


def _commands_from_recorded_actions(actions: list, username: str, password: str, login_url: str) -> list[dict[str, str]]:
    commands: list[dict[str, str]] = [
        {"command": "open", "target": login_url, "value": ""},
        {"command": "pause", "target": "2000", "value": ""},
    ]

    # Filter out language toggle actions that confuse scanners like Tenable WAS
    # These actions cause the scanner to toggle languages back and forth unnecessarily
    EXCLUDED_SELECTORS = [
        "languageToggleLink",     # Portal language toggle
        "languageToggle",          # Generic language toggle
        "language-toggle",         # Kebab-case variant
        "language_toggle",         # Snake-case variant
    ]

    filtered_actions = []
    for action in actions:
        selector_str = str(action.selector or "").lower()
        # Skip language toggle interactions
        if any(excluded.lower() in selector_str for excluded in EXCLUDED_SELECTORS):
            continue
        filtered_actions.append(action)

    for action in filtered_actions:
        selector = action.selector or "css=body"
        action_type = (action.action or "").lower()

        def _materialize(value: str | None) -> str:
            # Tenable WAS expects actual credentials inline in .side file (not placeholders)
            # Replace ${USERNAME} and ${PASSWORD} with actual values for Tenable compatibility
            if value == "${USERNAME}":
                return username
            if value == "${PASSWORD}":
                return password
            return value or ""

        if action_type == "type":
            commands.append({"command": "waitForElementVisible", "target": selector, "value": "15000"})
            commands.append({"command": "type", "target": selector, "value": _materialize(action.value)})
        elif action_type == "click":
            commands.append({"command": "waitForElementVisible", "target": selector, "value": "15000"})
            commands.append({"command": "click", "target": selector, "value": ""})
        elif action_type == "send_keys":
            commands.append({"command": "waitForElementVisible", "target": selector, "value": "15000"})
            commands.append({"command": "sendKeys", "target": selector, "value": _materialize(action.value) or "${KEY_ENTER}"})
        elif action_type == "submit_form":
            commands.append({"command": "waitForElementVisible", "target": selector, "value": "15000"})
            commands.append({"command": "sendKeys", "target": selector, "value": "${KEY_ENTER}"})
        else:
            # Unhandled action; fallback to a short pause so the flow timing remains stable.
            commands.append({"command": "pause", "target": "1000", "value": ""})

    commands.append({"command": "pause", "target": "6000", "value": ""})
    return commands


def build_two_step_side_file(
    start_url: str,
    recorded_actions: list,
    username: str,
    password: str,
    final_url: str | None = None,
) -> bytes:
    """
    Build a Selenium IDE .side file for two-step authentication flows.

    Uses the same command builder as single-page forms so the output has what
    Tenable WAS needs: real credentials inline (not ${USERNAME} placeholders),
    a wait before every action, and the post-login URL as ``pageToVerify``.

    Args:
        start_url: Initial authentication URL
        recorded_actions: List of RecordedAction objects from automation
        username: Username/email used
        password: Password used
        final_url: Authenticated landing URL, for the login plugin's pageToVerify

    Returns:
        UTF-8 encoded JSON .side file content
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    login_url = _normalize_url(start_url) or "about:blank"
    verify_url = _normalize_url(final_url) or _resolve_relative(login_url, final_url)

    # The builder adds its own "open"; entry-point clicks are recorded with a
    # descriptive pseudo-selector ("// Login entrypoint: ...") a replay can't use.
    replayable = [
        action for action in recorded_actions
        if (getattr(action, "action", "") or "").lower() != "open"
        and not str(getattr(action, "selector", "") or "").startswith("// ")
    ]
    commands = _commands_from_recorded_actions(replayable, username, password, login_url)

    side_document = {
        "id": f"two-step-auth-{timestamp}",
        "version": "2.0",
        "name": "Two-Step Authentication",
        "url": login_url,
        "tests": [
            {
                "id": f"test-two-step-{timestamp}",
                "name": "Two-Step Login Test",
                "commands": commands,
            }
        ],
        "suites": [
            {
                "id": f"suite-two-step-{timestamp}",
                "name": "Two-Step Login Suite",
                "tests": [f"test-two-step-{timestamp}"],
            }
        ],
        "plugins": [
            {
                "id": "login",
                "enabled": True,
                "config": {
                    "loginUrl": login_url,
                    "pageToVerify": stable_page_url(verify_url) or login_url,
                    "loginType": "two_step_form",
                },
            }
        ],
        "urls": [login_url],
        "pluginsVersion": {},
    }

    return json.dumps(side_document, indent=2).encode("utf-8")
