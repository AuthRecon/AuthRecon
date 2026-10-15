"""Replay a generated .side file in a fresh browser, the way a scanner would,
and report whether it reaches the page it claims to verify.

This is the check that tells an operator, before they load the script into
Tenable WAS, whether it will actually log in. It runs the login once more
against the target (one more login attempt on the account).

``replay_side`` takes the driver as an argument so it can be tested without
a browser; ``verify_side_artifact`` (worker job) wires in Chrome, artifact
decryption and storing the result on the run.
"""
from __future__ import annotations

import json
import logging
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_WAIT_SECONDS = 20.0
MAX_PAUSE_SECONDS = 8.0
SETTLE_SECONDS = 2.0


def _locator(target: str) -> tuple[str, str]:
    from selenium.webdriver.common.by import By

    kind, sep, value = (target or "").partition("=")
    strategies = {"css": By.CSS_SELECTOR, "xpath": By.XPATH, "id": By.ID, "name": By.NAME,
                  "linkText": By.LINK_TEXT, "partialLinkText": By.PARTIAL_LINK_TEXT}
    if sep and kind in strategies:
        return strategies[kind], value
    if target.startswith("//"):
        return By.XPATH, target
    return By.CSS_SELECTOR, target


def _same_page(landed: str | None, expected: str | None) -> bool:
    if not landed or not expected:
        return False
    a, b = urlsplit(landed), urlsplit(expected)
    return (a.scheme, a.netloc.lower(), a.path.rstrip("/") or "/") == (b.scheme, b.netloc.lower(), b.path.rstrip("/") or "/")


def _describe(command: dict) -> str:
    # Never echo the value: for "type" commands it is the username or password.
    return f"{command.get('command')} {command.get('target', '')}".strip()


def replay_side(driver, side: dict, *, pattern: str | None = None, sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Run the first test's commands. Returns a result dict (no credential values)."""
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import Select, WebDriverWait

    tests = side.get("tests") or [{}]
    commands = tests[0].get("commands") or []
    plugins = side.get("plugins") or [{}]
    expected = ((plugins[0] or {}).get("config") or {}).get("pageToVerify")

    for index, command in enumerate(commands, start=1):
        name = command.get("command")
        target = command.get("target") or ""
        value = command.get("value") or ""
        try:
            if name == "open":
                driver.get(target)
            elif name == "pause":
                sleep(min(float(target or 0) / 1000, MAX_PAUSE_SECONDS))
            elif name == "waitForElementVisible":
                timeout = min(float(value or 15000) / 1000, MAX_WAIT_SECONDS)
                WebDriverWait(driver, timeout).until(EC.visibility_of_element_located(_locator(target)))
            elif name == "type":
                element = driver.find_element(*_locator(target))
                element.clear()
                element.send_keys(value)
            elif name == "click":
                driver.find_element(*_locator(target)).click()
            elif name == "sendKeys":
                driver.find_element(*_locator(target)).send_keys(Keys.ENTER if value == "${KEY_ENTER}" else value)
            elif name == "select":
                label = value.split("=", 1)[-1]
                Select(driver.find_element(*_locator(target))).select_by_visible_text(label)
            else:
                return {"status": "failed", "failed_step": index, "step": _describe(command),
                        "message": f"Unsupported command '{name}'", "expected_url": expected}
        except Exception as exc:  # the step that broke is the useful part
            message = (str(exc).strip().splitlines() or [type(exc).__name__])[0][:200] or type(exc).__name__
            return {"status": "failed", "failed_step": index, "step": _describe(command),
                    "message": message, "expected_url": expected, "landed_url": _current_url(driver)}

    sleep(SETTLE_SECONDS)
    landed = _current_url(driver)
    page_ok = _same_page(landed, expected) if expected else None
    text_ok = None
    if pattern:
        try:
            text_ok = pattern.strip() in (driver.find_element("tag name", "body").text or "")
        except Exception:
            text_ok = False
    passed = (page_ok is not False) and (text_ok is not False) and (page_ok or text_ok)
    message = "Replay reached the verification page." if passed else (
        "Replay finished but did not reach the verification page." if page_ok is False
        else "Replay finished but the success text was not on the page.")
    return {"status": "passed" if passed else "failed", "landed_url": landed, "expected_url": expected,
            "url_matched": page_ok, "pattern_found": text_ok, "steps": len(commands), "message": message}


def _current_url(driver) -> str | None:
    try:
        from app.core.urls import strip_userinfo

        return strip_userinfo(driver.current_url)
    except Exception:
        return None


def set_verification(run, artifact_id: str, result: dict) -> None:
    """Store a result under run.options['side_verification'] (reassigned so it persists)."""
    options = deepcopy(run.options) if isinstance(run.options, dict) else {}
    store = options.get("side_verification") if isinstance(options.get("side_verification"), dict) else {}
    store[artifact_id] = {**result, "checked_at": datetime.now(timezone.utc).isoformat()}
    options["side_verification"] = store
    run.options = options


def verify_side_artifact(run_id: str, artifact_id: str) -> None:
    """RQ job: replay one .side artifact and record the outcome on the run."""
    from app.db import SessionLocal
    from app.models import Artifact, Run, TimelineEvent
    from app.services.artifact_crypto import read_artifact_bytes
    from app.services.automation.browser import create_chrome_options, create_webdriver
    from app.services.storage import get_artifact_storage

    db = SessionLocal()
    driver = None
    try:
        run = db.get(Run, run_id)
        artifact = db.get(Artifact, artifact_id)
        if run is None or artifact is None or artifact.run_id != run_id or artifact.type != "side_file":
            return
        set_verification(run, artifact_id, {"status": "running"})
        db.commit()
        try:
            side = json.loads(read_artifact_bytes(db, run, artifact, get_artifact_storage()))
            driver = create_webdriver(create_chrome_options(headless=True))
            driver.set_page_load_timeout(45)
            result = replay_side(driver, side, pattern=run.pattern)
        except Exception as exc:
            logger.warning("Replay check failed to run for %s/%s: %s", run_id, artifact_id, exc)
            result = {"status": "error", "message": f"The replay could not run: {type(exc).__name__}"}
        run = db.get(Run, run_id)
        set_verification(run, artifact_id, result)
        outcome = {"passed": "passed", "failed": "failed", "error": "could not run"}[result["status"]]
        detail = f" at step {result['failed_step']} ({result['step']}): {result['message']}" if result.get("failed_step") else f": {result['message']}"
        db.add(TimelineEvent(run_id=run_id, occurred_at=datetime.now(timezone.utc),
                             message=f"Replay check of {artifact.name} {outcome}{detail}"))
        db.commit()
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        db.close()
