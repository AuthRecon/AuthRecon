"""The .side files are what operators load into Tenable WAS, so they must
replay as-is: real credentials inline, a wait before each action, valid
Selenium IDE commands, and the post-login URL as pageToVerify."""
from __future__ import annotations

import json

from app.services.automation.types import RecordedAction
from app.services.side_files import build_two_step_side_file

USER, PASSWORD = "user@example.test", "S3cret!pass"
VALID_COMMANDS = {"open", "pause", "waitForElementVisible", "type", "click", "sendKeys", "select", "check"}


def _two_step_side(**kw):
    actions = [
        RecordedAction(action="click", selector="// Login entrypoint: Staff", note="hint click"),
        RecordedAction(action="open", selector="https://app.test/login", note="nav"),
        RecordedAction(action="type", selector="css=[name='email']", value="${USERNAME}"),
        RecordedAction(action="click", selector="css=[type='submit']"),
        RecordedAction(action="type", selector="css=[name='password']", value="${PASSWORD}"),
        RecordedAction(action="send_keys", selector="css=[name='password']", value="${KEY_ENTER}"),
    ]
    raw = build_two_step_side_file("https://app.test/login", actions, USER, PASSWORD,
                                   final_url="https://app.test/home", **kw)
    return json.loads(raw)


def test_two_step_side_has_real_credentials_not_placeholders():
    doc = _two_step_side()
    text = json.dumps(doc)
    assert "${USERNAME}" not in text and "${PASSWORD}" not in text
    typed = [c["value"] for c in doc["tests"][0]["commands"] if c["command"] == "type"]
    assert typed == [USER, PASSWORD]


def test_two_step_side_replays_cleanly():
    commands = _two_step_side()["tests"][0]["commands"]
    assert commands[0] == {"command": "open", "target": "https://app.test/login", "value": ""}
    assert [c["command"] for c in commands].count("open") == 1
    assert {c["command"] for c in commands} <= VALID_COMMANDS
    assert not any(str(c["target"]).startswith("// ") for c in commands)
    for i, c in enumerate(commands):
        if c["command"] in ("type", "click", "sendKeys"):
            assert commands[i - 1] == {"command": "waitForElementVisible", "target": c["target"], "value": "15000"}


def test_two_step_side_sets_page_to_verify():
    config = _two_step_side()["plugins"][0]["config"]
    assert config["loginUrl"] == "https://app.test/login"
    assert config["pageToVerify"] == "https://app.test/home"
