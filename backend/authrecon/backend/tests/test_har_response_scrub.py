"""Known passwords are scrubbed from HAR response bodies, in every encoding."""
from __future__ import annotations

import base64
import html
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, quote_plus

import pytest

from app.models import Artifact
from app.services import artifact_crypto as ac
from app.services.har_redaction import REDACTED, mask_har, mask_har_bytes

SECRET = "SuperSecretPassword!"  # the-internet.herokuapp.com/login prints this on the page


def _har(*entries):
    return {"log": {"version": "1.2", "entries": list(entries)}}


def _entry(text, *, mime="text/html", encoding=None, request=None):
    content = {"mimeType": mime, "text": text, "size": len(text.encode())}
    if encoding:
        content["encoding"] = encoding
    return {"request": request or {"method": "GET", "url": "https://t.invalid/login", "headers": []},
            "response": {"status": 200, "content": content}}


def _content(har, i=0):
    return har["log"]["entries"][i]["response"]["content"]


@pytest.mark.parametrize(
    "form",
    [
        SECRET,
        quote(SECRET, safe=""),                 # SuperSecretPassword%21
        quote(SECRET, safe="").lower(),
        quote_plus(SECRET),
        html.escape(SECRET),                     # unchanged for "!", covered by plain
        "SuperSecretPassword&#33;",              # decimal entity
        "SuperSecretPassword&#x21;",             # hex entity
        "SuperSecretPassword&excl;",             # HTML5 named entity
        json.dumps(SECRET)[1:-1],
    ],
)
def test_text_response_forms_are_scrubbed(form):
    page = f"<p>Enter tomsmith and <em>{form}</em> for the password.</p>"
    har = mask_har(_har(_entry(page)), known_secrets=[SECRET])
    out = _content(har)["text"]
    assert form not in out and SECRET not in out and REDACTED in out
    assert "tomsmith" in out and _content(har)["size"] == len(out.encode())


def test_entity_forms_for_html_special_characters():
    secret = 'p@ss<&>"word'
    page = f"value={html.escape(secret)} also {''.join(c if c.isalnum() else f'&#{ord(c)};' for c in secret)}"
    out = _content(mask_har(_har(_entry(page)), known_secrets=[secret]))["text"]
    assert "p@ss" not in out and "&#64;" not in out and out.count(REDACTED) == 2


def test_base64_body_is_decoded_scrubbed_reencoded_and_sized():
    body = f"<html><em>{SECRET}</em> and {quote(SECRET, safe='')}</html>".encode()
    har = mask_har(_har(_entry(base64.b64encode(body).decode(), encoding="base64")), known_secrets=[SECRET])
    content = _content(har)
    decoded = base64.b64decode(content["text"])
    assert SECRET.encode() not in decoded and b"%21" not in decoded and REDACTED.encode() in decoded
    assert content["size"] == len(decoded) and content["encoding"] == "base64"


def test_binary_base64_content_is_left_alone():
    png = b"\x89PNG\r\n\x1a\n\x00\x00" + SECRET.encode()  # not valid UTF-8 text
    blob = base64.b64encode(png).decode()
    har = mask_har(_har(_entry(blob, mime="image/png", encoding="base64"),
                        _entry(base64.b64encode(b"\xff\xfe" + SECRET.encode()).decode(), mime="text/plain", encoding="base64")),
                   known_secrets=[SECRET])
    assert _content(har, 0)["text"] == blob
    assert base64.b64decode(_content(har, 1)["text"]).startswith(b"\xff\xfe")  # not text after decoding


def test_body_without_password_is_byte_identical():
    plain = _entry("<p>Welcome back</p>")
    b64 = _entry(base64.b64encode(b"<p>nothing secret</p>").decode(), encoding="base64")
    data = json.dumps(_har(plain, b64), indent=1).encode()  # non-canonical formatting on purpose
    assert mask_har_bytes(data, known_secrets=[SECRET]) is data


def test_password_typed_in_the_request_is_scrubbed_from_responses():
    """Manual recordings: no stored credential, but the HAR itself submitted it."""
    login = {"method": "POST", "url": "https://t.invalid/authenticate", "headers": [],
             "postData": {"mimeType": "application/x-www-form-urlencoded",
                          "params": [{"name": "username", "value": "tomsmith"}, {"name": "password", "value": SECRET}],
                          "text": f"username=tomsmith&password={quote_plus(SECRET)}"}}
    har = mask_har(_har(_entry(f"<em>{SECRET}</em>"), _entry("ok", request=login)))
    assert SECRET not in json.dumps(har)
    assert REDACTED in _content(har, 0)["text"]


def test_short_pin_values_are_not_harvested():
    req = {"method": "POST", "url": "https://t.invalid/mfa", "headers": [],
           "postData": {"params": [{"name": "pin", "value": "2024"}, {"name": "otp", "value": "123456"}]}}
    har = mask_har(_har(_entry("Copyright 2024, order 123456"), _entry("ok", request=req)))
    assert _content(har, 0)["text"] == "Copyright 2024, order 123456"


# --- legacy read-time masking uses the run's own passwords --------------------


def _one_time_secret(secret):
    from app.core.security import get_credential_cipher

    return get_credential_cipher().encrypt(secret.encode()).decode()


def test_legacy_plaintext_har_read_scrubs_response_bodies(db_session, artifact_storage, make_run):
    run, _ = make_run()
    run.options = {"one_time_secret": _one_time_secret(SECRET)}
    db_session.commit()
    (artifact_storage.base_path / run.id).mkdir(parents=True)
    har = _har(_entry(f"<em>{SECRET}</em>"),
               _entry(base64.b64encode(f"err: {SECRET}".encode()).decode(), mime="text/plain", encoding="base64"))
    (artifact_storage.base_path / run.id / "old.har").write_text(json.dumps(har))
    art = Artifact(id=str(uuid.uuid4())[:40], run_id=run.id, name="old.har", type="har", size_bytes=0,
                   storage_path=f"{run.id}/old.har", created_at=datetime.now(timezone.utc))
    db_session.add(art)
    db_session.commit()

    out = json.loads(ac.read_artifact_bytes(db_session, run, art, artifact_storage))
    assert SECRET not in json.dumps(out)
    assert SECRET.encode() not in base64.b64decode(out["log"]["entries"][1]["response"]["content"]["text"])


def test_known_secrets_for_run_covers_all_sources(db_session, make_run):
    from app.services.credentials import create_credential
    from app.services.run_secrets import known_secrets_for_run

    run, profile = make_run()
    run.options = {
        "one_time_secret": _one_time_secret("one-time-pw"),
        "scope": {"roles": [{"username": "a", "secret": _one_time_secret("role-pw-1")}, {"username": "b"}]},
    }
    from app.schemas.credential import CredentialCreate

    cred = create_credential(db_session, owner=profile,
                             payload=CredentialCreate(name="x", username="u", secret="stored-pw"))
    run.options = {**run.options, "credential_id": cred.id}
    db_session.commit()
    assert set(known_secrets_for_run(db_session, run)) == {"stored-pw", "one-time-pw", "role-pw-1"}
