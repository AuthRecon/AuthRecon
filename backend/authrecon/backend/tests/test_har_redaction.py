"""Password values are masked in HARs; structure and other fields survive."""
from __future__ import annotations

import base64
import json

from app.services.har_redaction import REDACTED, is_secret_field, mask_har, mask_har_bytes

SECRET = "Sup3r-Secret!pw"


def _har(request=None, response=None):
    return {"log": {"version": "1.2", "entries": [{"request": request or {}, "response": response or {}}]}}


def test_form_params_and_text_are_masked():
    har = mask_har(_har({
        "url": "https://t.invalid/login",
        "headers": [],
        "postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [{"name": "username", "value": "alice"}, {"name": "password", "value": SECRET}],
            "text": f"username=alice&password={SECRET}&remember=1",
        },
    }))
    post = har["log"]["entries"][0]["request"]["postData"]
    assert post["params"] == [{"name": "username", "value": "alice"}, {"name": "password", "value": REDACTED}]
    assert "password=%5BREDACTED%5D" in post["text"] or f"password={REDACTED}" in post["text"]
    assert "username=alice" in post["text"] and SECRET not in post["text"]


def test_json_body_nested_password_masked():
    body = {"user": {"email": "a@example.invalid", "password": SECRET}, "client_secret": "abc123456"}
    har = mask_har(_har({"url": "https://t.invalid/api", "postData": {"mimeType": "application/json", "text": json.dumps(body)}}))
    masked = json.loads(har["log"]["entries"][0]["request"]["postData"]["text"])
    assert masked["user"] == {"email": "a@example.invalid", "password": REDACTED}
    assert masked["client_secret"] == REDACTED


def test_multipart_password_part_masked():
    text = (
        "--B\r\nContent-Disposition: form-data; name=\"login\"\r\n\r\nalice\r\n"
        f"--B\r\nContent-Disposition: form-data; name=\"passwd\"\r\n\r\n{SECRET}\r\n--B--\r\n"
    )
    har = mask_har(_har({"url": "https://t.invalid/x", "postData": {"mimeType": "multipart/form-data; boundary=B", "text": text}}))
    out = har["log"]["entries"][0]["request"]["postData"]["text"]
    assert SECRET not in out and REDACTED in out and "alice" in out


def test_query_string_url_and_userinfo_masked():
    har = mask_har(_har({
        "url": f"https://alice:{SECRET}@t.invalid/cb?user=alice&pwd={SECRET}",
        "queryString": [{"name": "user", "value": "alice"}, {"name": "pwd", "value": SECRET}],
        "headers": [],
    }))
    req = har["log"]["entries"][0]["request"]
    assert SECRET not in req["url"] and "alice:" in req["url"] and "user=alice" in req["url"]
    assert req["queryString"][1]["value"] == REDACTED and req["queryString"][0]["value"] == "alice"


def test_basic_auth_header_masked_but_bearer_kept():
    basic = base64.b64encode(f"alice:{SECRET}".encode()).decode()
    har = mask_har(_har({"url": "https://t.invalid/", "headers": [
        {"name": "Authorization", "value": f"Basic {basic}"},
        {"name": "X-Other", "value": "Bearer keep-me"},
    ]}))
    headers = har["log"]["entries"][0]["request"]["headers"]
    assert headers[0]["value"] == f"Basic {REDACTED}" and headers[1]["value"] == "Bearer keep-me"


def test_known_secret_masked_everywhere_including_encoded_forms():
    har = _har(
        {"url": "https://t.invalid/", "postData": {"mimeType": "text/plain", "text": f"opaque:{SECRET}"}},
        {"content": {"text": f'echo {json.dumps(SECRET)} and {SECRET.replace("!", "%21")}'}},
    )
    out = json.dumps(mask_har(har, known_secrets=[SECRET]))
    assert SECRET not in out and "Sup3r-Secret%21pw" not in out


def test_non_secret_fields_untouched():
    for name in ("username", "email", "passenger", "compass", "spinner", "csrf_token"):
        assert not is_secret_field(name), name
    for name in ("password", "Passwd", "user[password]", "j_password", "new-password", "pass", "pwd", "client_secret", "otp"):
        assert is_secret_field(name), name


def test_bytes_round_trip_idempotent_and_invalid_json():
    data = json.dumps(_har({"url": "https://t.invalid/", "postData": {"params": [{"name": "password", "value": SECRET}]}})).encode()
    once = mask_har_bytes(data)
    assert SECRET.encode() not in once and mask_har_bytes(once) == once
    assert SECRET.encode() not in mask_har_bytes(b"not json " + SECRET.encode(), known_secrets=[SECRET])
