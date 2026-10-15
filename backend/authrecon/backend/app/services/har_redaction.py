"""Mask password values in HAR captures before they are stored.

Covers the places a login password shows up in a HAR:
- form/JSON/multipart request bodies (``postData.params`` and ``postData.text``)
- query strings (``queryString`` and the request URL)
- URL userinfo (``https://user:pass@host``) and ``Authorization: Basic``
- any exact occurrence of a known secret, in any field, including response
  bodies (plain, URL-, HTML-entity-, JSON- and base64-encoded forms; base64
  ``content.text`` is decoded, scrubbed and re-encoded). Known secrets are the
  run's passwords plus any password the HAR's own requests submitted.

Only values are replaced (with ``[REDACTED]``); names, structure and other
fields are kept so the HAR stays useful. ``.side`` files are NOT masked: Tenable
needs the credentials, and those files are encrypted at rest instead.
"""
from __future__ import annotations

import base64
import copy
import html
import json
import logging
import re
from html.entities import codepoint2name
from typing import Any, Iterable
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

logger = logging.getLogger(__name__)

REDACTED = "[REDACTED]"

# Field names whose values are passwords/secrets. Matched case-insensitively
# against the whole name after stripping separators (so "user[password]",
# "j_password", "Passwd", "new-password" all match).
_SECRET_NAME_RE = re.compile(
    r"(pass(word|wd|phrase|code)?|pwd|secret|client_?secret|otp|totp|mfa_?code|pin)$",
    re.IGNORECASE,
)
_SECRET_NAME_CONTAINS = ("password", "passwd", "passphrase", "secret")


def is_secret_field(name: str | None) -> bool:
    if not name:
        return False
    lowered = name.lower()
    if any(token in lowered for token in _SECRET_NAME_CONTAINS):
        return True
    # Last segment of names like "user[pass]" / "login.pwd" / "j_password"
    last = re.split(r"[\[\]\.\-:]+", lowered.strip("[]"))
    last = [part for part in last if part]
    candidate = last[-1] if last else lowered
    candidate = candidate.split("_")[-1] if candidate.startswith(("j_", "user_", "login_")) else candidate
    return bool(_SECRET_NAME_RE.fullmatch(candidate))


def _mask_pairs(pairs: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], bool]:
    changed = False
    out = []
    for key, value in pairs:
        if is_secret_field(key) and value and value != REDACTED:
            out.append((key, REDACTED))
            changed = True
        else:
            out.append((key, value))
    return out, changed


def mask_query_string(query: str) -> str:
    if not query:
        return query
    pairs = parse_qsl(query, keep_blank_values=True)
    masked, changed = _mask_pairs(pairs)
    return urlencode(masked, safe="[]") if changed else query


def mask_url(url: str) -> str:
    if not url or not isinstance(url, str):
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        if ":" in userinfo:
            user = userinfo.split(":", 1)[0]
            netloc = f"{user}:{REDACTED}@{host}"
    query = mask_query_string(parts.query)
    if netloc == parts.netloc and query == parts.query:
        return url
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _mask_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (REDACTED if is_secret_field(k) and isinstance(v, (str, int, float)) and v != "" else _mask_json_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_mask_json_value(v) for v in value]
    return value


_MULTIPART_FIELD_RE = re.compile(
    r'(Content-Disposition:[^\r\n]*\bname="([^"]+)"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)(.*?)(\r?\n--)',
    re.IGNORECASE | re.DOTALL,
)


def mask_body_text(text: str, mime_type: str | None) -> str:
    if not text or not isinstance(text, str):
        return text
    mime = (mime_type or "").lower()
    stripped = text.lstrip()
    if "json" in mime or stripped.startswith(("{", "[")):
        try:
            return json.dumps(_mask_json_value(json.loads(text)), separators=(",", ":"))
        except (ValueError, TypeError):
            pass
    if "multipart/form-data" in mime:
        return _MULTIPART_FIELD_RE.sub(
            lambda m: m.group(1) + (REDACTED if is_secret_field(m.group(2)) else m.group(3)) + m.group(4),
            text,
        )
    if "x-www-form-urlencoded" in mime or ("=" in text and "\n" not in text.strip()):
        return mask_query_string(text)
    return text


def _mask_headers(headers: list[dict]) -> None:
    for header in headers or []:
        name = str(header.get("name", "")).lower()
        value = header.get("value")
        if not isinstance(value, str):
            continue
        if name in ("authorization", "proxy-authorization") and value.lower().startswith("basic "):
            header["value"] = f"Basic {REDACTED}"


def _replace_known(value: Any, needles: list[str]) -> Any:
    if isinstance(value, str):
        for needle in needles:
            if needle in value:
                value = value.replace(needle, REDACTED)
        return value
    if isinstance(value, dict):
        return {k: _replace_known(v, needles) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_known(v, needles) for v in value]
    return value


MIN_KNOWN_SECRET_LEN = 4  # shorter values are too likely to hit unrelated text
MIN_HARVESTED_LEN = 6
# Only password-type fields are harvested from requests (not otp/pin, whose
# short numeric values would over-mask unrelated numbers in responses).
_HARVEST_NAME_RE = re.compile(r"pass(word|wd|phrase)?|pwd|secret", re.IGNORECASE)


def _html_entity_forms(secret: str) -> set[str]:
    """Ways an HTML page can render ``secret``: named, decimal and hex entities."""
    forms = {html.escape(secret, quote=True), html.escape(secret, quote=False)}
    forms.add(html.escape(secret, quote=True).replace("&#x27;", "&#39;"))
    named, dec, hexa = [], [], []
    for ch in secret:
        if ch.isalnum():
            named.append(ch)
            dec.append(ch)
            hexa.append(ch)
            continue
        name = codepoint2name.get(ord(ch)) or _HTML5_PUNCT_NAMES.get(ch)
        named.append(f"&{name};" if name else ch)
        dec.append(f"&#{ord(ch)};")
        hexa.append(f"&#x{ord(ch):x};")
    forms.update({"".join(named), "".join(dec), "".join(hexa)})
    return forms


_HTML5_PUNCT_NAMES = {
    "!": "excl", "#": "num", "$": "dollar", "%": "percnt", "(": "lpar", ")": "rpar",
    "*": "ast", "+": "plus", ",": "comma", ".": "period", "/": "sol", ":": "colon",
    ";": "semi", "=": "equals", "?": "quest", "@": "commat", "[": "lsqb", "\\": "bsol",
    "]": "rsqb", "^": "Hat", "_": "lowbar", "`": "grave", "{": "lcub", "|": "verbar",
    "}": "rcub", "~": "tilde", "'": "apos",
}


def _known_secret_forms(secrets: Iterable[str | None]) -> list[str]:
    forms: set[str] = set()
    for secret in secrets:
        if not secret or len(secret) < MIN_KNOWN_SECRET_LEN:
            continue
        pct = quote(secret, safe="")
        forms.update({secret, pct, pct.lower(), quote_plus(secret), quote_plus(secret).lower()})
        forms.add(json.dumps(secret)[1:-1])
        forms.add(json.dumps(secret, ensure_ascii=True)[1:-1])
        forms.add(base64.b64encode(secret.encode()).decode())
        forms.update(_html_entity_forms(secret))
    forms.discard(REDACTED)
    # Longest first so an encoded form is replaced before a substring of it.
    return sorted((f for f in forms if f), key=len, reverse=True)


def _scrub_text(text: str, needles: list[str]) -> str:
    for needle in needles:
        if needle in text:
            text = text.replace(needle, REDACTED)
    return text


_BINARY_MIME_PREFIXES = ("image/", "audio/", "video/", "font/")
_BINARY_MIME_TYPES = ("application/octet-stream", "application/pdf", "application/zip", "application/wasm")


def _looks_binary(mime: str) -> bool:
    mime = (mime or "").lower()
    return mime.startswith(_BINARY_MIME_PREFIXES) or any(t in mime for t in _BINARY_MIME_TYPES)


def scrub_response_content(content: dict, needles: list[str]) -> bool:
    """Replace known secrets in ``response.content``; returns True if it changed.

    base64 bodies are decoded, scrubbed and re-encoded (``size`` updated).
    Bodies that are not text after decoding are left untouched.
    """
    text = content.get("text")
    if not needles or not isinstance(text, str) or not text:
        return False
    if (content.get("encoding") or "").lower() == "base64":
        if _looks_binary(content.get("mimeType")):
            return False
        try:
            raw = base64.b64decode(text, validate=True)
            decoded = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False  # binary or not really base64
        if "\x00" in decoded:
            return False
        scrubbed = _scrub_text(decoded, needles)
        if scrubbed == decoded:
            return False
        new_raw = scrubbed.encode("utf-8")
        content["text"] = base64.b64encode(new_raw).decode("ascii")
        content["size"] = len(new_raw)
        return True
    scrubbed = _scrub_text(text, needles)
    if scrubbed == text:
        return False
    content["text"] = scrubbed
    content["size"] = len(scrubbed.encode("utf-8"))
    return True


def _harvest_request_secrets(entries: list) -> set[str]:
    """Password values the HAR itself submitted (e.g. typed during a manual recording)."""
    found: set[str] = set()

    def keep(name: Any, value: Any) -> None:
        if (
            isinstance(name, str)
            and isinstance(value, str)
            and len(value) >= MIN_HARVESTED_LEN
            and value != REDACTED
            and _HARVEST_NAME_RE.search(name)
        ):
            found.add(value)

    def walk_json(value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                keep(k, v)
                walk_json(v)
        elif isinstance(value, list):
            for v in value:
                walk_json(v)

    for entry in entries:
        request = entry.get("request") or {}
        for item in request.get("queryString") or []:
            keep(item.get("name"), item.get("value"))
        post = request.get("postData") or {}
        for param in post.get("params") or []:
            keep(param.get("name"), param.get("value"))
        body = post.get("text")
        if isinstance(body, str) and body:
            stripped = body.lstrip()
            if stripped.startswith(("{", "[")):
                try:
                    walk_json(json.loads(body))
                except ValueError:
                    pass
            elif "=" in body:
                for k, v in parse_qsl(body, keep_blank_values=True):
                    keep(k, v)
        try:
            netloc = urlsplit(request.get("url") or "").netloc
        except ValueError:
            netloc = ""
        if "@" in netloc and ":" in netloc.rsplit("@", 1)[0]:
            keep("password", netloc.rsplit("@", 1)[0].split(":", 1)[1])
        for header in request.get("headers") or []:
            value = header.get("value")
            if str(header.get("name", "")).lower() == "authorization" and isinstance(value, str) \
                    and value.lower().startswith("basic "):
                try:
                    creds = base64.b64decode(value[6:].strip()).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    continue
                if ":" in creds:
                    keep("password", creds.split(":", 1)[1])
    return found


def mask_har(har: dict, *, known_secrets: Iterable[str | None] = ()) -> dict:
    """Return the HAR with password values masked (mutates and returns ``har``).

    Requests get structural masking; then every exact occurrence of a known
    password (the run's own, plus any the HAR's requests submitted) is
    replaced anywhere, including response bodies (base64 bodies included).
    """
    log = har.get("log") if isinstance(har, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    entries = [e for e in (entries or []) if isinstance(e, dict)]
    harvested = _harvest_request_secrets(entries)

    for entry in entries:
        request = entry.get("request") or {}
        if "url" in request:
            request["url"] = mask_url(request["url"])
        for item in request.get("queryString") or []:
            if is_secret_field(item.get("name")) and item.get("value"):
                item["value"] = REDACTED
        _mask_headers(request.get("headers"))
        post = request.get("postData") or {}
        for param in post.get("params") or []:
            if is_secret_field(param.get("name")) and param.get("value"):
                param["value"] = REDACTED
        if isinstance(post.get("text"), str):
            post["text"] = mask_body_text(post["text"], post.get("mimeType"))
        response = entry.get("response") or {}
        if isinstance(response.get("redirectURL"), str):
            response["redirectURL"] = mask_url(response["redirectURL"])

    needles = _known_secret_forms([*known_secrets, *harvested])
    if needles:
        for entry in entries:
            content = (entry.get("response") or {}).get("content")
            if isinstance(content, dict):
                scrub_response_content(content, needles)
        har = _replace_known(har, needles)
    return har


def mask_har_bytes(data: bytes, *, known_secrets: Iterable[str | None] = ()) -> bytes:
    """Mask a serialized HAR. Returns ``data`` unchanged (same bytes) if nothing
    needed masking. Unparseable input still gets known-secret replacement."""
    try:
        har = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        logger.warning("HAR is not valid JSON; applying known-secret masking only")
        text = data.decode("utf-8", errors="replace")
        masked = _scrub_text(text, _known_secret_forms(known_secrets))
        return data if masked == text else masked.encode("utf-8")
    masked = mask_har(copy.deepcopy(har), known_secrets=known_secrets)
    if masked == har:
        return data
    return json.dumps(masked, ensure_ascii=False).encode("utf-8")
