"""
Sanitization boundary for anything sent to a model as part of AI-assisted
authentication analysis. See SECURITY.md at the repo root.

Every byte that crosses from a live page into a prompt goes through
sanitize_html_for_llm() first. This is not a convenience helper — it is the
one place that enforces "the model never sees a real credential value".
Don't call an LLM provider with raw page HTML from anywhere else.
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

# Field name/id/label fragments that indicate a credential-bearing input,
# independent of its declared `type`. Case-insensitive substring match.
_CREDENTIAL_FIELD_HINTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "otp",
    "pin",
    "apikey",
    "api_key",
    "api-key",
    "authcode",
    "auth_code",
)

# Credential-shaped strings that can appear in page text outside of form
# inputs entirely (e.g. a JS variable, an error message that echoes a token).
_CREDENTIAL_PATTERNS = (
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
    re.compile(r"\bBearer\s+[A-Za-z0-9_\-.=]{10,}\b", re.IGNORECASE),  # Bearer token
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),  # long hex blob (API keys, hashes)
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),  # long base64 blob
)

_REDACTED = "[REDACTED]"
_DEFAULT_MAX_CHARS = 20_000


def _is_credential_field(tag) -> bool:
    if (tag.get("type") or "").lower() == "password":
        return True
    haystack = " ".join(
        str(tag.get(attr, "")) for attr in ("name", "id", "aria-label", "placeholder")
    ).lower()
    return any(hint in haystack for hint in _CREDENTIAL_FIELD_HINTS)


def _redact_credential_patterns(text: str) -> str:
    for pattern in _CREDENTIAL_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return text


def sanitize_html_for_llm(html: str, max_chars: int = _DEFAULT_MAX_CHARS) -> str:
    """
    Strip credential material from page HTML before it can reach a model.

    Guarantees:
      - Every password-type input's value is removed.
      - Every input whose name/id/label looks credential-shaped has its
        value removed, even if `type` doesn't say password.
      - <script> and <style> content is dropped entirely.
      - Remaining text is scanned for credential-shaped strings (JWTs,
        bearer tokens, long hex/base64 blobs) and those are redacted too.
      - Output is capped at max_chars.

    This is deliberately conservative: it can over-redact (strip a value
    that wasn't actually a credential) but must never under-redact.
    """
    if not html:
        return ""

    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style"]):
        tag.decompose()

    for input_tag in soup.find_all("input"):
        if _is_credential_field(input_tag) and input_tag.has_attr("value"):
            input_tag["value"] = _REDACTED

    for textarea in soup.find_all("textarea"):
        haystack = " ".join(
            str(textarea.get(attr, "")) for attr in ("name", "id", "aria-label")
        ).lower()
        if any(hint in haystack for hint in _CREDENTIAL_FIELD_HINTS):
            textarea.string = _REDACTED

    sanitized = str(soup)
    sanitized = _redact_credential_patterns(sanitized)

    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars] + f"\n<!-- truncated at {max_chars} chars -->"

    return sanitized


def assert_no_credential_leak(sanitized_html: str, secrets: list[str]) -> None:
    """
    Defense in depth: verify none of the actual secret values for this run
    (raw password, any known token) survived sanitization verbatim.

    Callers that have access to the real credential value(s) for the run
    should call this right before the sanitized HTML is sent anywhere, and
    treat a failure as "do not proceed" — not as something to log and
    continue past.
    """
    for secret in secrets:
        if secret and secret in sanitized_html:
            raise ValueError(
                "Sanitized HTML still contains a raw secret value — refusing "
                "to send to a model. This indicates a gap in sanitize_html_for_llm, "
                "not a transient error."
            )
