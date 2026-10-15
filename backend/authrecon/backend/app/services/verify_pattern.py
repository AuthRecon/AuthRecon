"""Choose the "pattern to verify" for a scanner: text that is on the page after
logging in and NOT on the login page.

The scanner checks this text to decide whether it is still logged in, so:
- invented text (e.g. "Authenticated page") never appears and makes every scan
  think the login failed;
- text that also appears on the login page (a site name in the title, a
  heading shared by both pages) makes the scanner think a failed login worked.

Candidates come from the automation (success message, heading, title) and then
from the post-login HTML (a "Log out" control, headings, the title). The first
candidate that is visible after login and absent before it wins. Returns None
when nothing qualifies, so the UI can ask the operator instead of guessing.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Iterable

# Strings older code used as stand-ins when it found no real text.
PLACEHOLDER_PATTERNS = frozenset({
    "authenticated page",
    "authenticated",
    "authentication successful",
    "two-step authentication successful",
    "login successful",
})

_LOGOUT = re.compile(r"^\s*(log\s?out|sign\s?out|sign off|log off)\b", re.IGNORECASE)
_MIN_LEN, _MAX_LEN = 3, 120
_SKIP_TAGS = {"script", "style", "noscript", "template", "head"}


class _PageText(HTMLParser):
    """Visible text plus the texts of headings, title and logout controls."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.title: list[str] = []
        self.headings: list[str] = []
        self.logout: list[str] = []
        self._stack: list[str] = []
        self._capture: list[tuple[str, list[str]]] = []

    def handle_starttag(self, tag, attrs):
        self._stack.append(tag)
        if tag in ("h1", "h2", "a", "button"):
            self._capture.append((tag, []))
        if tag == "input":
            values = dict(attrs)
            if (values.get("type") or "").lower() in ("submit", "button") and _LOGOUT.match(values.get("value") or ""):
                self.logout.append(values["value"].strip())

    def handle_endtag(self, tag):
        if self._capture and self._capture[-1][0] == tag:
            kind, parts = self._capture.pop()
            text = _clean(" ".join(parts))
            if text:
                if kind in ("h1", "h2"):
                    self.headings.append(text)
                elif _LOGOUT.match(text):
                    self.logout.append(text)
        while self._stack:
            if self._stack.pop() == tag:
                break

    def handle_data(self, data):
        if "title" in self._stack:
            self.title.append(data)
            return
        if any(t in _SKIP_TAGS for t in self._stack):
            return
        self.visible.append(data)
        for _, parts in self._capture:
            parts.append(data)


def _clean(text: str | None) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _parse(html: str | None) -> _PageText:
    page = _PageText()
    if html:
        try:
            page.feed(html)
            page.close()
        except Exception:  # malformed markup: use what was parsed
            pass
    return page


def is_placeholder(pattern: str | None) -> bool:
    return _clean(pattern).lower() in PLACEHOLDER_PATTERNS


def choose_verify_pattern(
    candidates: Iterable[str | None],
    post_auth_html: str | None,
    pre_auth_html: str | None,
) -> str | None:
    post = _parse(post_auth_html)
    pre = _parse(pre_auth_html)
    post_text = _clean(" ".join(post.visible))
    pre_text = _clean(" ".join(pre.visible) + " " + " ".join(pre.title))

    ordered = list(candidates) + post.logout + post.headings + [_clean(" ".join(post.title))]
    seen: set[str] = set()
    for raw in ordered:
        text = _clean(raw)
        if not (_MIN_LEN <= len(text) <= _MAX_LEN) or is_placeholder(text) or text in seen:
            continue
        seen.add(text)
        if post_text and text not in post_text:
            continue  # not visible after login (e.g. only in <title>)
        if pre_text and text in pre_text:
            continue  # also on the login page: proves nothing
        return text
    return None
