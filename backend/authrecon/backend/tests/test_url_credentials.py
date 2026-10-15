"""Basic-auth runs load https://user:pass@host/; that URL must never be stored."""
from __future__ import annotations

import pytest

from app.core.urls import strip_userinfo


@pytest.mark.parametrize("url,expected", [
    ("http://user%40x.local:P%40ss%21@loginlab:5500/basic-auth", "http://loginlab:5500/basic-auth"),
    ("https://u:p@example.com/a?b=1#c", "https://example.com/a?b=1#c"),
    ("https://example.com/login", "https://example.com/login"),
    ("https://example.com/path@notuserinfo", "https://example.com/path@notuserinfo"),
    (None, None),
    ("", ""),
])
def test_strip_userinfo(url, expected):
    assert strip_userinfo(url) == expected
