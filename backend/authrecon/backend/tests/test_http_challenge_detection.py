"""WWW-Authenticate challenges map to the right auth type: Basic is
automatable; Negotiate/NTLM and Digest are reported, not attempted."""
from __future__ import annotations

import pytest

from app.services.scoring import analyze_headers_for_signals


@pytest.mark.parametrize("header,expected", [
    ('Basic realm="x"', "basic_auth"),
    ("Negotiate", "windows_integrated"),
    ("NTLM", "windows_integrated"),
    ('Negotiate, NTLM, Basic realm="x"', "basic_auth"),  # Basic offered too: use it
    ('Digest realm="x", nonce="n"', "digest_auth"),
])
def test_www_authenticate_classification(header, expected):
    signals = analyze_headers_for_signals({"WWW-Authenticate": header})
    assert expected in {s.auth_type for s in signals}
    if expected == "basic_auth":
        assert "windows_integrated" not in {s.auth_type for s in signals}
