"""
Tests for the AI sanitization boundary. Run directly with
`python3 test_sanitize.py` or via pytest if available — no DB or running
services required.
"""
from app.services.automation.ai_fallback.sanitize import assert_no_credential_leak, sanitize_html_for_llm

REAL_PASSWORD = "hunter2-super-secret"
REAL_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_fake_sig_padding"


def test_password_type_input_is_redacted():
    html = f'<input type="password" name="pw" value="{REAL_PASSWORD}">'
    out = sanitize_html_for_llm(html)
    assert REAL_PASSWORD not in out
    assert "[REDACTED]" in out


def test_credential_shaped_field_name_is_redacted_even_without_password_type():
    html = f'<input type="text" name="api_secret_key" value="{REAL_PASSWORD}">'
    out = sanitize_html_for_llm(html)
    assert REAL_PASSWORD not in out


def test_normal_username_field_survives():
    html = '<input type="text" name="username" value="analyst1">'
    out = sanitize_html_for_llm(html)
    assert "analyst1" in out


def test_script_and_style_are_removed():
    html = "<script>var x = 1;</script><style>.a{color:red}</style><p>hello</p>"
    out = sanitize_html_for_llm(html)
    assert "var x" not in out
    assert "color:red" not in out
    assert "hello" in out


def test_jwt_in_free_text_is_redacted():
    html = f"<div>session token: {REAL_JWT}</div>"
    out = sanitize_html_for_llm(html)
    assert REAL_JWT not in out


def test_bearer_token_is_redacted():
    html = "<div>Authorization: Bearer abcdef0123456789ABCDEF0123456789</div>"
    out = sanitize_html_for_llm(html)
    assert "abcdef0123456789ABCDEF0123456789" not in out


def test_truncation():
    # Space-separated words, not one long run — a long unbroken run of
    # base64-alphabet characters is deliberately treated as a possible
    # credential blob and redacted rather than truncated (see
    # test_long_base64_like_blob_is_treated_as_credential below).
    html = "<p>" + ("hello world " * 5_000) + "</p>"
    out = sanitize_html_for_llm(html, max_chars=100)
    assert len(out) < 200  # 100 + truncation marker
    assert "truncated" in out


def test_long_base64_like_blob_is_treated_as_credential():
    # A long unbroken alphanumeric run is exactly what a leaked API key or
    # session token looks like — redact it, don't just pass it through.
    html = "<p>" + ("x" * 5_000) + "</p>"
    out = sanitize_html_for_llm(html, max_chars=100_000)
    assert "x" * 40 not in out
    assert "[REDACTED]" in out


def test_empty_input():
    assert sanitize_html_for_llm("") == ""


def test_assert_no_credential_leak_raises_on_leak():
    sanitized = "<p>oops the value is still hunter2-super-secret</p>"
    try:
        assert_no_credential_leak(sanitized, [REAL_PASSWORD])
        raise AssertionError("expected ValueError to be raised")
    except ValueError:
        pass


def test_assert_no_credential_leak_passes_when_clean():
    sanitized = sanitize_html_for_llm(f'<input type="password" value="{REAL_PASSWORD}">')
    assert_no_credential_leak(sanitized, [REAL_PASSWORD])  # must not raise


if __name__ == "__main__":
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:  # noqa: BLE001 — test runner, not app code
            failures += 1
            print(f"FAIL {test.__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    raise SystemExit(1 if failures else 0)
