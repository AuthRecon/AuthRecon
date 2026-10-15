"""Shared input validation helpers for the portal."""
from __future__ import annotations

import re


def validate_password(password: str) -> str | None:
    """Validate password against the portal complexity policy.

    Returns an error message string if the password fails, or None if it passes.
    Only validates at create/change time — never called on existing stored hashes.

    Policy: 12+ characters, at least one uppercase, one digit, one special character.
    """
    if len(password) < 12:
        return "Password must be at least 12 characters"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number"
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character"
    return None
