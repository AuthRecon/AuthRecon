"""
HTTPX authentication patterns.

Headless HTTP client for fast API-based auth flows (no browser overhead).
"""

from .form_login import attempt_form_login_httpx

__all__ = ['attempt_form_login_httpx']
