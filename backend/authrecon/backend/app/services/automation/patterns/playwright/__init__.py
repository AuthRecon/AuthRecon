"""
Playwright authentication patterns.

Modern browser automation for SPA/JavaScript-heavy auth flows with HAR capture.
"""

from .form_login import attempt_form_login_playwright

__all__ = ['attempt_form_login_playwright']
