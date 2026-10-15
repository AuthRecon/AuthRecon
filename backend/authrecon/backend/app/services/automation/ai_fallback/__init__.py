"""
AI-assisted auth-flow analysis (not yet implemented).

See SECURITY.md at the repo root for the rules this module must
follow. The short version: the model suggests, it never acts, and it never
sees or produces a credential value.

Planned behavior, once implemented:
- Invoked only when the rule-based pattern library can't confidently
  classify a login page (low-confidence detection, no matching playbook,
  selector miss).
- Given sanitized page HTML (see sanitize.py) and optionally a screenshot
  with input regions redacted — never the raw page, never a credential.
- Returns selector/auth-type *suggestions* with a confidence score. The
  caller (deterministic worker code) decides whether to act on them and,
  if so, performs the actual credential injection itself. This module
  never receives a username or password, and never returns one.
- A successful suggestion, once verified by the deterministic path, can
  seed a new TenantPlaybook entry the same way rule-based detection does.

Architecture:
- Primary: rule-based pattern library (fast, deterministic, free).
- Fallback: this module (slower, probabilistic, requires an opt-in
  provider — see SECURITY.md, "AI and MCP").

This is planned as a licensed feature (see license_client.require_feature,
commented out below until there's a real implementation to gate).
"""
from __future__ import annotations

from dataclasses import dataclass


class AIFallbackNotImplemented(NotImplementedError):
    """Raised when AI fallback is invoked but not yet implemented."""

    def __init__(self):
        super().__init__(
            "AI-assisted auth-flow analysis is not yet implemented. "
            "Current version uses the rule-based pattern library only."
        )


@dataclass(frozen=True)
class AuthSuggestion:
    """
    A model's guess at how to authenticate against a page it hasn't seen
    a playbook for. Deliberately has no field capable of holding a
    credential value — that's enforced by the shape of this type, not by
    a comment asking callers to be careful.
    """

    auth_type: str  # e.g. "form_auth", "okta", "saml" — same vocabulary as variant.auth_hint
    username_selector: str | None
    password_selector: str | None
    submit_selector: str | None
    confidence: float  # 0.0-1.0; caller decides its own acceptance threshold
    reasoning: str  # short human-readable explanation, for audit/debugging


def suggest_auth_selectors(sanitized_html: str, *, screenshot_b64: str | None = None) -> AuthSuggestion:
    """
    Ask a model to suggest login selectors for a page the rule-based
    library couldn't classify.

    Args:
        sanitized_html: output of sanitize.sanitize_html_for_llm() — never
            pass raw page HTML here.
        screenshot_b64: optional base64 screenshot with input regions
            already redacted. Not yet supported by any implementation.

    Returns:
        AuthSuggestion — a suggestion only. The caller is responsible for
        deciding whether to act on it and for performing the actual
        credential injection through existing deterministic automation.

    Raises:
        AIFallbackNotImplemented: always, until an implementation exists.
    """
    # from app.services.license_client import require_feature, FeatureNotLicensedError
    #
    # require_feature(
    #     "ai_fallback",
    #     upgrade_message="AI-assisted auth-flow analysis requires an upgraded license.",
    # )
    #
    # (actual provider call here, using the sanitized_html this function
    # was given — never raw HTML, never a credential value)

    raise AIFallbackNotImplemented()


__all__ = ["suggest_auth_selectors", "AuthSuggestion", "AIFallbackNotImplemented"]
