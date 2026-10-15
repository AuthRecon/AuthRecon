from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class HintProfile:
    profile_id: str
    keywords: tuple[str, ...]
    auth_type: str
    description: str
    confidence: int = 80
    force: bool = True


@dataclass(frozen=True)
class HintDecision:
    profile: HintProfile
    matched_keyword: str

    @property
    def auth_type(self) -> str:
        return self.profile.auth_type

    @property
    def confidence(self) -> int:
        return self.profile.confidence

    @property
    def reason(self) -> str:
        return f"Hint matched profile '{self.profile.profile_id}' via keyword '{self.matched_keyword}' ({self.profile.description})"

    @property
    def force(self) -> bool:
        return self.profile.force


_HINT_PROFILES: tuple[HintProfile, ...] = (
    HintProfile(
        profile_id="azure_multi_entry",
        keywords=("azure", "entra", "portal", "partner", "client"),
        auth_type="azure_ad",
        description="Multi-entry Azure AD / Entra ID portals with branded buttons",
        confidence=88,
    ),
    HintProfile(
        profile_id="ldap_directory",
        keywords=("ldap", "directory", "domain\\", "adfs", "sts", "federation"),
        auth_type="ldap",
        description="Classic LDAP/ADFS or DOMAIN\\username workflows",
        confidence=82,
    ),
    HintProfile(
        profile_id="okta_federation",
        keywords=("okta", "oktapreview", "okta.com"),
        auth_type="okta",
        description="Okta-hosted SSO portals",
        confidence=85,
    ),
    HintProfile(
        profile_id="oauth_redirect",
        keywords=("oauth", "authorize", "identity provider", "idp", "federated"),
        auth_type="oauth",
        description="Generic OAuth / IdP redirect workflows",
        confidence=75,
        force=False,
    ),
    HintProfile(
        profile_id="two_step_form",
        keywords=("multi-factor", "one-time", "otp", "two-step"),
        auth_type="two_step_form",
        description="Two-step or MFA-enabled HTML form workflows",
        confidence=70,
        force=False,
    ),
)


def _normalized_keywords(keywords: Iterable[str]) -> set[str]:
    return {keyword.strip().lower() for keyword in keywords if keyword}


def match_hint(login_hint: str | None) -> HintDecision | None:
    """
    Attempt to match the provided login hint against known profiles.

    Returns:
        HintDecision if a profile matches; otherwise None.
    """
    if not login_hint:
        return None
    normalized_hint = login_hint.strip().lower()
    if not normalized_hint:
        return None

    for profile in _HINT_PROFILES:
        for keyword in _normalized_keywords(profile.keywords):
            if keyword and keyword in normalized_hint:
                return HintDecision(profile=profile, matched_keyword=keyword)
    return None
