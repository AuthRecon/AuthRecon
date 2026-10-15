"""
Authentication Pattern Library

This module contains rule-based pattern matchers for common authentication flows.
These patterns handle ~70-75% of web authentication scenarios deterministically
without requiring AI/ML models.

Supported Patterns:
- form_login: Generic HTML form-based authentication
- microsoft_adfs: Microsoft ADFS/Azure AD/Entra ID
- saml_login: SAML 2.0 Enterprise SSO (Shibboleth, SimpleSAMLphp, OneLogin)
- okta_login: Okta SSO (hosted and custom domains)
- oauth_login: OAuth 2.0/OpenID Connect (Google, GitHub, etc.)
- ldap_login: LDAP/Directory services
- two_step_form: Multi-step authentication flows
- basic_auth: HTTP Basic Authentication

Architecture:
Each pattern module exports:
- attempt_login(driver, url, username, password, **kwargs) -> dict
- Detection logic is handled by auth_detection.py service

Future: AI fallback for edge cases (v2.0)
"""

from .basic_auth import run_basic_auth
from .form_login import run_form_login
from .ldap_login import run_ldap_login
from .microsoft_adfs import run_azure_login
from .oauth_login import run_oauth_login
from .okta_login import run_okta_login
from .saml_login import run_saml_login
from .two_step_form import run_two_step_form_login

__all__ = [
    "run_basic_auth",
    "run_form_login",
    "run_ldap_login",
    "run_azure_login",
    "run_oauth_login",
    "run_okta_login",
    "run_saml_login",
    "run_two_step_form_login",
]
