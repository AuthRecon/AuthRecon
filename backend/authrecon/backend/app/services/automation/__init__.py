from .patterns.basic_auth import run_basic_auth, BasicAuthResult
from .patterns.form_login import run_form_login
from .patterns.microsoft_adfs import run_azure_login
from .patterns.okta_login import run_okta_login
from .patterns.ldap_login import run_ldap_login
from .patterns.oauth_login import run_oauth_login
from .patterns.saml_login import run_saml_login
from .types import FormAuthResult, ScreenshotCapture, RecordedAction, AutomationFailure, CredentialRejected
from .entrypoint_selection import select_login_entrypoint, click_entrypoint_safe, EntrypointCandidate

__all__ = [
    "BasicAuthResult",
    "FormAuthResult",
    "ScreenshotCapture",
    "RecordedAction",
    "AutomationFailure",
    "CredentialRejected",
    "run_basic_auth",
    "run_form_login",
    "run_azure_login",
    "run_okta_login",
    "run_ldap_login",
    "run_oauth_login",
    "run_saml_login",
    "select_login_entrypoint",
    "click_entrypoint_safe",
    "EntrypointCandidate",
]
