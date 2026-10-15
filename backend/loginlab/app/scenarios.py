"""
Scenario Registry
Defines all available authentication test scenarios.
"""
from typing import Dict, Optional
from pydantic import BaseModel


class Scenario(BaseModel):
    id: str
    name: str
    description: str
    auth_type: str
    difficulty: str
    path: str
    enabled: bool = True
    expected_confidence: float = 0.95
    detection_hints: Dict[str, str] = {}


# Registry of all available scenarios
SCENARIOS: Dict[str, Scenario] = {
    "basic-auth": Scenario(
        id="basic-auth",
        name="HTTP Basic Authentication",
        description="Browser-based HTTP Basic Auth with WWW-Authenticate header",
        auth_type="http_basic",
        difficulty="easy",
        path="/basic-auth",
        expected_confidence=1.0,
        detection_hints={
            "header": "WWW-Authenticate: Basic realm=...",
            "status": "401 on first request, 200 on success",
            "indicator": "Authorization header with Basic scheme",
        },
    ),
    "form-login": Scenario(
        id="form-login",
        name="Single-Form Login",
        description="Standard HTML form with username/password POST",
        auth_type="form_post",
        difficulty="easy",
        path="/form-login",
        expected_confidence=0.95,
        detection_hints={
            "form": "POST to /form-login with username/password fields",
            "success": "302 redirect or session cookie",
            "indicator": "Set-Cookie: loginlab_session=...",
        },
    ),
    "multi-step": Scenario(
        id="multi-step",
        name="Multi-Step Login",
        description="Email entry → Password entry (separate pages)",
        auth_type="multi_step_form",
        difficulty="medium",
        path="/multi-step",
        expected_confidence=0.90,
        detection_hints={
            "step1": "Email input, POST to /multi-step/email",
            "step2": "Password input, POST to /multi-step/password",
            "indicator": "Progressive form with state parameter",
        },
    ),
    "sso-redirect": Scenario(
        id="sso-redirect",
        name="SSO-Style Redirect",
        description="OAuth-like flow with state parameter and redirects",
        auth_type="oauth_redirect",
        difficulty="medium",
        path="/sso-redirect",
        expected_confidence=0.85,
        detection_hints={
            "flow": "Redirect to /sso-redirect/authorize with state",
            "callback": "POST credentials, redirect back with code",
            "indicator": "OAuth-like parameter passing",
        },
    ),
    "ldap-login": Scenario(
        id="ldap-login",
        name="LDAP-Style Login",
        description="Domain\\Username format authentication",
        auth_type="ldap_form",
        difficulty="medium",
        path="/ldap-login",
        expected_confidence=0.90,
        detection_hints={
            "format": "DOMAIN\\username in username field",
            "fallback": "Also accepts email format",
            "indicator": "Domain separator in username input",
        },
    ),
    "api-auth": Scenario(
        id="api-auth",
        name="JSON API Authentication",
        description="REST API with JSON payload and JWT token response",
        auth_type="api_token",
        difficulty="easy",
        path="/api/auth",
        expected_confidence=0.95,
        detection_hints={
            "content_type": "application/json",
            "response": "JWT token in JSON response",
            "indicator": "Bearer token authentication",
        },
    ),
    "form-login-domain": Scenario(
        id="form-login-domain",
        name="Form Login with Domain Select",
        description="Login form behind a reveal button with domain/tenant dropdown and required checkbox",
        auth_type="form_post",
        difficulty="medium",
        path="/form-login-domain",
        expected_confidence=0.9,
        detection_hints={
            "form": "POST to /form-login-domain with username/password and domain select",
            "controls": "Requires selecting domain and checking consent",
            "indicator": "Hidden form revealed after click; select[name=domain]",
        },
    ),
    "covert-auth": Scenario(
        id="covert-auth",
        name="Covert JS Widget Auth",
        description=(
            "No <form> element and no input[type='password'] — fields submitted via "
            "JS fetch() to a JSON endpoint, password field visually masked with CSS "
            "instead of type=password. Designed to defeat rule-based field discovery "
            "on purpose; a genuine target for ai_fallback / MCP-assisted analysis."
        ),
        auth_type="js_widget_auth",
        difficulty="hard",
        path="/covert-auth",
        expected_confidence=0.0,
        detection_hints={
            "note": "Rule-based discovery is expected to fail here by design",
            "fields": "field_a (Access ID), field_b (Passphrase, CSS-masked text input)",
            "submit": "JS fetch() POST to /covert-auth/submit with JSON body, not a form POST",
        },
    ),
}


def get_scenario(scenario_id: str) -> Optional[Scenario]:
    """Get scenario by ID."""
    return SCENARIOS.get(scenario_id)


def list_enabled_scenarios() -> list[Scenario]:
    """List all enabled scenarios."""
    return [s for s in SCENARIOS.values() if s.enabled]
