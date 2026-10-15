"""
Security Context Data Models

Comprehensive security metadata extracted from authentication runs.
Captures cookies, headers, TLS info, tokens, storage, and more.

Schema version: 1.0.0
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Enums
# ============================================================================


class SameSitePolicy(str, Enum):
    """Cookie SameSite attribute values."""

    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"


class SecurityIssueLevel(str, Enum):
    """Security issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# 1. Cookie Analysis Models
# ============================================================================


class CookieMetadata(BaseModel):
    """Comprehensive metadata for a single HTTP cookie."""

    # Basic attributes
    name: str
    value_encrypted: str | None = None  # Encrypted, not plaintext
    value_hash: str  # SHA256 hash for detection/comparison
    domain: str
    path: str

    # Expiration
    expires: int | None = None  # Unix timestamp (None = session cookie)
    ttl_seconds: int | None = None  # Calculated from expires
    is_session: bool  # True if no expiration
    is_persistent: bool  # True if has expiration

    # Security flags
    http_only: bool
    secure: bool
    same_site: SameSitePolicy | None = None

    # Size
    size_bytes: int

    # Entropy analysis
    entropy_score: float = Field(ge=0.0, le=1.0)  # Randomness (0.0-1.0)

    # Timestamp
    captured_at: datetime

    # Security analysis
    security_issues: list[str] = Field(default_factory=list)


class CookieAnalysis(BaseModel):
    """Aggregated cookie analysis for a run."""

    cookies: list[CookieMetadata]

    # Counts
    total_count: int
    session_count: int
    persistent_count: int
    secure_count: int
    http_only_count: int
    same_site_none_count: int

    # Size
    total_size_bytes: int

    # Security score
    security_score: float = Field(ge=0.0, le=100.0)

    # Issues
    issues: list[str] = Field(default_factory=list)


# ============================================================================
# 2. Security Headers Models
# ============================================================================


class HSTSConfig(BaseModel):
    """HTTP Strict Transport Security configuration."""

    max_age: int  # Seconds
    include_subdomains: bool = False
    preload: bool = False
    raw_value: str


class CSPDirective(BaseModel):
    """Content Security Policy directive."""

    name: str  # e.g., "default-src", "script-src"
    values: list[str]  # e.g., ["'self'", "https:"]


class CSPConfig(BaseModel):
    """Content Security Policy configuration."""

    directives: list[CSPDirective]
    report_uri: str | None = None
    report_only: bool = False
    raw_value: str

    # Security analysis
    allows_unsafe_inline: bool = False
    allows_unsafe_eval: bool = False
    allows_wildcard: bool = False
    issues: list[str] = Field(default_factory=list)


class CORSConfig(BaseModel):
    """CORS (Cross-Origin Resource Sharing) configuration."""

    allow_origin: str | None = None
    allow_credentials: bool = False
    allow_methods: list[str] = Field(default_factory=list)
    allow_headers: list[str] = Field(default_factory=list)
    expose_headers: list[str] = Field(default_factory=list)
    max_age: int | None = None

    # Security analysis
    is_overly_permissive: bool = False
    issues: list[str] = Field(default_factory=list)


class SecurityHeaders(BaseModel):
    """Security-related HTTP response headers."""

    # Strict Transport Security
    hsts: HSTSConfig | None = None

    # Content Security Policy
    csp: CSPConfig | None = None

    # Frame protection
    x_frame_options: str | None = None  # DENY, SAMEORIGIN, ALLOW-FROM

    # MIME sniffing
    x_content_type_options: str | None = None  # nosniff

    # XSS protection (legacy)
    x_xss_protection: str | None = None  # 1; mode=block

    # Referrer policy
    referrer_policy: str | None = None

    # Permissions policy (formerly Feature-Policy)
    permissions_policy: dict[str, list[str]] = Field(default_factory=dict)

    # CORS headers
    cors: CORSConfig | None = None

    # Other security-relevant headers
    other: dict[str, str] = Field(default_factory=dict)

    # Missing headers (security gaps)
    missing_headers: list[str] = Field(default_factory=list)

    # Security analysis
    security_score: float = Field(ge=0.0, le=100.0)
    issues: list[str] = Field(default_factory=list)


class ResponseHeaders(BaseModel):
    """Complete HTTP response headers analysis."""

    security: SecurityHeaders

    # Server identification
    server: str | None = None
    x_powered_by: str | None = None
    framework_hints: list[str] = Field(default_factory=list)

    # All raw headers
    raw: dict[str, str] = Field(default_factory=dict)


# ============================================================================
# 3. TLS/Certificate Models
# ============================================================================


class CertificateInfo(BaseModel):
    """SSL/TLS certificate information."""

    subject: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    days_until_expiry: int
    is_expired: bool
    is_self_signed: bool

    # Subject Alternative Names
    sans: list[str] = Field(default_factory=list)

    # Certificate chain
    chain_depth: int

    # Fingerprint
    sha256_fingerprint: str

    # Security analysis
    issues: list[str] = Field(default_factory=list)


class TLSInfo(BaseModel):
    """TLS connection information."""

    version: str  # TLSv1.2, TLSv1.3
    cipher_suite: str
    key_exchange: str | None = None
    encryption: str | None = None
    mac: str | None = None

    # Certificate
    certificate: CertificateInfo

    # Security analysis
    issues: list[str] = Field(default_factory=list)


# ============================================================================
# 4. Authentication Token Models
# ============================================================================


class JWTAnalysis(BaseModel):
    """JSON Web Token analysis."""

    raw_token_encrypted: str  # Full token (encrypted storage)
    token_hash: str  # SHA256 hash

    # Decoded parts (no signature verification)
    header: dict[str, Any]
    payload: dict[str, Any]

    # Standard claims
    issuer: str | None = None  # iss
    subject: str | None = None  # sub
    audience: str | None = None  # aud
    issued_at: int | None = None  # iat (Unix timestamp)
    expires_at: int | None = None  # exp (Unix timestamp)
    not_before: int | None = None  # nbf (Unix timestamp)

    # Analysis
    algorithm: str  # HS256, RS256, etc.
    ttl_seconds: int | None = None
    is_expired: bool
    custom_claims: dict[str, Any] = Field(default_factory=dict)

    # Security issues
    issues: list[str] = Field(default_factory=list)


class BearerToken(BaseModel):
    """OAuth 2.0 Bearer token."""

    token_type: str  # "Bearer"
    access_token_encrypted: str
    access_token_hash: str
    refresh_token_encrypted: str | None = None
    refresh_token_hash: str | None = None
    scope: list[str] = Field(default_factory=list)
    expires_in: int | None = None  # Seconds


class AuthenticationTokens(BaseModel):
    """All authentication tokens found during the run."""

    jwt_tokens: list[JWTAnalysis] = Field(default_factory=list)
    bearer_tokens: list[BearerToken] = Field(default_factory=list)
    csrf_tokens: list[str] = Field(default_factory=list)  # Hashed
    api_keys: dict[str, str] = Field(default_factory=dict)  # {header_name: key_hash}
    state_parameters: dict[str, str] = Field(default_factory=dict)  # OAuth/SAML state

    # Security analysis
    issues: list[str] = Field(default_factory=list)


# ============================================================================
# 5. Browser Storage Models
# ============================================================================


class BrowserStorage(BaseModel):
    """LocalStorage and SessionStorage contents."""

    local_storage: dict[str, str] = Field(default_factory=dict)
    session_storage: dict[str, str] = Field(default_factory=dict)

    # Analysis
    sensitive_keys: list[str] = Field(default_factory=list)  # Keys with "token", "secret", etc.
    total_size_bytes: int
    indexed_db_detected: bool = False
    service_worker_registered: bool = False

    # Security issues
    issues: list[str] = Field(default_factory=list)


# ============================================================================
# 6. Server Fingerprinting Models
# ============================================================================


class ServerFingerprint(BaseModel):
    """Server and technology stack fingerprinting."""

    # From headers
    server_header: str | None = None
    x_powered_by: str | None = None
    framework_version: str | None = None

    # Technology detection
    technologies: list[str] = Field(default_factory=list)  # ["ASP.NET 4.8", "IIS 10.0"]

    # Hosting/CDN
    cdn_provider: str | None = None  # CloudFlare, Akamai, Fastly
    hosting_provider: str | None = None  # AWS, Azure, GCP
    hosting_region: str | None = None

    # IP information
    ip_address: str | None = None
    reverse_dns: str | None = None
    asn: int | None = None
    asn_organization: str | None = None

    # Detection confidence
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.0)


# ============================================================================
# 7. Redirect Chain Models
# ============================================================================


class RedirectStep(BaseModel):
    """Single step in a redirect chain."""

    sequence: int
    url: str
    status_code: int  # 301, 302, 307, 308
    method: str  # GET, POST
    location_header: str | None = None
    reason: str | None = None  # "SSO handoff", "Post-login redirect"
    timestamp: datetime
    duration_ms: int


class RedirectChain(BaseModel):
    """Complete redirect chain analysis."""

    steps: list[RedirectStep] = Field(default_factory=list)
    total_redirects: int
    total_duration_ms: int
    is_circular: bool = False

    # Identity provider detection
    identity_providers: list[str] = Field(default_factory=list)  # ["Azure AD", "Okta"]

    # Pattern analysis
    flow_type: str | None = None  # "SAML", "OAuth", "Form-based"

    # Issues
    issues: list[str] = Field(default_factory=list)


# ============================================================================
# 8. Form Metadata Models
# ============================================================================


class FormField(BaseModel):
    """HTML form field metadata."""

    name: str
    field_type: str  # text, password, email, hidden
    autocomplete: str | None = None
    pattern: str | None = None  # Regex validation
    required: bool = False
    minlength: int | None = None
    maxlength: int | None = None


class FormMetadata(BaseModel):
    """HTML form structure and validation."""

    action_url: str
    method: str  # GET, POST

    # Fields
    username_field: FormField | None = None
    password_field: FormField | None = None
    hidden_fields: list[dict[str, str]] = Field(default_factory=list)

    # CSRF protection
    csrf_token_field: str | None = None
    csrf_token_value_hash: str | None = None

    # Validation
    client_side_validation: bool = False
    validation_patterns: dict[str, str] = Field(default_factory=dict)

    # MFA
    mfa_fields_detected: list[str] = Field(default_factory=list)
    mfa_methods_visible: list[str] = Field(default_factory=list)


# ============================================================================
# 9. API Discovery Models
# ============================================================================


class APIEndpoint(BaseModel):
    """Discovered API endpoint."""

    url: str
    method: str  # GET, POST, PUT, DELETE
    response_status: int
    request_content_type: str | None = None
    response_content_type: str | None = None


class APIDiscovery(BaseModel):
    """API patterns discovered during the run."""

    endpoints: list[APIEndpoint] = Field(default_factory=list)

    # Patterns
    rest_apis: list[str] = Field(default_factory=list)  # ["/api/v1/users"]
    graphql_endpoints: list[str] = Field(default_factory=list)
    websocket_endpoints: list[str] = Field(default_factory=list)

    # Versioning
    api_versions: list[str] = Field(default_factory=list)  # ["v1", "v2"]

    # Undocumented endpoints
    undocumented_endpoints: list[str] = Field(default_factory=list)


# ============================================================================
# 10. JavaScript Secret Scanner Models
# ============================================================================


class JSSecretFinding(BaseModel):
    """Secret or sensitive data found in JavaScript files."""

    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    type: str  # "AWS Access Key", "Hardcoded Password", etc.
    file: str  # Filename from URL
    url: str  # Full URL to the JS file
    line: int  # Line number where secret was found
    snippet: str  # Code snippet showing the secret (with context)
    matched_value: str  # The actual matched string
    impact: str  # What this means for security
    pre_auth: bool  # Was this found before authentication?
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW


class JSSecretsAnalysis(BaseModel):
    """JavaScript secrets scanning results."""

    findings: list[JSSecretFinding] = Field(default_factory=list)

    # Summary statistics
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    pre_auth_count: int = 0
    post_auth_count: int = 0

    # Files scanned
    total_js_files: int = 0
    files_with_secrets: int = 0

    # Scanning statistics (added 2025-12-14)
    total_lines_scanned: int = 0
    largest_files: list[dict] = Field(default_factory=list)  # [{name, lines, size_bytes}]

    # Security assessment
    security_score: float = Field(ge=0.0, le=100.0, default=100.0)
    issues: list[str] = Field(default_factory=list)


# ============================================================================
# 11. Error Disclosure Models
# ============================================================================


class ErrorDisclosure(BaseModel):
    """Information leakage through errors."""

    stack_traces: list[str] = Field(default_factory=list)
    database_errors: list[str] = Field(default_factory=list)
    debug_messages: list[str] = Field(default_factory=list)

    # Disclosed information
    internal_paths: list[str] = Field(default_factory=list)
    database_names: list[str] = Field(default_factory=list)
    table_names: list[str] = Field(default_factory=list)
    framework_versions: list[str] = Field(default_factory=list)

    debug_mode_detected: bool = False
    debug_endpoints: list[str] = Field(default_factory=list)

    # Security score (lower = more disclosure)
    security_score: float = Field(ge=0.0, le=100.0, default=100.0)


# ============================================================================
# Complete Security Context
# ============================================================================


class SecurityContext(BaseModel):
    """
    Complete security metadata extracted from an authentication run.

    This is the top-level object stored in the database as JSONB.
    """

    # Core analysis (HIGH PRIORITY)
    cookies: CookieAnalysis | None = None
    security_headers: ResponseHeaders | None = None
    authentication_tokens: AuthenticationTokens | None = None

    # Network & infrastructure (MEDIUM PRIORITY)
    tls_info: TLSInfo | None = None
    server_fingerprint: ServerFingerprint | None = None
    redirect_chain: RedirectChain | None = None
    browser_storage: BrowserStorage | None = None

    # Discovery & metadata (LOW PRIORITY)
    form_metadata: FormMetadata | None = None
    api_discovery: APIDiscovery | None = None
    error_disclosure: ErrorDisclosure | None = None
    js_secrets: JSSecretsAnalysis | None = None

    # Performance metrics
    page_load_time_ms: int | None = None
    time_to_first_byte_ms: int | None = None
    total_requests: int | None = None
    total_data_transferred_bytes: int | None = None

    # Overall security assessment
    overall_security_score: float = Field(ge=0.0, le=100.0, default=0.0)
    critical_issues: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    # Metadata
    extracted_at: datetime
    extraction_version: str = "1.0.0"  # Schema version

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "cookies": {"total_count": 3, "security_score": 75.0},
            "security_headers": {
                "security": {"security_score": 85.0},
                "server": "nginx/1.20.0",
            },
            "overall_security_score": 80.0,
            "extracted_at": "2025-11-29T12:00:00Z",
            "extraction_version": "1.0.0",
        }
    })
