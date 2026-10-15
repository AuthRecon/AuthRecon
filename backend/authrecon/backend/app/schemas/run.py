from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, AnyHttpUrl, Field, root_validator

from app.schemas.security_context import SecurityContext


class RunStatus(str, Enum):
    queued = "queued"
    running = "running"
    manual_recording = "manual_recording"
    succeeded = "succeeded"
    failed = "failed"


class RunSubmission(BaseModel):
    target_url: AnyHttpUrl
    credential_id: str | None = None
    username: str | None = None
    password: str | None = Field(default=None, min_length=1)
    save_credential_name: str | None = None
    roles: list[dict[str, Any]] = []
    auth_type: str | None = Field(
        default=None,
        description="Optional override for detected authentication type (e.g., azure_ad, ldap, okta)."
    )
    login_hint: str | None = Field(
        default=None,
        description="Optional keyword to select correct login button (e.g., 'funeral', 'medical', 'partner')"
    )
    domain_prefix: str | None = Field(
        default=None,
        description="Optional domain prefix for username (e.g., 'COMPANY' for COMPANY\\username format)"
    )
    engines: list[str] = Field(
        default=["selenium"],
        description="Authentication engines to run (selenium, playwright, httpx). Default: selenium only."
    )
    streaming_enabled: bool = Field(
        default=False,
        description="Enable VNC browser streaming for real-time automation viewing. Default: false."
    )
    recording_mode: str = Field(
        default="auto",
        description="Recording mode: 'auto' for automated authentication, 'manual' for operator-guided sessions."
    )
    options: dict[str, Any] = {}

    @root_validator
    def validate_credentials(cls, values: dict[str, Any]) -> dict[str, Any]:
        recording_mode = values.get("recording_mode", "auto")

        # Skip credential validation for manual recording mode
        if recording_mode == "manual":
            return values

        credential_id = values.get("credential_id")
        username = values.get("username")
        password = values.get("password")
        save_name = values.get("save_credential_name")
        roles = values.get("roles") or []
        if credential_id:
            if save_name:
                raise ValueError("save_credential_name can only be used when submitting inline credentials.")
            return values
        if roles:
            return values
        if username and password:
            return values
        raise ValueError("Provide either credential_id, roles, or username/password pair.")


class AuthDetectionInfo(BaseModel):
    auth_type: str | None = None
    evidence: str | None = None
    # Where the pre-run detection request ended up (before logging in). Not the
    # run's final URL, which is RunDetail.final_url (after logging in).
    pre_login_url: str | None = None
    error: str | None = None
    signals: list[dict[str, Any]] = Field(default_factory=list)
    redirect_chain: list[str] = Field(default_factory=list)
    probed_urls: list[str] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    occurred_at: datetime
    message: str


class TechFingerprint(BaseModel):
    server: str | None = None
    powered_by: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    js_frameworks: list[str] = Field(default_factory=list)
    js_libraries: list[str] = Field(default_factory=list)
    cms: list[str] = Field(default_factory=list)
    meta_generators: list[str] = Field(default_factory=list)
    security_headers: list[str] = Field(default_factory=list)
    cookies: list[str] = Field(default_factory=list)
    auth_cookies: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)


class RunSummary(BaseModel):
    id: str
    status: RunStatus
    target_url: AnyHttpUrl
    submitted_at: datetime
    auth_type: str | None = None
    operator: str | None = None
    # True if any AI selector suggestion was ever recorded for this run (see
    # app/api/ai_assist.py) — lets the run list show at-a-glance which runs
    # involved AI assistance without a separate per-run API call.
    ai_assisted: bool = False
    # Problems on an otherwise successful run (e.g. some roles failed).
    warnings: list[str] = Field(default_factory=list)


class RunRoleSummary(BaseModel):
    slug: str | None = None
    label: str | None = None
    username: str | None = None
    status: str | None = None
    final_url: AnyHttpUrl | None = None
    auth_type: str | None = None
    tags: list[str] = Field(default_factory=list)
    artifact_count: int = 0
    screenshot_count: int = 0
    artifact_types: dict[str, int] = Field(default_factory=dict)
    error: str | None = None


class RunDetail(RunSummary):
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: int | None = None
    final_url: AnyHttpUrl | None = None
    pattern: str | None = None
    llm_pattern: str | None = None
    session_cookies: list[dict[str, Any]] = Field(default_factory=list)
    js_frameworks: list[str] = Field(default_factory=list)
    tech_fingerprint: TechFingerprint | None = None
    security_context: SecurityContext | None = None
    timeline: list[TimelineEntry] = Field(default_factory=list)
    detected_auth: AuthDetectionInfo | None = None
    role_scope: dict[str, Any] | None = None
    # Full AI-suggestion history for this run (see app/api/ai_assist.py).
    # llm_pattern above is just the at-a-glance summary of the suggestion
    # that was actually used, if one succeeded — this is everything that
    # was ever suggested, including ones that were never acted on or that
    # were tried and failed, for "to what extent was AI used" transparency.
    ai_suggestions: list[dict[str, Any]] = Field(default_factory=list)
    roles: list[RunRoleSummary] = Field(default_factory=list)
    error_message: str | None = None
    flow_summary: str | None = None
    streaming_enabled: bool = False
    vnc_port: int | None = None
    # What to put in the scanner (services/was_setup.py); None unless succeeded.
    was_setup: dict[str, Any] | None = None
    # Plain-language category and next steps; None unless failed.
    failure: dict[str, Any] | None = None
