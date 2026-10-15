from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from app.schemas.security_context import SecurityContext


@dataclass(slots=True)
class ScreenshotCapture:
    file_name: str
    data: bytes
    description: str | None = None


@dataclass(slots=True)
class RecordedAction:
    action: str
    selector: str | None
    value: str | None = None
    note: str | None = None


@dataclass(slots=True)
class FormAuthResult:
    final_url: str
    page_title: str | None
    heading: str | None
    success_message: str | None
    cookies: List[dict[str, Any]]  # Full cookie objects for downstream scanner/security analysis
    security_context: SecurityContext | None  # New: comprehensive security metadata
    screenshots: List[ScreenshotCapture]
    events: List[str]
    pre_auth_html: str
    post_auth_html: str
    username_selector: str | None
    password_selector: str | None
    submit_selector: str | None
    submit_method: str | None
    recorded_actions: List[RecordedAction]
    har_bytes: bytes | None = None  # Playwright HAR capture (full network trace)
    success: bool = True  # Explicit success flag (Playwright/httpx need this)

    @property
    def pattern(self) -> str | None:
        for candidate in (self.success_message, self.heading, self.page_title):
            if candidate:
                return candidate
        return None


class AutomationFailure(Exception):
    def __init__(
        self,
        message: str,
        screenshots: List[ScreenshotCapture] | None = None,
        events: List[str] | None = None,
        html: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.screenshots = list(screenshots or [])
        # Keep the handler's own list (not a copy): if it's a LiveEvents list
        # its messages were already written to the timeline, and the worker
        # checks that flag so it doesn't record them twice.
        self.events = events if events is not None else []
        self.html = html

    def __str__(self) -> str:
        return self.message


class CredentialRejected(AutomationFailure):
    """The target answered the login with an explicit "wrong credentials" error.

    Retrying would just resubmit the same username/password, which is how
    accounts get locked out (AD lockout policies often trip at 3-5 failures),
    so callers must not retry on this.
    """
