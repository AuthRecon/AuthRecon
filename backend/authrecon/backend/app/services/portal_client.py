"""Client helpers for talking to the Security Portal service APIs."""
from __future__ import annotations

from typing import Any, Dict, Optional

import httpx
from fastapi import status

from app.core.config import get_settings


class PortalAuthError(Exception):
    """Raised when the portal rejects or cannot process a service auth request."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class PortalServiceError(Exception):
    """Raised when a portal service endpoint cannot be reached or returns an error."""


def login_via_portal(username: str, password: str) -> Dict[str, Any]:
    """
    Ask the portal to verify credentials and return the service login payload.
    Raises PortalAuthError on failure.
    """
    return _service_request(
        "POST",
        "/api/service/auth/login",
        payload={"username": username, "password": password},
        wrap_error_as="auth",
    )


def _service_request(
    method: str,
    path: str,
    *,
    payload: Optional[Dict[str, Any]] = None,
    wrap_error_as: Optional[str] = None,
) -> Dict[str, Any]:
    settings = get_settings()
    base_url = str(settings.portal_service_url).rstrip("/")
    url = f"{base_url}{path}"
    headers = {
        "x-portal-service-secret": settings.portal_api_secret,
        "Content-Type": "application/json",
    }
    timeout = settings.portal_service_timeout
    try:
        response = httpx.request(method, url, json=payload, headers=headers, timeout=timeout)
    except httpx.RequestError as exc:
        if wrap_error_as == "auth":
            raise PortalAuthError(status.HTTP_502_BAD_GATEWAY, "Unable to reach portal service") from exc
        raise PortalServiceError("Unable to reach portal service") from exc

    if response.status_code >= 400:
        detail = "Portal request failed"
        try:
            data = response.json()
            detail = data.get("detail", detail)
        except ValueError:
            pass
        if wrap_error_as == "auth":
            raise PortalAuthError(
                status.HTTP_401_UNAUTHORIZED
                if response.status_code == status.HTTP_401_UNAUTHORIZED
                else status.HTTP_502_BAD_GATEWAY,
                detail,
            )
        raise PortalServiceError(detail)

    try:
        return response.json()
    except ValueError as exc:
        if wrap_error_as == "auth":
            raise PortalAuthError(status.HTTP_502_BAD_GATEWAY, "Malformed response from portal") from exc
        raise PortalServiceError("Malformed response from portal") from exc
