"""Helpers for verifying Security Portal-issued JWTs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import jwt
from jwt import PyJWTError


@dataclass
class PortalClaims:
    username: str
    user_id: str  # Portal user UUID
    roles: List[str]
    service: Optional[str] = None


class PortalTokenError(Exception):
    """Raised when a portal-issued token cannot be validated."""


def decode_portal_token(token: str, secret: str) -> PortalClaims:
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except PyJWTError as exc:
        raise PortalTokenError("Invalid portal token") from exc

    username = payload.get("username") or payload.get("sub")
    if not username:
        raise PortalTokenError("Portal token missing subject")

    user_id = payload.get("user_id")
    if not user_id:
        raise PortalTokenError("Portal token missing user_id")

    roles = payload.get("roles") or []
    if not isinstance(roles, list):
        roles = [str(roles)]

    service = payload.get("service")

    return PortalClaims(
        username=str(username).lower(),
        user_id=str(user_id),
        roles=[str(role).lower() for role in roles],
        service=str(service).lower() if isinstance(service, str) else None,
    )
