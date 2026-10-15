"""Helpers to mint short-lived JWTs for service-to-service calls."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import jwt

from auth import SessionUser


ALGORITHM = "HS256"


def create_service_token(
    user: SessionUser,
    secret: str,
    roles: List[str] | None = None,
    ttl_minutes: int = 5,
    service: Optional[str] = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, object] = {
        "sub": user.username,
        "username": user.username,
        "user_id": str(user.user_id),  # Portal user UUID - required by AuthRecon
        "roles": roles or (["admin"] if user.is_admin else ["analyst"]),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
    }
    if service:
        payload["service"] = service
    return jwt.encode(payload, secret, algorithm=ALGORITHM)
