"""Test-wide setup: app.py builds an app at import time and fails closed
without a signing secret, so give the test process random ones."""
from __future__ import annotations

import os
import secrets

os.environ.setdefault("PORTAL_SECRET_KEY", secrets.token_hex(32))
os.environ.setdefault("PORTAL_API_SECRET", secrets.token_hex(32))


def seed_users(*names_and_admin: tuple[str, bool]) -> None:
    """Create portal users whose id equals their name, so tests can mint
    tokens with ``create_jwt_token(name, user_id=name)``. The portal checks
    every token against the DB, so a token for a nonexistent user is a 401."""
    from database import get_session
    from models import PortalUser

    with get_session() as session:
        for name, is_admin in names_and_admin:
            if session.get(PortalUser, name) is None:
                session.add(PortalUser(id=name, username=name, password="x", is_admin=is_admin, is_active=True))
        session.commit()
