"""Database-backed user store for the portal."""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List

import bcrypt
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.user import PortalUser

LOGGER = logging.getLogger("PortalUserStore")


class UserStore:
    """Persist portal users inside the configured database."""

    def __init__(self, session_factory: Callable[[], Session], legacy_path: Path | None = None) -> None:
        self._session_factory = session_factory
        self.legacy_path = legacy_path
        if self.legacy_path:
            self.legacy_path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_file()

    @contextmanager
    def _session(self) -> Session:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @property
    def is_initialized(self) -> bool:
        with self._session() as session:
            count = session.scalar(select(func.count()).select_from(PortalUser))
            return bool(count)

    def list_users(self) -> List[Dict[str, object]]:
        with self._session() as session:
            rows = session.scalars(select(PortalUser).order_by(PortalUser.username)).all()
            return [
                {
                    "id": row.id,
                    "username": row.username,
                    "full_name": row.full_name,
                    "is_admin": row.is_admin,
                    "is_active": row.is_active,
                    "created_at": row.created_at,
                    "last_login_at": row.last_login_at,
                }
                for row in rows
            ]

    def add_user(
        self,
        username: str,
        password: str,
        is_admin: bool = False,
        full_name: str | None = None,
        is_active: bool = True,
    ) -> Dict[str, object]:
        normalized = username.strip().lower()
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        with self._session() as session:
            try:
                user = PortalUser(
                    username=normalized,
                    password=hashed,
                    full_name=full_name,
                    is_admin=is_admin,
                    is_active=is_active,
                )
                session.add(user)
                session.flush()
                return {
                    "id": user.id,
                    "username": user.username,
                    "full_name": user.full_name,
                    "is_admin": user.is_admin,
                    "is_active": user.is_active,
                    "created_at": user.created_at,
                    "last_login_at": user.last_login_at,
                }
            except IntegrityError as exc:
                raise ValueError("User already exists") from exc

    def get_user(self, user_id: str) -> Dict[str, object] | None:
        with self._session() as session:
            user = session.scalar(select(PortalUser).where(PortalUser.id == user_id).limit(1))
            if not user:
                return None
            return {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "is_admin": user.is_admin,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "last_login_at": user.last_login_at,
            }

    def update_user(
        self,
        user_id: str,
        full_name: str | None = None,
        is_admin: bool | None = None,
        is_active: bool | None = None,
        password: str | None = None,
    ) -> Dict[str, object]:
        with self._session() as session:
            user = session.scalar(select(PortalUser).where(PortalUser.id == user_id).limit(1))
            if not user:
                raise ValueError("User not found")

            if full_name is not None:
                user.full_name = full_name
            if is_admin is not None:
                user.is_admin = is_admin
            if is_active is not None:
                user.is_active = is_active
            if password is not None:
                hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                user.password = hashed

            session.flush()
            return {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "is_admin": user.is_admin,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "last_login_at": user.last_login_at,
            }

    def update_password(self, username: str, password: str) -> None:
        normalized = username.strip().lower()
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        with self._session() as session:
            user = session.scalar(
                select(PortalUser).where(func.lower(PortalUser.username) == normalized).limit(1)
            )
            if not user:
                raise ValueError("User not found")
            user.password = hashed

    def delete_user(self, user_id: str) -> None:
        with self._session() as session:
            user = session.scalar(select(PortalUser).where(PortalUser.id == user_id).limit(1))
            if not user:
                raise ValueError("User not found")
            session.delete(user)

    def remove_user(self, username: str) -> None:
        """Legacy method - use delete_user() instead."""
        normalized = username.strip().lower()
        with self._session() as session:
            user = session.scalar(
                select(PortalUser).where(func.lower(PortalUser.username) == normalized).limit(1)
            )
            if not user:
                raise ValueError("User not found")
            session.delete(user)

    def verify_credentials(self, username: str, password: str) -> Dict[str, object] | None:
        normalized = username.strip().lower()
        with self._session() as session:
            user = session.scalar(
                select(PortalUser).where(func.lower(PortalUser.username) == normalized).limit(1)
            )
            if not user:
                return None
            if not user.is_active:
                return None
            hashed = user.password.encode("utf-8")
            if not hashed or not bcrypt.checkpw(password.encode("utf-8"), hashed):
                return None
            user.last_login_at = datetime.utcnow()
            return {"id": user.id, "username": user.username, "is_admin": user.is_admin}

    def verify_password(self, plain_password: str, password_hash: str) -> bool:
        """Verify a plain password against a bcrypt hash."""
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
        except Exception:
            return False

    def _migrate_legacy_file(self) -> None:
        if not self.legacy_path or not self.legacy_path.exists():
            return
        if self.is_initialized:
            return
        try:
            legacy_users = json.loads(self.legacy_path.read_text())
        except json.JSONDecodeError as exc:
            LOGGER.warning("Failed to parse legacy user file %s: %s", self.legacy_path, exc)
            return
        if not isinstance(legacy_users, list):
            LOGGER.warning("Legacy user file %s is malformed", self.legacy_path)
            return
        with self._session() as session:
            for record in legacy_users:
                username = str(record.get("username", "")).strip().lower()
                password = record.get("password")
                if not username or not password:
                    continue
                session.add(
                    PortalUser(
                        username=username,
                        password=password,
                        is_admin=bool(record.get("is_admin", False)),
                    )
                )
        LOGGER.info("Imported %d users from legacy store", len(legacy_users))
