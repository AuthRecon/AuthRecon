"""Per-user two-factor authentication (TOTP).

A separate table (not columns on portal_users) so existing installs pick it up
through create_all without a schema migration.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class UserMFA(Base):
    __tablename__ = "user_mfa"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # JSON list of SHA-256 hashes of the unused backup codes.
    backup_codes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    # Last accepted TOTP time step: a code is never accepted twice.
    last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
