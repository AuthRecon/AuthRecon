"""Per-user acknowledgement of the in-app security notice.

A separate table (not a column on portal_users) so existing installs pick it
up through create_all without a schema migration.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class SecurityNoticeAck(Base):
    __tablename__ = "security_notice_acks"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    notice_version: Mapped[int] = mapped_column(Integer, nullable=False)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
