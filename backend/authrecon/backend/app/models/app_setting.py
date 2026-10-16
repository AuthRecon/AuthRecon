"""Small key/value store for instance-wide settings an admin changes in the UI."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Column, DateTime, String
from sqlalchemy.orm import Mapped, Session

from app.db.base import Base

MCP_ENABLED = "mcp_enabled"
# Runs an MCP client submits wait for a human to approve them (api/runs.py).
MCP_RUNS_NEED_APPROVAL = "mcp_runs_need_approval"


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = Column(String(100), primary_key=True)
    value: Mapped[Any] = Column(JSON, nullable=True)
    updated_at: Mapped[datetime] = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(AppSetting, key)
    return default if row is None else row.value


def set_setting(db: Session, key: str, value: Any) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key)
    row.value = value
    row.updated_at = datetime.now(timezone.utc)
    db.add(row)
    db.commit()
